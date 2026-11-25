/**
 * ShareSafe Chrome Extension — Prioritized Automatic Attachment Redaction Workflow
 * 
 * Intercepts document, photo, and image attachments on WhatsApp Web and Gmail.
 * Automatically scans attachments using OCR and sensitive-information detectors,
 * applies default redactions, presents an in-situ review interface with selective undo,
 * validates non-recoverability (0 extractable text streams), and swaps the sanitized
 * copy into the attachment stream so original sensitive files are NEVER transmitted.
 */

(function () {
  const ALLOWED_EXTS = ["pdf", "docx", "pptx", "xlsx", "txt", "csv", "png", "jpg", "jpeg", "webp", "bmp", "tiff", "tif", "gif"];
  const bypassedFiles = new WeakSet();

  function getFileExtension(filename) {
    if (!filename || !filename.includes(".")) return "";
    return filename.split(".").pop().toLowerCase();
  }

  function isInspectableFile(file) {
    if (!file || !file.name) return false;
    const ext = getFileExtension(file.name);
    return ALLOWED_EXTS.includes(ext);
  }

  // Base64 helper
  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  function base64ToBlob(base64Data, contentType) {
    const parts = base64Data.split(",");
    const raw = parts.length > 1 ? parts[1] : parts[0];
    const byteCharacters = atob(raw);
    const byteArrays = [];
    const sliceSize = 1024;
    for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
      const slice = byteCharacters.slice(offset, offset + sliceSize);
      const byteNumbers = new Array(slice.length);
      for (let i = 0; i < slice.length; i++) {
        byteNumbers[i] = slice.charCodeAt(i);
      }
      byteArrays.push(new Uint8Array(byteNumbers));
    }
    return new Blob(byteArrays, { type: contentType || "application/octet-stream" });
  }

  // Floating Status Toast (delegated to unified ShareSafeUI)
  function showStatusToast(message, type = "info", duration = 3200) {
    return window.ShareSafeUI.showToast(message, type, duration);
  }

  // Unsupported File Alert Modal (delegated to unified ShareSafeUI)
  function showUnsupportedFileModal(file, onCancel, onOverride) {
    const ext = getFileExtension(file.name);
    return window.ShareSafeUI.showUnsupportedModal(file, ext, onCancel, onOverride);
  }

  // Scan Failure or Server Offline Modal (delegated to unified ShareSafeUI)
  function showScanFailedModal(file, errMsg, onCancel, onOverride) {
    return window.ShareSafeUI.showOfflineModal(file, errMsg, onCancel, onOverride);
  }

  // Category icon resolver for detections
  function getDetectionIcon(type, label) {
    const t = (type || "").toLowerCase();
    const l = (label || "").toLowerCase();
    if (t === "name" || l.includes("patient") || l.includes("physician") || l.includes("doctor") || l.includes("name")) return "👤";
    if (t === "email" || l.includes("email")) return "✉️";
    if (t === "phone" || l.includes("phone") || l.includes("mobile") || l.includes("cell")) return "📞";
    if (t === "ssn" || t.includes("uid") || t.includes("pan") || t.includes("aadhaar") || l.includes("social security") || l.includes("tax")) return "🪪";
    if (t.includes("card") || l.includes("card") || l.includes("visa") || l.includes("mastercard")) return "💳";
    if (t.includes("expir") || l.includes("expir") || l.includes("valid thru")) return "📅";
    if (t === "address" || l.includes("address") || l.includes("street") || l.includes("terrace")) return "📍";
    if (t === "qr_code" || l.includes("qr")) return "📱";
    if (t.includes("id") || l.includes("invoice") || l.includes("account") || l.includes("token")) return "🏷️";
    return "🛡️";
  }

  // Interactive Attachment Redaction & Review Interface
  function showAttachmentReviewModal(file, scanData, onConfirmSendSanitized, onCancel, onOverride) {
    const existing = document.getElementById("sharesafe-shield-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "sharesafe-shield-overlay";
    overlay.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(15, 23, 42, 0.56); backdrop-filter: blur(4px);
      z-index: 2147483647; display: flex; align-items: center; justify-content: center;
      padding: 20px; box-sizing: border-box; font-family: ${window.ShareSafeUI.FONT_STACK};
    `;

    let currentScan = scanData;
    const excludedDetectionIds = new Set();
    let manualRedactions = [];
    let selectedManualId = null;
    let isManualMode = false;
    let editorTool = "draw"; // "draw" or "select"
    let currentPage = 1;
    let pageCount = (currentScan.pages && currentScan.pages.length) ? currentScan.pages.length : (currentScan.page_count || 1);
    const undoStack = [];
    const redoStack = [];

    const risk = currentScan.risk_summary || {};
    const riskLevel = (risk.level || "HIGH").toUpperCase();
    const riskScore = risk.score || 0;
    const isPdf = currentScan.is_pdf;
    const formatLabel = currentScan.format_category
      ? currentScan.format_category.toUpperCase()
      : (isPdf ? "PDF Document" : "Image");
    const riskBadgePalette = (riskLevel === "CRITICAL" || riskLevel === "HIGH")
      ? { bg: "#FEF2F2", ink: "#B91C1C", border: "#FECACA" }
      : (riskLevel === "MEDIUM")
      ? { bg: "#FFFBEB", ink: "#B45309", border: "#FDE68A" }
      : { bg: "#F0FDF4", ink: "#15803D", border: "#BBF7D0" };
    let updateSeq = 0;

    overlay.innerHTML = `
      <style>
        @keyframes ssSpin {
          to { transform: rotate(360deg); }
        }
        #ssDetectionsList::-webkit-scrollbar, #ssManualList::-webkit-scrollbar {
          width: 6px;
        }
        #ssDetectionsList::-webkit-scrollbar-track, #ssManualList::-webkit-scrollbar-track {
          background: #F8FAFC;
          border-radius: 4px;
        }
        #ssDetectionsList::-webkit-scrollbar-thumb, #ssManualList::-webkit-scrollbar-thumb {
          background: #CBD5E1;
          border-radius: 4px;
        }
        #ssDetectionsList::-webkit-scrollbar-thumb:hover, #ssManualList::-webkit-scrollbar-thumb:hover {
          background: #94A3B8;
        }
        .ss-btn-choice {
          transition: background 0.15s ease, color 0.15s ease;
          user-select: none;
        }
        .ss-btn-choice:hover {
          opacity: 0.9;
        }
        .ss-detection-row {
          transition: border-color 0.15s ease, background 0.15s ease;
        }
        .ss-detection-row:hover {
          border-color: #CBD5E1 !important;
        }
        .ss-editor-btn {
          padding: 6px 10px;
          font-size: 12px;
          font-weight: 500;
          border-radius: 7px;
          cursor: pointer;
          border: 1px solid #E2E8F0;
          background: #FFFFFF;
          color: #334155;
          display: inline-flex;
          align-items: center;
          gap: 5px;
          transition: background 0.15s ease, border-color 0.15s ease;
          user-select: none;
        }
        .ss-editor-btn:hover:not(:disabled) {
          background: #F1F5F9;
          border-color: #CBD5E1;
        }
        .ss-editor-btn:disabled {
          opacity: 0.45;
          cursor: not-allowed;
          color: #94A3B8;
        }
        .ss-editor-btn.active {
          background: #0F172A !important;
          color: #FFFFFF !important;
          border-color: #0F172A !important;
        }
        .ss-manual-box {
          box-sizing: border-box;
          transition: border-color 0.1s ease;
        }
        .ss-manual-box:hover {
          border-color: #0F172A !important;
        }
        @media (max-width: 768px) {
          #ssModalContainer {
            max-height: 96vh !important;
            height: 96vh !important;
          }
          #ssReviewBody {
            grid-template-columns: 1fr !important;
            overflow-y: auto !important;
          }
          #ssPreviewCard {
            max-height: 300px !important;
          }
        }
      </style>
      <div id="ssModalContainer" style="background: #FFFFFF; border-radius: 16px; width: 100%; max-width: 940px; max-height: 92vh; height: min(790px, 92vh); display: flex; flex-direction: column; box-shadow: 0 24px 60px rgba(15, 23, 42, 0.22), 0 4px 16px rgba(15, 23, 42, 0.06); overflow: hidden; border: 1px solid #E2E8F0; box-sizing: border-box;">
        
        <!-- Header (Clean, restrained hierarchy) -->
        <div style="padding: 18px 28px; background: #FFFFFF; border-bottom: 1px solid #E2E8F0; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-shrink: 0;">
          <div style="display: flex; align-items: center; gap: 14px; min-width: 0;">
            <div style="width: 38px; height: 38px; border-radius: 10px; background: #F8FAFC; border: 1px solid #E2E8F0; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
              ${window.ShareSafeUI.ICONS.shield("#C65A4A", 19)}
            </div>
            <div style="min-width: 0;">
              <div style="font-size: 17px; font-weight: 600; color: #0F172A; letter-spacing: -0.015em; line-height: 1.3;">
                Attachment Redaction &amp; Review
              </div>
              <div style="font-size: 12px; font-weight: 400; color: #64748B; margin-top: 2px;">
                ShareSafe successfully protected this attachment
              </div>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 10px; flex-shrink: 0;">
            <span id="ssManualBadge" style="display: none; font-size: 11px; font-weight: 600; padding: 4px 10px; border-radius: 999px; background: #F1F5F9; color: #0F172A; border: 1px solid #CBD5E1;">
              Manual redact active
            </span>
            <span style="font-size: 11px; font-weight: 600; padding: 4px 11px; border-radius: 999px; background: ${riskBadgePalette.bg}; color: ${riskBadgePalette.ink}; border: 1px solid ${riskBadgePalette.border}; letter-spacing: 0.2px; white-space: nowrap;">
              ${riskLevel} RISK &middot; ${riskScore}/100
            </span>
          </div>
        </div>

        <!-- Security Status Strip (Calm, user-first, secondary technical detail) -->
        <div style="background: #F8FAFC; border-bottom: 1px solid #E2E8F0; padding: 12px 28px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; flex-shrink: 0;">
          <div style="display: flex; align-items: center; gap: 10px; min-width: 0;">
            ${window.ShareSafeUI.ICONS.shieldCheck("#15803D", 17)}
            <div style="font-size: 13px; color: #0F172A; line-height: 1.4;">
              <strong style="font-weight: 600;">Sanitization complete</strong>
              <span style="color: #475569; margin-left: 6px;">Sensitive content has been permanently redacted and metadata removed.</span>
            </div>
          </div>
          <span style="font-size: 12px; color: #64748B; white-space: nowrap;">
            0 extractable characters
          </span>
        </div>

        <!-- Main Body: Coherent Two-Column Workflow -->
        <div id="ssReviewBody" style="padding: 20px 28px; overflow: hidden; flex: 1; min-height: 0; display: grid; grid-template-columns: 360px 1fr; gap: 24px; background: #FFFFFF; box-sizing: border-box;">
          
          <!-- LEFT: Sanitized Preview & Separated Manual Redact Controls -->
          <div id="ssPreviewCard" style="display: flex; flex-direction: column; min-height: 0; overflow: hidden; box-sizing: border-box;">
            
            <!-- Preview Header -->
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; flex-shrink: 0;">
              <span style="font-size: 13px; font-weight: 600; color: #0F172A;">
                Sanitized Preview
              </span>
              <span id="ssPreviewSafeBadge" style="background: #F0FDF4; color: #15803D; border: 1px solid #BBF7D0; border-radius: 999px; padding: 3px 10px; font-size: 11px; font-weight: 600;">
                ✓ Safe to Send
              </span>
            </div>

            <!-- Spacious Preview Viewport -->
            <div id="ssPreviewViewport" style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 12px; padding: 12px; overflow: hidden; flex: 1; min-height: 220px; display: flex; align-items: center; justify-content: center; position: relative; user-select: none; box-sizing: border-box;">
              <img id="ssPreviewImg" src="${currentScan.preview_data_url || ''}" alt="Redacted Preview" style="width: 100%; height: 100%; object-fit: contain; display: block; pointer-events: none; border-radius: 6px;" />
              
              <!-- Drawing & Selection Interaction Layer -->
              <div id="ssDrawingLayer" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 15;">
                <!-- Manual redaction boxes placed here -->
              </div>

              <!-- Rubberband Rectangle -->
              <div id="ssRubberBand" style="display: none; position: absolute; border: 2px dashed #0F172A; background: rgba(15, 23, 42, 0.16); pointer-events: none; z-index: 25; border-radius: 2px;"></div>

              <!-- Updating Spinner -->
              <div id="ssPreviewLoading" style="display: none; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(248, 250, 252, 0.9); backdrop-filter: blur(2px); flex-direction: column; align-items: center; justify-content: center; font-size: 12px; color: #0F172A; font-weight: 500; gap: 8px; z-index: 30;">
                <div style="width: 24px; height: 24px; border: 2.5px solid #E2E8F0; border-top-color: #0F172A; border-radius: 50%; animation: ssSpin 0.75s linear infinite;"></div>
                <span>Updating sanitized copy...</span>
              </div>
            </div>

            <!-- Subtle File Metadata -->
            <div style="margin-top: 12px; flex-shrink: 0; display: flex; flex-direction: column; gap: 3px;">
              <div style="font-size: 12px; color: #475569; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                <span style="font-weight: 500; color: #0F172A;">${escapeHtml(file.name)}</span>
                <span style="color: #94A3B8;"> &middot; </span>
                <span>${formatBytes(file.size)}</span>
                <span style="color: #94A3B8;"> &middot; </span>
                <span>${escapeHtml(formatLabel)}</span>
              </div>
              <div id="ssRedactedSummary" style="font-size: 12px; color: #64748B;">
                All sensitive items protected
              </div>
            </div>

            <!-- Separated Manual Redact & Page Controls -->
            <div id="ssEditorToolbar" style="margin-top: 12px; padding: 10px 12px; background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 10px; display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; flex-shrink: 0;">
              <div style="display: flex; align-items: center; gap: 6px;">
                <button type="button" id="ssBtnToggleManual" class="ss-editor-btn" title="Toggle manual draw-to-redact mode">
                  <span>Manual Redact</span>
                </button>
                <div id="ssToolGroup" style="display: none; align-items: center; background: #E2E8F0; padding: 2px; border-radius: 6px; gap: 2px;">
                  <button type="button" id="ssToolDraw" class="ss-editor-btn active" style="padding: 3px 8px; font-size: 11px; border: none;" title="Draw rectangular blackout box">
                    Draw
                  </button>
                  <button type="button" id="ssToolSelect" class="ss-editor-btn" style="padding: 3px 8px; font-size: 11px; border: none;" title="Select and delete existing manual redactions">
                    Select
                  </button>
                </div>
              </div>

              <div style="display: flex; align-items: center; gap: 4px;">
                <button type="button" id="ssBtnUndo" class="ss-editor-btn" style="padding: 5px 8px;" title="Undo last action" disabled>
                  Undo
                </button>
                <button type="button" id="ssBtnRedo" class="ss-editor-btn" style="padding: 5px 8px;" title="Redo action" disabled>
                  Redo
                </button>
                <button type="button" id="ssBtnDeleteSelected" class="ss-editor-btn" style="padding: 5px 8px;" title="Delete selected manual redaction" disabled>
                  Delete
                </button>
              </div>

              <!-- Multi-Page Navigation -->
              <div id="ssPageNavGroup" style="display: ${pageCount > 1 ? 'flex' : 'none'}; align-items: center; gap: 6px;">
                <button type="button" id="ssBtnPrevPage" class="ss-editor-btn" style="padding: 4px 8px;" title="Previous Page" ${currentPage === 1 ? 'disabled' : ''}>
                  &lsaquo;
                </button>
                <span id="ssPageIndicator" style="font-size: 12px; font-weight: 500; color: #475569; min-width: 64px; text-align: center;">
                  ${currentPage} / ${pageCount}
                </span>
                <button type="button" id="ssBtnNextPage" class="ss-editor-btn" style="padding: 4px 8px;" title="Next Page" ${currentPage === pageCount ? 'disabled' : ''}>
                  &rsaquo;
                </button>
              </div>
            </div>
          </div>

          <!-- RIGHT: Detected Information & Protection Controls -->
          <div style="display: flex; flex-direction: column; min-height: 0; overflow: hidden; box-sizing: border-box;">
            
            <!-- Section Header with Calm Counts & Secondary Global Actions -->
            <div style="display: flex; justify-content: space-between; align-items: flex-end; gap: 12px; margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px solid #E2E8F0; flex-shrink: 0;">
              <div>
                <div style="font-size: 14px; font-weight: 600; color: #0F172A;">
                  Detected information
                </div>
                <div id="ssActiveCount" style="font-size: 12px; color: #64748B; margin-top: 2px;">
                  ${currentScan.detections.length} protected &middot; 0 kept
                </div>
              </div>
              <div style="display: flex; gap: 8px; flex-shrink: 0;">
                <button type="button" id="ssBtnRedactAll" title="Redact all detected sensitive items" style="
                  background: #FFFFFF;
                  color: #334155;
                  border: 1px solid #CBD5E1;
                  border-radius: 7px;
                  padding: 5px 11px;
                  font-size: 12px;
                  font-weight: 500;
                  cursor: pointer;
                  transition: background 0.15s ease;
                ">
                  Redact All
                </button>
                <button type="button" id="ssBtnKeepAll" title="Keep all items visible (unredacted)" style="
                  background: #FFFFFF;
                  color: #334155;
                  border: 1px solid #CBD5E1;
                  border-radius: 7px;
                  padding: 5px 11px;
                  font-size: 12px;
                  font-weight: 500;
                  cursor: pointer;
                  transition: background 0.15s ease;
                ">
                  Keep All
                </button>
              </div>
            </div>

            <!-- Scrollable Automatic Detections List -->
            <div id="ssDetectionsList" style="flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; padding-right: 4px;">
              <!-- Dynamic detections rendered here -->
            </div>

            <!-- Manual Redactions Section -->
            <div id="ssManualSection" style="display: none; margin-top: 12px; border-top: 1px solid #E2E8F0; padding-top: 10px; flex-shrink: 0;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span id="ssManualCount" style="font-size: 12px; font-weight: 600; color: #0F172A;">
                  Manual Redactions (0)
                </span>
                <button type="button" id="ssBtnClearManual" style="background: none; border: none; font-size: 12px; font-weight: 500; color: #64748B; cursor: pointer; text-decoration: underline; padding: 0;">
                  Clear all
                </button>
              </div>
              <div id="ssManualList" style="display: flex; flex-direction: column; gap: 6px; max-height: 85px; overflow-y: auto; padding-right: 4px;">
                <!-- Manual items rendered here -->
              </div>
            </div>
          </div>

        </div>

        <!-- Bottom Action Area (Clear Primary -> Secondary -> Tertiary -> Subdued Override) -->
        <div id="ssModalFooter" style="padding: 18px 28px; background: #F8FAFC; border-top: 1px solid #E2E8F0; display: flex; flex-direction: column; gap: 12px; flex-shrink: 0; box-sizing: border-box;">
          <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
            <!-- Primary Action -->
            <button id="ssBtnSendSanitized" class="ss-ui-btn-primary" style="flex: 2; min-width: 210px; height: 42px; padding: 0 22px; background: #0F172A; color: #FFFFFF; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; transition: filter 0.15s ease;">
              <span>Send Sanitized Attachment</span>
            </button>
            <!-- Secondary Action -->
            <button id="ssBtnDownloadClean" class="ss-ui-btn-secondary" style="flex: 1; min-width: 160px; height: 42px; padding: 0 18px; background: #FFFFFF; color: #0F172A; border: 1px solid #CBD5E1; border-radius: 10px; font-size: 13px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; transition: background 0.15s ease;">
              <span>Download Clean Copy</span>
            </button>
            <!-- Tertiary Action -->
            <button id="ssBtnCancel" class="ss-ui-btn-ghost" style="height: 42px; padding: 0 16px; background: transparent; color: #475569; border: 1px solid transparent; border-radius: 10px; font-size: 13px; font-weight: 500; cursor: pointer; transition: background 0.15s ease;">
              Cancel
            </button>
          </div>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; padding-top: 4px; border-top: 1px solid #E2E8F0;">
            <span style="font-size: 12px; color: #64748B;">Original file remains unchanged.</span>
            <button id="ssBtnOverride" style="background: none; border: none; color: #64748B; font-size: 12px; cursor: pointer; text-decoration: underline; padding: 2px 0;">
              Send original unredacted file anyway
            </button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const detectionsContainer = overlay.querySelector("#ssDetectionsList");
    const manualSection = overlay.querySelector("#ssManualSection");
    const manualListContainer = overlay.querySelector("#ssManualList");
    const manualCountElem = overlay.querySelector("#ssManualCount");
    const activeCountElem = overlay.querySelector("#ssActiveCount");
    const redactedSummaryElem = overlay.querySelector("#ssRedactedSummary");
    const previewSafeBadge = overlay.querySelector("#ssPreviewSafeBadge");
    const previewImg = overlay.querySelector("#ssPreviewImg");
    const previewLoading = overlay.querySelector("#ssPreviewLoading");
    const drawingLayer = overlay.querySelector("#ssDrawingLayer");
    const rubberBand = overlay.querySelector("#ssRubberBand");

    // Toolbar buttons
    const btnToggleManual = overlay.querySelector("#ssBtnToggleManual");
    const toolGroup = overlay.querySelector("#ssToolGroup");
    const toolDraw = overlay.querySelector("#ssToolDraw");
    const toolSelect = overlay.querySelector("#ssToolSelect");
    const btnUndo = overlay.querySelector("#ssBtnUndo");
    const btnRedo = overlay.querySelector("#ssBtnRedo");
    const btnDeleteSelected = overlay.querySelector("#ssBtnDeleteSelected");
    const btnClearManual = overlay.querySelector("#ssBtnClearManual");
    const manualBadge = overlay.querySelector("#ssManualBadge");

    // Multi-page controls
    const pageNavGroup = overlay.querySelector("#ssPageNavGroup");
    const btnPrevPage = overlay.querySelector("#ssBtnPrevPage");
    const btnNextPage = overlay.querySelector("#ssBtnNextPage");
    const pageIndicator = overlay.querySelector("#ssPageIndicator");

    function saveUndoState() {
      undoStack.push({
        manual: JSON.parse(JSON.stringify(manualRedactions)),
        excluded: new Set(excludedDetectionIds)
      });
      redoStack.length = 0;
      updateUndoRedoUI();
    }

    function updateUndoRedoUI() {
      btnUndo.disabled = (undoStack.length === 0);
      btnRedo.disabled = (redoStack.length === 0);
      btnDeleteSelected.disabled = (!selectedManualId);
    }

    function handleUndo() {
      if (undoStack.length === 0) return;
      redoStack.push({
        manual: JSON.parse(JSON.stringify(manualRedactions)),
        excluded: new Set(excludedDetectionIds)
      });
      const prev = undoStack.pop();
      manualRedactions = prev.manual;
      excludedDetectionIds.clear();
      prev.excluded.forEach((id) => excludedDetectionIds.add(id));
      selectedManualId = null;
      renderDetections();
      renderManualBoxes();
      renderManualList();
      updateUndoRedoUI();
      updateRedactionsOnServer();
    }

    function handleRedo() {
      if (redoStack.length === 0) return;
      undoStack.push({
        manual: JSON.parse(JSON.stringify(manualRedactions)),
        excluded: new Set(excludedDetectionIds)
      });
      const next = redoStack.pop();
      manualRedactions = next.manual;
      excludedDetectionIds.clear();
      next.excluded.forEach((id) => excludedDetectionIds.add(id));
      selectedManualId = null;
      renderDetections();
      renderManualBoxes();
      renderManualList();
      updateUndoRedoUI();
      updateRedactionsOnServer();
    }

    btnUndo.addEventListener("click", handleUndo);
    btnRedo.addEventListener("click", handleRedo);

    btnDeleteSelected.addEventListener("click", () => {
      if (selectedManualId) {
        saveUndoState();
        manualRedactions = manualRedactions.filter((m) => m.id !== selectedManualId);
        selectedManualId = null;
        renderManualBoxes();
        renderManualList();
        updateUndoRedoUI();
        updateRedactionsOnServer();
      }
    });

    btnClearManual.addEventListener("click", () => {
      if (manualRedactions.length > 0) {
        saveUndoState();
        manualRedactions = [];
        selectedManualId = null;
        renderManualBoxes();
        renderManualList();
        updateUndoRedoUI();
        updateRedactionsOnServer();
      }
    });

    // Toggle Manual Mode
    btnToggleManual.addEventListener("click", () => {
      isManualMode = !isManualMode;
      if (isManualMode) {
        btnToggleManual.classList.add("active");
        toolGroup.style.display = "inline-flex";
        manualBadge.style.display = "inline-block";
        drawingLayer.style.pointerEvents = "auto";
        drawingLayer.style.cursor = (editorTool === "draw") ? "crosshair" : "default";
      } else {
        btnToggleManual.classList.remove("active");
        toolGroup.style.display = "none";
        manualBadge.style.display = "none";
        drawingLayer.style.pointerEvents = "none";
        drawingLayer.style.cursor = "default";
        selectedManualId = null;
      }
      renderManualBoxes();
      updateUndoRedoUI();
    });

    toolDraw.addEventListener("click", () => {
      editorTool = "draw";
      toolDraw.classList.add("active");
      toolSelect.classList.remove("active");
      drawingLayer.style.cursor = "crosshair";
    });

    toolSelect.addEventListener("click", () => {
      editorTool = "select";
      toolSelect.classList.add("active");
      toolDraw.classList.remove("active");
      drawingLayer.style.cursor = "default";
    });

    // Multi-page navigation handlers
    function updatePageNav() {
      pageCount = (currentScan.pages && currentScan.pages.length) ? currentScan.pages.length : (currentScan.page_count || 1);
      if (pageCount > 1) {
        pageNavGroup.style.display = "flex";
        pageIndicator.textContent = `Page ${currentPage} / ${pageCount}`;
        btnPrevPage.disabled = (currentPage === 1);
        btnNextPage.disabled = (currentPage === pageCount);
      } else {
        pageNavGroup.style.display = "none";
      }
    }

    btnPrevPage.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage--;
        updatePageNav();
        const curPreview = (currentScan.pages && currentScan.pages[currentPage - 1])
          ? currentScan.pages[currentPage - 1].preview_data_url
          : currentScan.preview_data_url;
        if (previewImg && curPreview) previewImg.src = curPreview;
        selectedManualId = null;
        renderManualBoxes();
        renderManualList();
        renderDetections();
      }
    });

    btnNextPage.addEventListener("click", () => {
      if (currentPage < pageCount) {
        currentPage++;
        updatePageNav();
        const curPreview = (currentScan.pages && currentScan.pages[currentPage - 1])
          ? currentScan.pages[currentPage - 1].preview_data_url
          : currentScan.preview_data_url;
        if (previewImg && curPreview) previewImg.src = curPreview;
        selectedManualId = null;
        renderManualBoxes();
        renderManualList();
        renderDetections();
      }
    });

    // Coordinate Math: Maps client pointer to native image coordinates and back
    function getImageRenderGeometry() {
      const rect = previewImg.getBoundingClientRect();
      let natW = previewImg.naturalWidth;
      let natH = previewImg.naturalHeight;

      if (!natW || !natH) {
        if (currentScan.pages && currentScan.pages[currentPage - 1]) {
          natW = currentScan.pages[currentPage - 1].width || 800;
          natH = currentScan.pages[currentPage - 1].height || 1000;
        } else {
          natW = rect.width || 800;
          natH = rect.height || 1000;
        }
      }

      const elemW = rect.width;
      const elemH = rect.height;

      if (!elemW || !elemH) {
        return { natW, natH, renderW: natW, renderH: natH, offsetX: 0, offsetY: 0, scale: 1, rect };
      }

      const imgAspect = natW / natH;
      const elemAspect = elemW / elemH;

      let renderW, renderH, offsetX, offsetY;
      if (elemAspect > imgAspect) {
        renderH = elemH;
        renderW = elemH * imgAspect;
        offsetX = (elemW - renderW) / 2;
        offsetY = 0;
      } else {
        renderW = elemW;
        renderH = elemW / imgAspect;
        offsetX = 0;
        offsetY = (elemH - renderH) / 2;
      }

      const scale = natW / renderW;
      return { natW, natH, elemW, elemH, renderW, renderH, offsetX, offsetY, scale, rect };
    }

    function clientPointToNative(clientX, clientY) {
      const geom = getImageRenderGeometry();
      const relX = clientX - geom.rect.left - geom.offsetX;
      const relY = clientY - geom.rect.top - geom.offsetY;

      const clampedX = Math.max(0, Math.min(geom.renderW, relX));
      const clampedY = Math.max(0, Math.min(geom.renderH, relY));

      return {
        x: clampedX * geom.scale,
        y: clampedY * geom.scale
      };
    }

    function nativeBboxToScreen(bbox) {
      const geom = getImageRenderGeometry();
      const screenScale = 1 / geom.scale;
      return {
        left: geom.offsetX + bbox[0] * screenScale,
        top: geom.offsetY + bbox[1] * screenScale,
        width: bbox[2] * screenScale,
        height: bbox[3] * screenScale
      };
    }

    // Pointer-based rectangular drawing on drawingLayer
    let isDrawing = false;
    let dragStart = null;

    drawingLayer.addEventListener("pointerdown", (e) => {
      if (!isManualMode) return;
      if (editorTool !== "draw") return;

      dragStart = clientPointToNative(e.clientX, e.clientY);
      isDrawing = true;
      drawingLayer.setPointerCapture(e.pointerId);

      const screen = nativeBboxToScreen([dragStart.x, dragStart.y, 0, 0]);
      rubberBand.style.left = `${screen.left}px`;
      rubberBand.style.top = `${screen.top}px`;
      rubberBand.style.width = `0px`;
      rubberBand.style.height = `0px`;
      rubberBand.style.display = "block";
    });

    drawingLayer.addEventListener("pointermove", (e) => {
      if (!isDrawing || !dragStart) return;

      const current = clientPointToNative(e.clientX, e.clientY);
      const x0 = Math.min(dragStart.x, current.x);
      const y0 = Math.min(dragStart.y, current.y);
      const w0 = Math.abs(current.x - dragStart.x);
      const h0 = Math.abs(current.y - dragStart.y);

      const screen = nativeBboxToScreen([x0, y0, w0, h0]);
      rubberBand.style.left = `${screen.left}px`;
      rubberBand.style.top = `${screen.top}px`;
      rubberBand.style.width = `${screen.width}px`;
      rubberBand.style.height = `${screen.height}px`;
    });

    function finishDrawing(e) {
      if (!isDrawing || !dragStart) return;
      isDrawing = false;
      rubberBand.style.display = "none";
      try { drawingLayer.releasePointerCapture(e.pointerId); } catch (_) {}

      const current = clientPointToNative(e.clientX, e.clientY);
      const x0 = Math.min(dragStart.x, current.x);
      const y0 = Math.min(dragStart.y, current.y);
      const w0 = Math.abs(current.x - dragStart.x);
      const h0 = Math.abs(current.y - dragStart.y);

      // Require minimum size of 8x8 pixels in native resolution
      if (w0 >= 8 && h0 >= 8) {
        saveUndoState();
        const newRedaction = {
          id: `man_${Math.random().toString(36).substr(2, 8)}`,
          page: currentPage,
          bbox: [
            Math.round(x0 * 10) / 10,
            Math.round(y0 * 10) / 10,
            Math.round(w0 * 10) / 10,
            Math.round(h0 * 10) / 10
          ],
          style: "blackout",
          label: `Manual Box #${manualRedactions.length + 1}`
        };
        manualRedactions.push(newRedaction);
        selectedManualId = newRedaction.id;
        renderManualBoxes();
        renderManualList();
        updateUndoRedoUI();
        updateRedactionsOnServer();
      }
      dragStart = null;
    }

    drawingLayer.addEventListener("pointerup", finishDrawing);
    drawingLayer.addEventListener("pointercancel", finishDrawing);

    // Keyboard Shortcuts (Delete, Ctrl+Z, Ctrl+Y)
    function onKeyDown(e) {
      if (e.key === "Delete" || e.key === "Backspace") {
        if (selectedManualId && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") {
          e.preventDefault();
          saveUndoState();
          manualRedactions = manualRedactions.filter((m) => m.id !== selectedManualId);
          selectedManualId = null;
          renderManualBoxes();
          renderManualList();
          updateUndoRedoUI();
          updateRedactionsOnServer();
        }
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "z") {
        e.preventDefault();
        if (e.shiftKey) {
          handleRedo();
        } else {
          handleUndo();
        }
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "y") {
        e.preventDefault();
        handleRedo();
      }
    }
    window.addEventListener("keydown", onKeyDown);

    // Render Manual Blackout Boxes on Overlay
    function renderManualBoxes() {
      drawingLayer.innerHTML = "";
      const pageBoxes = manualRedactions.filter((m) => m.page === currentPage);

      pageBoxes.forEach((mr) => {
        const isSelected = (selectedManualId === mr.id);
        const screen = nativeBboxToScreen(mr.bbox);

        const boxDiv = document.createElement("div");
        boxDiv.className = "ss-manual-box";
        boxDiv.dataset.id = mr.id;
        boxDiv.style.cssText = `
          position: absolute;
          left: ${screen.left}px;
          top: ${screen.top}px;
          width: ${screen.width}px;
          height: ${screen.height}px;
          background: #000000;
          border: 1.5px solid ${isSelected ? "#C65A4A" : "#333333"};
          box-shadow: ${isSelected ? "0 0 0 2px #C65A4A, 0 2px 8px rgba(198, 90, 74, 0.45)" : "none"};
          pointer-events: auto;
          cursor: pointer;
          z-index: 20;
          box-sizing: border-box;
        `;

        if (isSelected) {
          const badge = document.createElement("span");
          badge.textContent = "SELECTED";
          badge.style.cssText = `
            position: absolute;
            top: -16px;
            left: 0;
            background: #C65A4A;
            color: #FFFFFF;
            font-size: 8px;
            font-weight: 700;
            padding: 1px 4px;
            border-radius: 3px;
            letter-spacing: 0.3px;
            pointer-events: none;
          `;
          boxDiv.appendChild(badge);
        }

        boxDiv.addEventListener("click", (e) => {
          e.stopPropagation();
          selectedManualId = (selectedManualId === mr.id) ? null : mr.id;
          renderManualBoxes();
          renderManualList();
          updateUndoRedoUI();
        });

        drawingLayer.appendChild(boxDiv);
      });
    }

    // Render Manual Redactions in Side Panel
    function renderManualList() {
      if (manualRedactions.length === 0) {
        manualSection.style.display = "none";
        return;
      }

      manualSection.style.display = "block";
      manualCountElem.textContent = `Manual Redactions (${manualRedactions.length})`;
      manualListContainer.innerHTML = "";

      manualRedactions.forEach((mr, idx) => {
        const isSelected = (selectedManualId === mr.id);
        const isCurPage = (mr.page === currentPage);
        const itemRow = document.createElement("div");
        itemRow.style.cssText = `
          background: ${isSelected ? "#FDF1EE" : "#F9FAFB"};
          border: 1px solid ${isSelected ? "#F8DCD6" : "#E5E7EB"};
          border-left: 3px solid ${isSelected ? "#C65A4A" : "#6B7280"};
          border-radius: 6px;
          padding: 5px 8px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          font-size: 11px;
          cursor: pointer;
          transition: all 0.15s ease;
        `;

        const w = Math.round(mr.bbox[2]);
        const h = Math.round(mr.bbox[3]);

        itemRow.innerHTML = `
          <div style="display: flex; align-items: center; gap: 6px; min-width: 0;">
            <span style="font-weight: 700; color: #2A2A2A;">#${idx + 1}</span>
            <span style="color: #6B7280;">Page ${mr.page} &bull; ${w}&times;${h}px</span>
            ${!isCurPage ? '<span style="font-size: 9px; color: #9CA3AF;">(Other Page)</span>' : ''}
          </div>
          <button type="button" class="ss-btn-del-manual" title="Delete manual redaction" style="
            background: none;
            border: none;
            color: #C65A4A;
            font-size: 13px;
            cursor: pointer;
            padding: 0 4px;
          ">
            ✕
          </button>
        `;

        itemRow.addEventListener("click", () => {
          if (mr.page !== currentPage) {
            currentPage = mr.page;
            updatePageNav();
            const curPreview = (currentScan.pages && currentScan.pages[currentPage - 1])
              ? currentScan.pages[currentPage - 1].preview_data_url
              : currentScan.preview_data_url;
            if (previewImg && curPreview) previewImg.src = curPreview;
          }
          selectedManualId = mr.id;
          renderManualBoxes();
          renderManualList();
          updateUndoRedoUI();
        });

        itemRow.querySelector(".ss-btn-del-manual").addEventListener("click", (e) => {
          e.stopPropagation();
          saveUndoState();
          manualRedactions = manualRedactions.filter((m) => m.id !== mr.id);
          if (selectedManualId === mr.id) selectedManualId = null;
          renderManualBoxes();
          renderManualList();
          updateUndoRedoUI();
          updateRedactionsOnServer();
        });

        manualListContainer.appendChild(itemRow);
      });
    }

    // Keep bounding boxes accurately aligned whenever image loads or resizes
    previewImg.addEventListener("load", () => {
      renderManualBoxes();
    });

    const resizeObs = new ResizeObserver(() => {
      renderManualBoxes();
    });
    resizeObs.observe(previewImg);

    function renderDetections() {
      detectionsContainer.innerHTML = "";
      const total = currentScan.detections.length;
      const excludedCount = excludedDetectionIds.size;
      const activeRedacted = total - excludedCount;

      activeCountElem.textContent = `${activeRedacted} protected · ${excludedCount} kept`;
      if (redactedSummaryElem) {
        const manualCount = manualRedactions.length;
        const manualNote = manualCount > 0 ? ` · ${manualCount} manual` : '';
        if (activeRedacted === total) {
          redactedSummaryElem.textContent = `All ${total} sensitive items protected${manualNote}`;
          redactedSummaryElem.style.color = "#15803D";
        } else if (activeRedacted === 0) {
          redactedSummaryElem.textContent = `All sensitive items kept visible${manualNote}`;
          redactedSummaryElem.style.color = "#B45309";
        } else {
          redactedSummaryElem.textContent = `${activeRedacted} of ${total} items protected${manualNote}`;
          redactedSummaryElem.style.color = "#475569";
        }
      }

      if (previewSafeBadge) {
        if (activeRedacted === 0 && manualRedactions.length === 0) {
          previewSafeBadge.textContent = "Unredacted Copy";
          previewSafeBadge.style.background = "#FFFBEB";
          previewSafeBadge.style.color = "#B45309";
          previewSafeBadge.style.borderColor = "#FDE68A";
        } else {
          previewSafeBadge.textContent = "✓ Safe to Send";
          previewSafeBadge.style.background = "#F0FDF4";
          previewSafeBadge.style.color = "#15803D";
          previewSafeBadge.style.borderColor = "#BBF7D0";
        }
      }

      currentScan.detections.forEach((d) => {
        const isExcluded = excludedDetectionIds.has(d.id);
        const itemDiv = document.createElement("div");
        itemDiv.className = "ss-detection-row";
        itemDiv.style.cssText = `
          background: #FFFFFF;
          border: 1px solid #E2E8F0;
          border-radius: 10px;
          padding: 12px 14px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          box-sizing: border-box;
        `;

        const itemLabel = escapeHtml(d.label || d.type || "Sensitive Item");
        const maskedVal = escapeHtml(d.masked || "••••••••");
        const rawVal = escapeHtml(d.value || "");
        const details = escapeHtml(d.details || d.location || "Verified pattern");

        itemDiv.innerHTML = `
          <!-- Left: Clean 3-Level Hierarchy (Name -> Value -> Description) -->
          <div style="flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px;">
            <div style="font-size: 13px; font-weight: 600; color: #0F172A; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${itemLabel}
            </div>
            <div>
              <code style="font-size: 12px; font-family: ${window.ShareSafeUI.MONO_STACK}; background: #F1F5F9; color: ${isExcluded ? "#B45309" : "#334155"}; padding: 2px 7px; border-radius: 5px; display: inline-block; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${isExcluded ? rawVal : maskedVal}
              </code>
            </div>
            <div style="font-size: 12px; color: #64748B; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${details}
            </div>
          </div>

          <!-- Right: Restrained Status + Compact Control -->
          <div style="display: flex; align-items: center; gap: 10px; flex-shrink: 0;">
            <span class="ss-item-badge" style="
              font-size: 11px;
              font-weight: 500;
              padding: 3px 9px;
              border-radius: 999px;
              background: ${isExcluded ? "#FFFBEB" : "#F0FDF4"};
              color: ${isExcluded ? "#B45309" : "#15803D"};
              border: 1px solid ${isExcluded ? "#FDE68A" : "#BBF7D0"};
              white-space: nowrap;
            ">
              ${isExcluded ? "Kept" : "Redacted"}
            </span>
            <div class="ss-toggle-group" role="group" aria-label="Controls for ${itemLabel}" style="
              display: inline-flex;
              align-items: center;
              background: #F1F5F9;
              padding: 2px;
              border-radius: 7px;
              border: 1px solid #E2E8F0;
              gap: 2px;
            ">
              <button type="button" class="ss-btn-choice ss-btn-redact" data-action="redact" title="Redact ${itemLabel}" style="
                background: ${!isExcluded ? "#0F172A" : "transparent"};
                color: ${!isExcluded ? "#FFFFFF" : "#64748B"};
                font-weight: ${!isExcluded ? "600" : "500"};
                border: none;
                border-radius: 5px;
                padding: 4px 9px;
                font-size: 11px;
                cursor: pointer;
              ">
                Redact
              </button>
              <button type="button" class="ss-btn-choice ss-btn-keep" data-action="keep" title="Keep ${itemLabel}" style="
                background: ${isExcluded ? "#FFFFFF" : "transparent"};
                color: ${isExcluded ? "#0F172A" : "#64748B"};
                font-weight: ${isExcluded ? "600" : "500"};
                box-shadow: ${isExcluded ? "0 1px 2px rgba(15,23,42,0.08)" : "none"};
                border: none;
                border-radius: 5px;
                padding: 4px 9px;
                font-size: 11px;
                cursor: pointer;
              ">
                Keep
              </button>
            </div>
          </div>
        `;

        // Attach individual Redact / Keep handlers
        const btnRedact = itemDiv.querySelector(".ss-btn-redact");
        const btnKeep = itemDiv.querySelector(".ss-btn-keep");

        btnRedact.addEventListener("click", () => {
          if (excludedDetectionIds.has(d.id)) {
            saveUndoState();
            excludedDetectionIds.delete(d.id);
            renderDetections();
            updateRedactionsOnServer();
          }
        });

        btnKeep.addEventListener("click", () => {
          if (!excludedDetectionIds.has(d.id)) {
            saveUndoState();
            excludedDetectionIds.add(d.id);
            renderDetections();
            updateRedactionsOnServer();
          }
        });

        detectionsContainer.appendChild(itemDiv);
      });
    }

    // Bulk actions
    overlay.querySelector("#ssBtnRedactAll").addEventListener("click", () => {
      if (excludedDetectionIds.size > 0) {
        saveUndoState();
        excludedDetectionIds.clear();
        renderDetections();
        updateRedactionsOnServer();
      }
    });

    overlay.querySelector("#ssBtnKeepAll").addEventListener("click", () => {
      if (excludedDetectionIds.size !== currentScan.detections.length) {
        saveUndoState();
        currentScan.detections.forEach((d) => excludedDetectionIds.add(d.id));
        renderDetections();
        updateRedactionsOnServer();
      }
    });

    function updateRedactionsOnServer() {
      const currentSeq = ++updateSeq;
      if (previewLoading) previewLoading.style.display = "flex";

      chrome.runtime.sendMessage(
        {
          action: "UPDATE_ATTACHMENT_REDACTIONS",
          sessionId: currentScan.session_id,
          excludedDetectionIds: Array.from(excludedDetectionIds),
          manualRedactions: manualRedactions
        },
        (res) => {
          if (currentSeq !== updateSeq) return;
          if (previewLoading) previewLoading.style.display = "none";
          if (res && res.success) {
            currentScan.sanitized_base64 = res.sanitized_base64;
            currentScan.preview_data_url = res.preview_data_url;
            currentScan.sanitized_filename = res.sanitized_filename;
            if (res.detections) {
              currentScan.detections = res.detections;
            }
            if (res.pages) {
              currentScan.pages = res.pages;
              currentScan.page_count = res.page_count || res.pages.length;
              updatePageNav();
            }

            const curPreview = (currentScan.pages && currentScan.pages[currentPage - 1])
              ? currentScan.pages[currentPage - 1].preview_data_url
              : (res.preview_data_url || currentScan.preview_data_url);

            if (previewImg && curPreview) {
              previewImg.src = curPreview;
            }
            renderManualBoxes();
          } else {
            console.warn("[ShareSafe] Failed to update redactions:", res ? res.error : "Unknown error");
          }
        }
      );
    }

    updatePageNav();
    renderDetections();
    renderManualBoxes();
    renderManualList();

    function cleanUpListeners() {
      window.removeEventListener("keydown", onKeyDown);
      try { resizeObs.disconnect(); } catch (_) {}
    }

    // Confirm & Send Sanitized Attachment (Sends the updated sanitized file)
    overlay.querySelector("#ssBtnSendSanitized").addEventListener("click", () => {
      cleanUpListeners();
      overlay.remove();
      if (typeof onConfirmSendSanitized === "function") {
        onConfirmSendSanitized(currentScan);
      }
    });

    // Download Clean Copy Locally (Uses the user's selected redaction settings)
    overlay.querySelector("#ssBtnDownloadClean").addEventListener("click", () => {
      try {
        const blob = base64ToBlob(currentScan.sanitized_base64, currentScan.sanitized_mime);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = currentScan.sanitized_filename || `safe_${file.name}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showStatusToast(`Saved clean copy as "${currentScan.sanitized_filename}"`, "success");
      } catch (e) {
        console.error("[ShareSafe] Download failed:", e);
      }
    });

    // Cancel Attachment
    overlay.querySelector("#ssBtnCancel").addEventListener("click", () => {
      cleanUpListeners();
      overlay.remove();
      if (typeof onCancel === "function") onCancel();
      showStatusToast(`Attachment upload cancelled. Original file protected.`, "info");
    });

    // Override (Send Original Unredacted)
    overlay.querySelector("#ssBtnOverride").addEventListener("click", () => {
      cleanUpListeners();
      overlay.remove();
      bypassedFiles.add(file);
      if (typeof onOverride === "function") onOverride();
      showStatusToast(`Override granted. Original file sending unredacted.`, "info");
    });
  }

  // Auto-Redact Pipeline Coordinator
  async function processAttachment(file, target, onProceedWithSanitized) {
    // 1. Validate inspectable extension
    if (!isInspectableFile(file)) {
      showUnsupportedFileModal(
        file,
        // onCancel
        () => {
          try { target.value = ""; } catch (_) {}
        },
        // onOverride
        () => {
          bypassedFiles.add(file);
          onProceedWithSanitized(file);
        }
      );
      return;
    }

    // 2. Encode to Base64 & display spacious ShareSafe scanning card
    const scanningCard = window.ShareSafeUI.showScanningCard(file);

    let base64Data;
    try {
      base64Data = await fileToBase64(file);
    } catch (err) {
      if (scanningCard && scanningCard.parentElement) scanningCard.remove();
      showScanFailedModal(file, "Failed to read file into memory.", () => { target.value = ""; }, () => { bypassedFiles.add(file); onProceedWithSanitized(file); });
      return;
    }

    // 3. Delegate to Background Service Worker -> /api/auto-redact-attachment
    chrome.runtime.sendMessage(
      {
        action: "AUTO_REDACT_ATTACHMENT",
        filename: file.name,
        fileType: file.type,
        fileSize: file.size,
        base64Data: base64Data
      },
      (res) => {
        if (scanningCard && scanningCard.parentElement) scanningCard.remove();

        if (chrome.runtime.lastError || !res || !res.success) {
          const err = chrome.runtime.lastError?.message || res?.error || "Connection error to local server";
          showScanFailedModal(
            file,
            err,
            // onCancel
            () => {
              try { target.value = ""; } catch (_) {}
            },
            // onOverride
            () => {
              bypassedFiles.add(file);
              onProceedWithSanitized(file);
            }
          );
          return;
        }

        // 4. If clean (0 sensitive items detected), show Attachment Verified card and attach safely
        if (res.is_clean || res.total_findings === 0) {
          window.ShareSafeUI.showVerifiedCard(file, 3200);
          bypassedFiles.add(file);
          onProceedWithSanitized(file);
          return;
        }

        // 5. Sensitive items detected & auto-redacted: Present Review Modal
        showAttachmentReviewModal(
          file,
          res,
          // onConfirmSendSanitized
          (finalScan) => {
            const blob = base64ToBlob(finalScan.sanitized_base64, finalScan.sanitized_mime);
            const sanitizedFile = new File([blob], file.name, {
              type: finalScan.sanitized_mime || file.type,
              lastModified: Date.now()
            });

            bypassedFiles.add(sanitizedFile);
            onProceedWithSanitized(sanitizedFile);
            showStatusToast(`Attachment sanitized! Protected copy sent to chat.`, "success", 3500);
          },
          // onCancel
          () => {
            try { target.value = ""; } catch (_) {}
          },
          // onOverride
          () => {
            bypassedFiles.add(file);
            onProceedWithSanitized(file);
          }
        );
      }
    );
  }

  // Intercept Input[type="file"] in capture phase
  document.addEventListener("change", (event) => {
    const target = event.target;
    if (!target || target.tagName !== "INPUT" || target.type !== "file") return;

    const files = target.files;
    if (!files || !files.length) return;

    const file = files[0];
    if (bypassedFiles.has(file)) {
      // File has been sanitized and approved or consciously overridden: allow WhatsApp/Gmail to process
      return;
    }

    // HALT immediate event propagation so WhatsApp/Gmail does NOT receive the original file
    event.stopImmediatePropagation();
    event.preventDefault();

    processAttachment(file, target, (sanitizedFile) => {
      // Swap sanitized file into input using DataTransfer
      try {
        const dt = new DataTransfer();
        dt.items.add(sanitizedFile);
        target.files = dt.files;
        // Dispatch synthetic change event to trigger platform preview/upload
        target.dispatchEvent(new Event("change", { bubbles: true }));
      } catch (err) {
        console.error("[ShareSafe] Failed to swap attachment into file input:", err);
      }
    });
  }, true);

  // Intercept Drag & Drop attachments
  document.addEventListener("drop", (event) => {
    if (!event.dataTransfer || !event.dataTransfer.files || !event.dataTransfer.files.length) return;
    const file = event.dataTransfer.files[0];
    if (bypassedFiles.has(file)) return;

    // Halt original drop propagation
    event.preventDefault();
    event.stopImmediatePropagation();

    const dropTarget = event.target;

    processAttachment(file, dropTarget, (sanitizedFile) => {
      // Re-dispatch synthetic drop event with sanitized file
      try {
        const dt = new DataTransfer();
        dt.items.add(sanitizedFile);
        const dropEvent = new DragEvent("drop", {
          bubbles: true,
          cancelable: true,
          dataTransfer: dt
        });
        dropTarget.dispatchEvent(dropEvent);
      } catch (err) {
        console.error("[ShareSafe] Failed to re-dispatch drop with sanitized file:", err);
      }
    });
  }, true);

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  console.log("[ShareSafe] Automatic Attachment Redaction Shield active. Prioritizing WhatsApp Web & Gmail files.");
})();
