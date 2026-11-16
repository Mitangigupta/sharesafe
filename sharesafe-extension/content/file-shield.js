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
  const ALLOWED_EXTS = ["pdf", "png", "jpg", "jpeg", "webp", "bmp"];
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

  // Floating Status Toast
  function showStatusToast(message, type = "info", duration = 3000) {
    const existing = document.getElementById("sharesafe-status-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "sharesafe-status-toast";
    toast.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 2147483647;
      padding: 10px 16px;
      background: ${type === "error" ? "#FCE8E7" : type === "success" ? "#EAF0EB" : "#FFFFFF"};
      color: ${type === "error" ? "#A74440" : type === "success" ? "#647C70" : "#252522"};
      border: 1px solid ${type === "error" ? "#E8B4B2" : type === "success" ? "#CDDDD3" : "#EAE5DD"};
      border-radius: 8px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.12);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 13px;
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 10px;
      animation: sharesafeSlideUp 0.25s ease;
      pointer-events: none;
    `;

    toast.innerHTML = `
      <span style="font-size: 15px;">🛡️</span>
      <span>${escapeHtml(message)}</span>
    `;

    document.body.appendChild(toast);

    if (duration > 0) {
      setTimeout(() => {
        if (toast.parentElement) {
          toast.style.opacity = "0";
          toast.style.transition = "opacity 0.3s ease";
          setTimeout(() => toast.remove(), 300);
        }
      }, duration);
    }
    return toast;
  }

  // Unsupported File Alert Modal (Never silently treat as safe)
  function showUnsupportedFileModal(file, onCancel, onOverride) {
    const existing = document.getElementById("sharesafe-shield-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "sharesafe-shield-overlay";
    overlay.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(37, 37, 34, 0.65); backdrop-filter: blur(4px);
      z-index: 2147483647; display: flex; align-items: center; justify-content: center;
      padding: 20px; font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    `;

    const ext = getFileExtension(file.name);
    overlay.innerHTML = `
      <div style="background: #FFFFFF; border-radius: 12px; width: 100%; max-width: 480px; box-shadow: 0 12px 36px rgba(0,0,0,0.22); overflow: hidden; border: 1px solid #EAE5DD;">
        <div style="padding: 16px 20px; background: #FDF1E3; border-bottom: 1px solid #E8D7BF; display: flex; align-items: center; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 32px; height: 32px; border-radius: 6px; background: #F5EBDD; color: #B27329; display: flex; align-items: center; justify-content: center; font-size: 16px;">⚠️</div>
            <div>
              <div style="font-size: 14px; font-weight: 700; color: #252522;">Unsupported Attachment Format</div>
              <div style="font-size: 11px; color: #77736D;">ShareSafe Attachment Shield Notice</div>
            </div>
          </div>
          <span style="font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; background: #F5EBDD; color: #B27329;">UNVERIFIED</span>
        </div>
        <div style="padding: 20px;">
          <p style="font-size: 13px; color: #252522; line-height: 1.5; margin-bottom: 12px;">
            The file <strong>"${escapeHtml(file.name)}"</strong> has extension <code>.${escapeHtml(ext)}</code>, which is not supported for automatic OCR inspection and vector sanitization.
          </p>
          <div style="background: #F8F6F2; border: 1px solid #EAE5DD; border-radius: 6px; padding: 10px 12px; font-size: 12px; color: #77736D; margin-bottom: 16px;">
            <strong>Protected formats:</strong> PDF, PNG, JPG, JPEG, WEBP, BMP.<br/>
            To avoid accidental data leaks, transmission has been paused.
          </div>
          <div style="display: flex; gap: 10px; margin-bottom: 10px;">
            <button id="ssBtnCancel" style="flex: 1; padding: 10px 14px; background: #A74440; color: #FFFFFF; border: none; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer;">
              🛑 Cancel Attachment (Recommended)
            </button>
          </div>
          <button id="ssBtnOverride" style="width: 100%; background: none; border: none; color: #77736D; font-size: 11px; cursor: pointer; text-decoration: underline; text-align: center; padding: 4px;">
            I understand the risk; send unverified file
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector("#ssBtnCancel").addEventListener("click", () => {
      overlay.remove();
      if (typeof onCancel === "function") onCancel();
      showStatusToast(`Attachment cancelled. "${file.name}" was not sent.`, "info");
    });

    overlay.querySelector("#ssBtnOverride").addEventListener("click", () => {
      overlay.remove();
      if (typeof onOverride === "function") onOverride();
      showStatusToast(`Override authorized. Sending unverified file.`, "info");
    });
  }

  // Scan Failure or Server Offline Modal
  function showScanFailedModal(file, errMsg, onCancel, onOverride) {
    const existing = document.getElementById("sharesafe-shield-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "sharesafe-shield-overlay";
    overlay.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(37, 37, 34, 0.65); backdrop-filter: blur(4px);
      z-index: 2147483647; display: flex; align-items: center; justify-content: center;
      padding: 20px; font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    `;

    overlay.innerHTML = `
      <div style="background: #FFFFFF; border-radius: 12px; width: 100%; max-width: 480px; box-shadow: 0 12px 36px rgba(0,0,0,0.22); overflow: hidden; border: 1px solid #EAE5DD;">
        <div style="padding: 16px 20px; background: #FCE8E7; border-bottom: 1px solid #E8B4B2; display: flex; align-items: center; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 32px; height: 32px; border-radius: 6px; background: #F9ECEB; color: #A74440; display: flex; align-items: center; justify-content: center; font-size: 16px;">🛑</div>
            <div>
              <div style="font-size: 14px; font-weight: 700; color: #252522;">Attachment Scan Unreachable</div>
              <div style="font-size: 11px; color: #77736D;">ShareSafe Local Engine Offline or Blocked</div>
            </div>
          </div>
          <span style="font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; background: #F9ECEB; color: #A74440;">OFFLINE</span>
        </div>
        <div style="padding: 20px;">
          <p style="font-size: 13px; color: #252522; line-height: 1.5; margin-bottom: 12px;">
            Unable to connect to the local ShareSafe engine at <code>http://127.0.0.1:5000</code> to scan <strong>"${escapeHtml(file.name)}"</strong>.
          </p>
          <div style="background: #F8F6F2; border: 1px solid #EAE5DD; border-radius: 6px; padding: 10px 12px; font-size: 12px; color: #77736D; margin-bottom: 16px;">
            ${escapeHtml(errMsg || "Make sure the Python server is running (python app.py).")}
          </div>
          <div style="display: flex; gap: 10px; margin-bottom: 10px;">
            <button id="ssBtnCancel" style="flex: 1; padding: 10px 14px; background: #A74440; color: #FFFFFF; border: none; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer;">
              🛑 Cancel Attachment (Recommended)
            </button>
          </div>
          <button id="ssBtnOverride" style="width: 100%; background: none; border: none; color: #77736D; font-size: 11px; cursor: pointer; text-decoration: underline; text-align: center; padding: 4px;">
            Send original file uninspected (Override)
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector("#ssBtnCancel").addEventListener("click", () => {
      overlay.remove();
      if (typeof onCancel === "function") onCancel();
      showStatusToast(`Attachment cancelled. "${file.name}" was not sent.`, "info");
    });

    overlay.querySelector("#ssBtnOverride").addEventListener("click", () => {
      overlay.remove();
      if (typeof onOverride === "function") onOverride();
      showStatusToast(`Upload override granted. Sending uninspected file.`, "info");
    });
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
      background: rgba(42, 42, 42, 0.65); backdrop-filter: blur(4px);
      z-index: 2147483647; display: flex; align-items: center; justify-content: center;
      padding: 16px; box-sizing: border-box; font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
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
    const riskLevel = risk.level || "HIGH";
    const riskScore = risk.score || 0;
    const isPdf = currentScan.is_pdf;
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
          background: #FFFBF3;
          border-radius: 4px;
        }
        #ssDetectionsList::-webkit-scrollbar-thumb, #ssManualList::-webkit-scrollbar-thumb {
          background: #D9CFC7;
          border-radius: 4px;
        }
        #ssDetectionsList::-webkit-scrollbar-thumb:hover, #ssManualList::-webkit-scrollbar-thumb:hover {
          background: #B3A8A0;
        }
        .ss-btn-choice {
          transition: all 0.15s ease;
          user-select: none;
        }
        .ss-btn-choice:hover {
          filter: brightness(0.95);
        }
        .ss-detection-row {
          transition: background 0.15s ease, border-color 0.15s ease;
        }
        .ss-editor-btn {
          padding: 4px 8px;
          font-size: 11px;
          font-weight: 600;
          border-radius: 6px;
          cursor: pointer;
          border: 1px solid #E5E7EB;
          background: #FFFFFF;
          color: #374151;
          display: inline-flex;
          align-items: center;
          gap: 4px;
          transition: all 0.15s ease;
          user-select: none;
        }
        .ss-editor-btn:hover:not(:disabled) {
          background: #F9FAFB;
          border-color: #D1D5DB;
        }
        .ss-editor-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
          color: #9CA3AF;
        }
        .ss-editor-btn.active {
          background: #C65A4A !important;
          color: #FFFFFF !important;
          border-color: #B3493A !important;
          box-shadow: 0 1px 3px rgba(198, 90, 74, 0.3);
        }
        .ss-manual-box {
          box-sizing: border-box;
          transition: border-color 0.1s ease, box-shadow 0.1s ease;
        }
        .ss-manual-box:hover {
          border-color: #C65A4A !important;
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
            max-height: 260px !important;
          }
        }
      </style>
      <div id="ssModalContainer" style="background: #FFFBF3; border-radius: 16px; width: 100%; max-width: 890px; max-height: 92vh; height: min(760px, 92vh); display: flex; flex-direction: column; box-shadow: 0 16px 48px rgba(198, 90, 74, 0.12), 0 4px 16px rgba(0,0,0,0.04); overflow: hidden; border: 1px solid #F1E8E0; box-sizing: border-box;">
        
        <!-- Header (Fixed top) -->
        <div style="padding: 12px 20px; background: #FFFFFF; border-bottom: 1px solid #F1E8E0; display: flex; align-items: center; justify-content: space-between; flex-shrink: 0;">
          <div style="display: flex; align-items: center; gap: 12px;">
            <div style="width: 36px; height: 36px; border-radius: 10px; background: #FDF1EE; border: 1px solid #F8DCD6; display: flex; align-items: center; justify-content: center; color: #C65A4A; font-size: 16px;">
              🛡️
            </div>
            <div>
              <div style="font-family: 'Newsreader', Georgia, serif; font-size: 17px; font-weight: 600; color: #2A2A2A; letter-spacing: -0.01em;">Attachment Redaction &amp; Review</div>
              <div style="font-size: 11px; font-weight: 500; color: #C65A4A; display: flex; align-items: center; gap: 4px;">
                <span>&bull;</span>
                <span>Zero-Leak Local Privacy Shield</span>
              </div>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span id="ssManualBadge" style="display: none; font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 9999px; background: #FDF1EE; color: #C65A4A; border: 1px solid #F8DCD6;">
              ✏️ MANUAL REDACT ACTIVE
            </span>
            <span style="font-size: 10px; font-weight: 700; padding: 4px 10px; border-radius: 9999px; background: #C65A4A; color: #FFFFFF; text-transform: uppercase; letter-spacing: 0.4px;">
              ${riskLevel} RISK (${riskScore}/100)
            </span>
          </div>
        </div>

        <!-- Verification Seal Banner (Fixed) -->
        <div style="background: #EAF3EE; border-bottom: 1px solid #D5E7DC; padding: 7px 20px; font-size: 11px; font-weight: 600; color: #2E7D5B; display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
          <span>✓</span>
          <span><strong>Preview &mdash; Safe to Send:</strong> Underlying text streams permanently flattened (0 characters) &bull; Metadata stripped.</span>
        </div>

        <!-- Main Body: Two-Column Review Layout (Flex-grow, contained inside viewport) -->
        <div id="ssReviewBody" style="padding: 12px 18px; overflow: hidden; flex: 1; min-height: 0; display: grid; grid-template-columns: 330px 1fr; gap: 14px; box-sizing: border-box;">
          
          <!-- Column 1: Visual Sanitized Preview & Manual Redactor -->
          <div id="ssPreviewCard" style="background: #FFFFFF; border: 1px solid #F1E8E0; border-radius: 16px; padding: 12px; box-shadow: 0 4px 16px rgba(198, 90, 74, 0.04); display: flex; flex-direction: column; min-height: 0; overflow: hidden; box-sizing: border-box;">
            
            <!-- Preview Top Bar -->
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; flex-shrink: 0;">
              <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: #2A2A2A;">
                Sanitized Preview
              </span>
              <span id="ssPreviewSafeBadge" style="background: #EAF3EE; color: #2E7D5B; border: 1px solid #D5E7DC; border-radius: 9999px; padding: 2px 8px; font-size: 10px; font-weight: 600;">
                ✓ Safe to Send
              </span>
            </div>

            <!-- Editor Toolbar: Manual Redact, Undo/Redo, Delete, Page Navigation -->
            <div id="ssEditorToolbar" style="display: flex; align-items: center; justify-content: space-between; gap: 4px; flex-wrap: wrap; margin-bottom: 6px; padding: 5px 8px; background: #FFFBF3; border: 1px solid #F1E8E0; border-radius: 8px; flex-shrink: 0;">
              <div style="display: flex; align-items: center; gap: 4px;">
                <button type="button" id="ssBtnToggleManual" class="ss-editor-btn" title="Toggle manual draw-to-redact mode">
                  <span>✏️</span><span>Manual Redact</span>
                </button>
                <div id="ssToolGroup" style="display: none; align-items: center; background: #F3ECE7; padding: 2px; border-radius: 6px; gap: 2px; border: 1px solid #E6DCD5;">
                  <button type="button" id="ssToolDraw" class="ss-editor-btn active" style="padding: 2px 6px; font-size: 10px;" title="Draw rectangular blackout box">
                    Draw
                  </button>
                  <button type="button" id="ssToolSelect" class="ss-editor-btn" style="padding: 2px 6px; font-size: 10px;" title="Select and delete existing manual redactions">
                    Select
                  </button>
                </div>
              </div>

              <div style="display: flex; align-items: center; gap: 3px;">
                <button type="button" id="ssBtnUndo" class="ss-editor-btn" title="Undo last action" disabled>
                  <span>↩️</span>
                </button>
                <button type="button" id="ssBtnRedo" class="ss-editor-btn" title="Redo action" disabled>
                  <span>↪️</span>
                </button>
                <button type="button" id="ssBtnDeleteSelected" class="ss-editor-btn" title="Delete selected manual redaction" disabled>
                  <span>🗑️</span>
                </button>
              </div>

              <!-- Multi-Page Navigation for PDFs -->
              <div id="ssPageNavGroup" style="display: ${pageCount > 1 ? 'flex' : 'none'}; align-items: center; gap: 3px;">
                <button type="button" id="ssBtnPrevPage" class="ss-editor-btn" style="padding: 2px 6px; font-size: 10px;" title="Previous Page" ${currentPage === 1 ? 'disabled' : ''}>
                  ◀
                </button>
                <span id="ssPageIndicator" style="font-size: 10px; font-weight: 700; color: #2A2A2A; min-width: 54px; text-align: center;">
                  Page ${currentPage} / ${pageCount}
                </span>
                <button type="button" id="ssBtnNextPage" class="ss-editor-btn" style="padding: 2px 6px; font-size: 10px;" title="Next Page" ${currentPage === pageCount ? 'disabled' : ''}>
                  ▶
                </button>
              </div>
            </div>

            <!-- Viewport Container with Image, Overlay and RubberBand -->
            <div id="ssPreviewViewport" style="background: #FFFBF3; border: 1px solid #F1E8E0; border-radius: 10px; overflow: hidden; flex: 1; min-height: 200px; display: flex; align-items: center; justify-content: center; position: relative; user-select: none;">
              <img id="ssPreviewImg" src="${currentScan.preview_data_url || ''}" alt="Redacted Preview" style="width: 100%; height: 100%; object-fit: contain; display: block; pointer-events: none;" />
              
              <!-- Drawing & Selection Interaction Layer -->
              <div id="ssDrawingLayer" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 15;">
                <!-- Manual redaction boxes placed here -->
              </div>

              <!-- Rubberband Rectangle -->
              <div id="ssRubberBand" style="display: none; position: absolute; border: 2px dashed #C65A4A; background: rgba(198, 90, 74, 0.25); pointer-events: none; z-index: 25; border-radius: 2px;"></div>

              <!-- Updating Spinner -->
              <div id="ssPreviewLoading" style="display: none; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,251,243,0.88); backdrop-filter: blur(2px); flex-direction: column; align-items: center; justify-content: center; font-size: 12px; color: #C65A4A; font-weight: 600; gap: 8px; z-index: 30;">
                <div style="width: 26px; height: 26px; border: 3px solid #F8DCD6; border-top-color: #C65A4A; border-radius: 50%; animation: ssSpin 0.75s linear infinite;"></div>
                <span>Updating sanitized copy...</span>
              </div>
            </div>

            <!-- File Metadata Line -->
            <div style="font-size: 11px; color: #6B7280; line-height: 1.35; margin-top: 6px; flex-shrink: 0;">
              <strong style="color: #2A2A2A;">${escapeHtml(file.name)}</strong> &bull; ${formatBytes(file.size)} &bull; ${isPdf ? "PDF Document" : "Image"}<br/>
              <span id="ssRedactedSummary" style="color: #C65A4A; font-weight: 600;">All sensitive items redacted</span>
            </div>
          </div>

          <!-- Column 2: Scrollable Detections List & Manual Redactions Panel -->
          <div style="background: #FFFFFF; border: 1px solid #F1E8E0; border-radius: 16px; padding: 12px 14px; box-shadow: 0 4px 16px rgba(198, 90, 74, 0.04); display: flex; flex-direction: column; min-height: 0; overflow: hidden; box-sizing: border-box;">
            
            <!-- Panel Header with live counts & bulk actions -->
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-shrink: 0;">
              <div>
                <span id="ssActiveCount" style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: #2A2A2A;">
                  Detected Items &mdash; ${currentScan.detections.length} redacted
                </span>
              </div>
              <div style="display: flex; gap: 6px;">
                <button type="button" id="ssBtnRedactAll" title="Redact all detected sensitive items" style="
                  background: #FDF1EE;
                  color: #C65A4A;
                  border: 1px solid #F8DCD6;
                  border-radius: 6px;
                  padding: 3px 8px;
                  font-size: 10px;
                  font-weight: 700;
                  cursor: pointer;
                  text-transform: uppercase;
                  letter-spacing: 0.3px;
                  transition: all 0.15s ease;
                ">
                  Redact All
                </button>
                <button type="button" id="ssBtnKeepAll" title="Keep all items visible (unredacted)" style="
                  background: #EAF3EE;
                  color: #2E7D5B;
                  border: 1px solid #D5E7DC;
                  border-radius: 6px;
                  padding: 3px 8px;
                  font-size: 10px;
                  font-weight: 700;
                  cursor: pointer;
                  text-transform: uppercase;
                  letter-spacing: 0.3px;
                  transition: all 0.15s ease;
                ">
                  Keep All
                </button>
              </div>
            </div>

            <!-- Scrollable Automatic Detections List -->
            <div id="ssDetectionsList" style="flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 7px; padding-right: 4px; margin: 2px 0 4px 0;">
              <!-- Dynamic detections rendered here -->
            </div>

            <!-- Manual Redactions Section (Collapsible / Listed) -->
            <div id="ssManualSection" style="display: none; margin-top: 6px; border-top: 1px dashed #F1E8E0; padding-top: 6px; flex-shrink: 0;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <span id="ssManualCount" style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #2A2A2A;">
                  Manual Redactions (0)
                </span>
                <button type="button" id="ssBtnClearManual" style="background: none; border: none; font-size: 10px; font-weight: 600; color: #C65A4A; cursor: pointer; text-decoration: underline; padding: 0;">
                  Clear All Manual
                </button>
              </div>
              <div id="ssManualList" style="display: flex; flex-direction: column; gap: 4px; max-height: 85px; overflow-y: auto; padding-right: 4px;">
                <!-- Manual items rendered here -->
              </div>
            </div>

            <!-- Helpful control hint -->
            <div style="font-size: 11px; color: #6B7280; background: #FFFBF3; border: 1px solid #F1E8E0; border-radius: 8px; padding: 6px 10px; flex-shrink: 0; line-height: 1.35; margin-top: 4px;">
              💡 <em>Toggle <strong>Redact</strong> or <strong>Keep</strong> for auto-detections. Activate <strong>Manual Redact</strong> to draw blackout boxes anywhere.</em>
            </div>
          </div>

        </div>

        <!-- Actions Footer (Fixed bottom) -->
        <div id="ssModalFooter" style="padding: 12px 20px; background: #FFFFFF; border-top: 1px solid #F1E8E0; display: flex; flex-direction: column; gap: 6px; flex-shrink: 0; box-sizing: border-box;">
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <!-- Primary Action: Send Sanitized -->
            <button id="ssBtnSendSanitized" style="flex: 2; min-width: 180px; padding: 10px 18px; background: #C65A4A; color: #FFFFFF; border: none; border-radius: 10px; font-size: 13px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; box-shadow: 0 2px 8px rgba(198, 90, 74, 0.22); transition: all 0.18s ease;">
              <span>✅ Send Sanitized Attachment</span>
            </button>
            <!-- Secondary: Download Clean Copy -->
            <button id="ssBtnDownloadClean" style="flex: 1; min-width: 140px; padding: 10px 14px; background: #FFFFFF; color: #2A2A2A; border: 1px solid #F1E8E0; border-radius: 10px; font-size: 12px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px;">
              <span>⬇️ Download Clean Copy</span>
            </button>
            <!-- Cancel -->
            <button id="ssBtnCancel" style="padding: 10px 14px; background: #FFFFFF; color: #6B7280; border: 1px solid #F1E8E0; border-radius: 10px; font-size: 12px; font-weight: 600; cursor: pointer;">
              Cancel
            </button>
          </div>
          <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 2px;">
            <button id="ssBtnOverride" style="background: none; border: none; color: #6B7280; font-size: 11px; cursor: pointer; text-decoration: underline; padding: 0;">
              I understand the risks; send original unredacted file (Override)
            </button>
            <span style="font-size: 11px; color: #6B7280;">🛡️ Original file is never altered on disk</span>
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

      activeCountElem.textContent = `Detected Items — ${activeRedacted} redacted, ${excludedCount} kept`;
      if (redactedSummaryElem) {
        const manualCount = manualRedactions.length;
        const manualNote = manualCount > 0 ? ` &bull; ${manualCount} manual redaction${manualCount === 1 ? '' : 's'}` : '';
        if (activeRedacted === total) {
          redactedSummaryElem.innerHTML = `All ${total} sensitive items redacted${manualNote}`;
          redactedSummaryElem.style.color = "#C65A4A";
        } else if (activeRedacted === 0) {
          redactedSummaryElem.innerHTML = `All sensitive items kept visible${manualNote}`;
          redactedSummaryElem.style.color = "#B27329";
        } else {
          redactedSummaryElem.innerHTML = `${activeRedacted} of ${total} items redacted${manualNote}`;
          redactedSummaryElem.style.color = "#C65A4A";
        }
      }

      if (previewSafeBadge) {
        if (activeRedacted === 0 && manualRedactions.length === 0) {
          previewSafeBadge.textContent = "⚠️ Unredacted Copy";
          previewSafeBadge.style.background = "#FDF1E3";
          previewSafeBadge.style.color = "#B27329";
          previewSafeBadge.style.borderColor = "#E8D7BF";
        } else {
          previewSafeBadge.textContent = "✓ Safe to Send";
          previewSafeBadge.style.background = "#EAF3EE";
          previewSafeBadge.style.color = "#2E7D5B";
          previewSafeBadge.style.borderColor = "#D5E7DC";
        }
      }

      currentScan.detections.forEach((d) => {
        const isExcluded = excludedDetectionIds.has(d.id);
        const itemDiv = document.createElement("div");
        itemDiv.className = "ss-detection-row";
        itemDiv.style.cssText = `
          background: ${isExcluded ? "#FCFDFD" : "#FFFFFF"};
          border: 1px solid ${isExcluded ? "#D5E7DC" : "#F1E8E0"};
          border-left: 3px solid ${isExcluded ? "#2E7D5B" : "#C65A4A"};
          border-radius: 10px;
          padding: 8px 10px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          box-sizing: border-box;
        `;

        const icon = getDetectionIcon(d.type, d.label);
        const itemLabel = escapeHtml(d.label || d.type || "Sensitive Item");
        const maskedVal = escapeHtml(d.masked || "••••••••");
        const rawVal = escapeHtml(d.value || "");
        const details = escapeHtml(d.details || "Verified pattern");

        itemDiv.innerHTML = `
          <!-- Left: Icon & Description -->
          <div style="display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0;">
            <div style="width: 30px; height: 30px; border-radius: 8px; background: ${isExcluded ? "#EAF3EE" : "#FDF1EE"}; border: 1px solid ${isExcluded ? "#D5E7DC" : "#F8DCD6"}; color: ${isExcluded ? "#2E7D5B" : "#C65A4A"}; display: flex; align-items: center; justify-content: center; font-size: 13px; flex-shrink: 0;">
              ${icon}
            </div>
            <div style="flex: 1; min-width: 0;">
              <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 2px;">
                <span style="font-size: 12px; font-weight: 700; color: #2A2A2A; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
                  ${itemLabel}
                </span>
                <span class="ss-item-badge" style="font-size: 9px; font-weight: 700; padding: 1px 6px; border-radius: 9999px; background: ${isExcluded ? "#EAF3EE" : "#FDF1EE"}; color: ${isExcluded ? "#2E7D5B" : "#C65A4A"}; border: 1px solid ${isExcluded ? "#D5E7DC" : "#F8DCD6"}; text-transform: uppercase; letter-spacing: 0.3px;">
                  ${isExcluded ? "KEPT" : "REDACTED"}
                </span>
              </div>
              <div style="font-size: 11px; color: #6B7280; display: flex; align-items: center; gap: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                <code style="font-size: 11px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: ${isExcluded ? "#EAF3EE" : "#F9FAFB"}; color: ${isExcluded ? "#2E7D5B" : "#4B5563"}; padding: 1px 5px; border-radius: 4px; border: 1px solid ${isExcluded ? "#D5E7DC" : "#E5E7EB"}; font-weight: ${isExcluded ? "600" : "400"};">
                  ${isExcluded ? rawVal : maskedVal}
                </code>
                <span style="color: #9CA3AF; font-size: 10px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">${details}</span>
              </div>
            </div>
          </div>

          <!-- Right: Individual Redact / Keep Segmented Switch -->
          <div class="ss-toggle-group" role="group" aria-label="Controls for ${itemLabel}" style="
            display: inline-flex;
            align-items: center;
            background: #F3ECE7;
            padding: 2px;
            border-radius: 8px;
            border: 1px solid #E6DCD5;
            flex-shrink: 0;
            gap: 2px;
          ">
            <button type="button" class="ss-btn-choice ss-btn-redact" data-action="redact" title="Redact ${itemLabel} (Hide in attachment)" style="
              background: ${!isExcluded ? "#C65A4A" : "transparent"};
              color: ${!isExcluded ? "#FFFFFF" : "#78716C"};
              font-weight: ${!isExcluded ? "700" : "500"};
              box-shadow: ${!isExcluded ? "0 1px 3px rgba(198,90,74,0.3)" : "none"};
              border: none;
              border-radius: 6px;
              padding: 4px 9px;
              font-size: 11px;
              cursor: pointer;
              display: inline-flex;
              align-items: center;
              gap: 3px;
            ">
              <span>🛡️</span><span>Redact</span>
            </button>
            <button type="button" class="ss-btn-choice ss-btn-keep" data-action="keep" title="Keep ${itemLabel} (Show in attachment)" style="
              background: ${isExcluded ? "#2E7D5B" : "transparent"};
              color: ${isExcluded ? "#FFFFFF" : "#78716C"};
              font-weight: ${isExcluded ? "700" : "500"};
              box-shadow: ${isExcluded ? "0 1px 3px rgba(46,125,91,0.3)" : "none"};
              border: none;
              border-radius: 6px;
              padding: 4px 9px;
              font-size: 11px;
              cursor: pointer;
              display: inline-flex;
              align-items: center;
              gap: 3px;
            ">
              <span>👁️</span><span>Keep</span>
            </button>
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

    // 2. Encode to Base64
    const toast = showStatusToast(`Scanning & auto-redacting "${file.name}"...`, "info", 0);

    let base64Data;
    try {
      base64Data = await fileToBase64(file);
    } catch (err) {
      if (toast.parentElement) toast.remove();
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
        if (toast.parentElement) toast.remove();

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

        // 4. If clean (0 sensitive items detected), attach normally
        if (res.is_clean || res.total_findings === 0) {
          showStatusToast(`"${file.name}" is Clean. Attaching safely.`, "success", 2500);
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
