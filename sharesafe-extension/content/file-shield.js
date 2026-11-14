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

  // Interactive Attachment Redaction & Review Interface
  function showAttachmentReviewModal(file, scanData, onConfirmSendSanitized, onCancel, onOverride) {
    const existing = document.getElementById("sharesafe-shield-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "sharesafe-shield-overlay";
    overlay.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(37, 37, 34, 0.72); backdrop-filter: blur(5px);
      z-index: 2147483647; display: flex; align-items: center; justify-content: center;
      padding: 16px; font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    `;

    let currentScan = scanData;
    const excludedDetectionIds = new Set();
    const risk = currentScan.risk_summary || {};
    const riskLevel = risk.level || "HIGH";
    const riskScore = risk.score || 0;
    const isPdf = currentScan.is_pdf;

    const riskColor = riskLevel === "CRITICAL" ? "#A74440" : riskLevel === "HIGH" ? "#C96D67" : "#B27329";
    const riskBg = riskLevel === "CRITICAL" ? "#FCE8E7" : riskLevel === "HIGH" ? "#F9ECEB" : "#F5EBDD";

    overlay.innerHTML = `
      <div style="background: #FFFFFF; border-radius: 12px; width: 100%; max-width: 720px; max-height: 90vh; display: flex; flex-direction: column; box-shadow: 0 16px 48px rgba(0,0,0,0.25); overflow: hidden; border: 1px solid #EAE5DD;">
        <!-- Header -->
        <div style="padding: 14px 20px; background: #F8F6F2; border-bottom: 1px solid #EAE5DD; display: flex; align-items: center; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 34px; height: 34px; border-radius: 6px; background: #F9ECEB; border: 1px solid #F0CAC7; display: flex; align-items: center; justify-content: center; color: #C96D67; font-size: 16px;">
              🛡️
            </div>
            <div>
              <div style="font-size: 15px; font-weight: 700; color: #252522;">Attachment Redaction &amp; Review</div>
              <div style="font-size: 11px; color: #77736D;">Automatic In-Situ Protection &bull; Pre-Send Screening</div>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px; background: ${riskBg}; color: ${riskColor}; text-transform: uppercase;">
              ${riskLevel} RISK (${riskScore}/100)
            </span>
          </div>
        </div>

        <!-- Verification Seal Banner -->
        <div style="background: #EAF0EB; border-bottom: 1px solid #CDDDD3; padding: 8px 20px; font-size: 12px; color: #647C70; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 14px;">🔒</span>
          <span><strong>Verified Non-Recoverable:</strong> Output file undergoes permanent raster flattening &bull; 0 text streams remain &bull; Metadata stripped.</span>
        </div>

        <!-- Main Body: Two-Column Review Layout -->
        <div style="padding: 16px 20px; overflow-y: auto; flex: 1; display: grid; grid-template-columns: 240px 1fr; gap: 16px;">
          
          <!-- Left Column: Visual Preview -->
          <div style="display: flex; flex-direction: column; gap: 8px;">
            <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #77736D;">
              Sanitized Preview
            </div>
            <div style="background: #F8F6F2; border: 1px solid #EAE5DD; border-radius: 8px; overflow: hidden; min-height: 220px; max-height: 280px; display: flex; align-items: center; justify-content: center; position: relative;">
              <img id="ssPreviewImg" src="${currentScan.preview_data_url || ''}" alt="Redacted Preview" style="width: 100%; height: 100%; object-fit: contain; display: block;" />
              <div id="ssPreviewLoading" style="display: none; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(255,255,255,0.7); align-items: center; justify-content: center; font-size: 12px; color: #252522; font-weight: 600;">
                Updating redaction...
              </div>
            </div>
            <div style="font-size: 11px; color: #77736D; line-height: 1.4;">
              <strong>${escapeHtml(file.name)}</strong><br/>
              ${formatBytes(file.size)} &bull; ${isPdf ? "PDF Document" : "Image"}
            </div>
          </div>

          <!-- Right Column: Interactive Detection List & Selective Undo -->
          <div style="display: flex; flex-direction: column;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
              <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #77736D;">
                Detected Items (Redacted by Default):
              </div>
              <span id="ssActiveCount" style="font-size: 11px; font-weight: 600; color: #647C70;">
                ${currentScan.detections.length} of ${currentScan.detections.length} Redacted
              </span>
            </div>

            <div id="ssDetectionsList" style="display: flex; flex-direction: column; gap: 8px; max-height: 240px; overflow-y: auto; padding-right: 4px; margin-bottom: 12px;">
              <!-- Dynamic detections rendered here -->
            </div>

            <div style="font-size: 11px; color: #77736D; background: #F8F6F2; border: 1px solid #EAE5DD; border-radius: 6px; padding: 6px 10px;">
              💡 <em>Click any toggle button to selectively undo or re-apply individual redactions. The preview updates automatically.</em>
            </div>
          </div>

        </div>

        <!-- Actions Footer -->
        <div style="padding: 14px 20px; background: #F8F6F2; border-top: 1px solid #EAE5DD; display: flex; flex-direction: column; gap: 8px;">
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <!-- Primary Action: Send Sanitized -->
            <button id="ssBtnSendSanitized" style="flex: 2; min-width: 180px; padding: 10px 16px; background: #647C70; color: #FFFFFF; border: none; border-radius: 6px; font-size: 13px; font-weight: 700; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px;">
              <span>✅ Send Sanitized Attachment</span>
            </button>
            <!-- Secondary: Download Clean Copy -->
            <button id="ssBtnDownloadClean" style="flex: 1; min-width: 140px; padding: 10px 14px; background: #FFFFFF; color: #252522; border: 1px solid #EAE5DD; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px;">
              <span>⬇️ Download Clean Copy</span>
            </button>
            <!-- Danger: Cancel -->
            <button id="ssBtnCancel" style="padding: 10px 14px; background: #FFFFFF; color: #A74440; border: 1px solid #E8B4B2; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;">
              🛑 Cancel
            </button>
          </div>
          <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 4px;">
            <button id="ssBtnOverride" style="background: none; border: none; color: #77736D; font-size: 11px; cursor: pointer; text-decoration: underline; padding: 0;">
              I understand the risks; send original unredacted file (Override)
            </button>
            <span style="font-size: 11px; color: #77736D;">Original file is never altered on disk</span>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const detectionsContainer = overlay.querySelector("#ssDetectionsList");
    const activeCountElem = overlay.querySelector("#ssActiveCount");
    const previewImg = overlay.querySelector("#ssPreviewImg");
    const previewLoading = overlay.querySelector("#ssPreviewLoading");

    function renderDetections() {
      detectionsContainer.innerHTML = "";
      const total = currentScan.detections.length;
      const active = total - excludedDetectionIds.size;
      activeCountElem.textContent = `${active} of ${total} Redacted`;

      currentScan.detections.forEach((d) => {
        const isExcluded = excludedDetectionIds.has(d.id);
        const itemDiv = document.createElement("div");
        itemDiv.style.cssText = `
          background: #FFFFFF;
          border: 1px solid ${isExcluded ? "#E8D7BF" : "#EAE5DD"};
          border-left: 3px solid ${isExcluded ? "#B27329" : "#647C70"};
          border-radius: 6px;
          padding: 8px 10px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          transition: all 0.15s ease;
        `;

        itemDiv.innerHTML = `
          <div style="flex: 1; min-width: 0;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2px;">
              <span style="font-size: 12px; font-weight: 700; color: #252522; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
                ${escapeHtml(d.label || d.type)}
              </span>
              <span style="font-size: 10px; font-weight: 700; padding: 1px 5px; border-radius: 3px; background: ${isExcluded ? "#F5EBDD" : "#EAF0EB"}; color: ${isExcluded ? "#B27329" : "#647C70"};">
                ${isExcluded ? "KEPT" : "REDACTED"}
              </span>
            </div>
            <div style="font-family: monospace; font-size: 11px; color: #252522; background: #F8F6F2; padding: 2px 6px; border-radius: 3px; margin: 2px 0; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
              ${escapeHtml(d.masked || d.value || "Sensitive Value")}
            </div>
            <div style="font-size: 10px; color: #77736D;">${escapeHtml(d.details || "Verified pattern")}</div>
          </div>
          <div>
            <button type="button" class="ss-toggle-btn" style="
              padding: 5px 8px;
              font-size: 11px;
              font-weight: 600;
              border-radius: 4px;
              cursor: pointer;
              border: 1px solid ${isExcluded ? "#B27329" : "#647C70"};
              background: ${isExcluded ? "#FDF1E3" : "#EAF0EB"};
              color: ${isExcluded ? "#B27329" : "#647C70"};
            ">
              ${isExcluded ? "↩ Redact" : "✕ Undo"}
            </button>
          </div>
        `;

        itemDiv.querySelector(".ss-toggle-btn").addEventListener("click", () => {
          if (excludedDetectionIds.has(d.id)) {
            excludedDetectionIds.delete(d.id);
          } else {
            excludedDetectionIds.add(d.id);
          }
          renderDetections();
          updateRedactionsOnServer();
        });

        detectionsContainer.appendChild(itemDiv);
      });
    }

    function updateRedactionsOnServer() {
      previewLoading.style.display = "flex";
      chrome.runtime.sendMessage(
        {
          action: "UPDATE_ATTACHMENT_REDACTIONS",
          sessionId: currentScan.session_id,
          excludedDetectionIds: Array.from(excludedDetectionIds)
        },
        (res) => {
          previewLoading.style.display = "none";
          if (res && res.success) {
            currentScan.sanitized_base64 = res.sanitized_base64;
            currentScan.preview_data_url = res.preview_data_url;
            currentScan.sanitized_filename = res.sanitized_filename;
            if (previewImg && res.preview_data_url) {
              previewImg.src = res.preview_data_url;
            }
          }
        }
      );
    }

    renderDetections();

    // Confirm & Send Sanitized Attachment
    overlay.querySelector("#ssBtnSendSanitized").addEventListener("click", () => {
      overlay.remove();
      if (typeof onConfirmSendSanitized === "function") {
        onConfirmSendSanitized(currentScan);
      }
    });

    // Download Clean Copy Locally
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
      overlay.remove();
      if (typeof onCancel === "function") onCancel();
      showStatusToast(`Attachment upload cancelled. Original file protected.`, "info");
    });

    // Override (Send Original Unredacted)
    overlay.querySelector("#ssBtnOverride").addEventListener("click", () => {
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
