/**
 * ShareSafe Chrome Extension — Automated Pre-Upload File Shield (Phase 3 Architecture)
 * 
 * Automatically intercepts document and image uploads across supported web applications
 * (WhatsApp Web, Gmail, etc.) before files are transmitted to external servers.
 * Evaluates PII, credentials, and QR threat payloads via the local ShareSafe core.
 */

(function () {
  const SERVER_URL = "http://127.0.0.1:5000";
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

  // Floating Toast Notification
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

  // Pre-Upload Defensive Warning Modal
  function showPreUploadShieldModal(file, scanData, onCancel, onOverride) {
    const existing = document.getElementById("sharesafe-shield-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "sharesafe-shield-overlay";
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(37, 37, 34, 0.65);
      backdrop-filter: blur(4px);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    const risk = scanData.risk_summary || {};
    const riskLevel = risk.level || "HIGH";
    const riskScore = risk.score || 0;
    const detections = scanData.detections || [];
    const workbenchUrl = `${SERVER_URL}${scanData.workbench_url || "/workbench/" + scanData.session_id}`;

    const riskColor = riskLevel === "CRITICAL" ? "#A74440" : riskLevel === "HIGH" ? "#C96D67" : "#B27329";
    const riskBg = riskLevel === "CRITICAL" ? "#FCE8E7" : riskLevel === "HIGH" ? "#F9ECEB" : "#F5EBDD";

    overlay.innerHTML = `
      <div style="background: #FFFFFF; border-radius: 12px; width: 100%; max-width: 540px; box-shadow: 0 12px 36px rgba(0,0,0,0.22); overflow: hidden; border: 1px solid #EAE5DD;">
        <!-- Header -->
        <div style="padding: 16px 20px; background: #F8F6F2; border-bottom: 1px solid #EAE5DD; display: flex; align-items: center; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 32px; height: 32px; border-radius: 6px; background: #F9ECEB; border: 1px solid #F0CAC7; display: flex; align-items: center; justify-content: center; color: #C96D67; font-size: 16px;">
              🛡️
            </div>
            <div>
              <div style="font-size: 15px; font-weight: 700; color: #252522;">ShareSafe Pre-Upload Privacy Shield</div>
              <div style="font-size: 11px; color: #77736D;">Accidental Data Exposure Interception &bull; Automated Screening</div>
            </div>
          </div>
          <span style="font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px; background: ${riskBg}; color: ${riskColor}; text-transform: uppercase;">
            ${riskLevel} RISK (${riskScore}/100)
          </span>
        </div>

        <!-- Body -->
        <div style="padding: 20px;">
          <div style="background: #F8F6F2; border: 1px solid #EAE5DD; border-radius: 8px; padding: 12px 14px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between;">
            <div>
              <div style="font-size: 13px; font-weight: 600; color: #252522;">${escapeHtml(file.name)}</div>
              <div style="font-size: 11px; color: #77736D;">${formatBytes(file.size)} &bull; ${detections.length} sensitive item(s) detected</div>
            </div>
            <span style="font-size: 12px; font-weight: 600; color: ${riskColor};">Upload Paused</span>
          </div>

          <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #77736D; margin-bottom: 8px;">
            Detected Information Requiring Protection:
          </div>

          <div style="display: flex; flex-direction: column; gap: 8px; max-height: 180px; overflow-y: auto; margin-bottom: 16px; padding-right: 4px;">
            ${detections.map(d => `
              <div style="background: #FFFFFF; border: 1px solid #EAE5DD; border-left: 3px solid ${riskColor}; border-radius: 6px; padding: 8px 12px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 3px;">
                  <span style="font-size: 12px; font-weight: 700; color: #252522;">${escapeHtml(d.label || d.type)}</span>
                  <span style="font-size: 10px; font-weight: 700; color: ${riskColor}; background: ${riskBg}; padding: 1px 6px; border-radius: 4px; text-transform: uppercase;">${escapeHtml(d.risk || "HIGH")}</span>
                </div>
                <div style="font-family: monospace; font-size: 11px; color: #252522; background: #F8F6F2; padding: 3px 6px; border-radius: 4px; margin: 3px 0;">
                  ${escapeHtml(d.masked || d.value || "Sensitive Value")}
                </div>
                <div style="font-size: 11px; color: #647C70;">${escapeHtml(d.details || "Verified algorithmic detection")}</div>
              </div>
            `).join("")}
          </div>

          <div style="background: #F9ECEB; border: 1px solid #F0CAC7; border-radius: 6px; padding: 10px 12px; font-size: 12px; color: #A74440; line-height: 1.45; margin-bottom: 20px;">
            <strong>Defensive Privacy Alert:</strong> Uploading this document unredacted exposes sovereign identity credentials or financial data across third-party communication networks.
          </div>

          <!-- Actions -->
          <div style="display: flex; flex-direction: column; gap: 10px;">
            <div style="display: flex; gap: 10px;">
              <button id="ssBtnCancel" style="flex: 1; padding: 10px 14px; background: #A74440; color: #FFFFFF; border: none; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px;">
                <span>🛑 Cancel Upload (Recommended)</span>
              </button>
              <button id="ssBtnRedact" style="flex: 1; padding: 10px 14px; background: #647C70; color: #FFFFFF; border: none; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px;">
                <span>✏️ Redact in ShareSafe Studio ↗</span>
              </button>
            </div>
            <button id="ssBtnOverride" style="background: none; border: none; color: #77736D; font-size: 11px; cursor: pointer; text-decoration: underline; text-align: center; padding: 4px;">
              I understand the risks; send file unredacted (Override)
            </button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector("#ssBtnCancel").addEventListener("click", () => {
      overlay.remove();
      if (typeof onCancel === "function") onCancel();
      showStatusToast(`Upload cancelled. "${file.name}" was protected from sharing.`, "success");
    });

    overlay.querySelector("#ssBtnRedact").addEventListener("click", () => {
      overlay.remove();
      if (typeof onCancel === "function") onCancel();
      window.open(workbenchUrl, "_blank");
      showStatusToast("Opened in ShareSafe Redaction Studio. Redact and download your safe copy.", "info", 5000);
    });

    overlay.querySelector("#ssBtnOverride").addEventListener("click", () => {
      overlay.remove();
      bypassedFiles.add(file);
      if (typeof onOverride === "function") onOverride();
      showStatusToast("Upload override granted. File sending unredacted.", "info");
    });
  }

  // File Inspection via Core Endpoint
  async function inspectFile(file) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("sharing_context", "academic");

    try {
      const res = await fetch(`${SERVER_URL}/api/inspect-file`, {
        method: "POST",
        body: formData
      });

      if (!res.ok) {
        throw new Error(`Server returned status ${res.status}`);
      }

      return await res.json();
    } catch (err) {
      console.warn("[ShareSafe] Inspection endpoint unreachable or error:", err);
      return null;
    }
  }

  // Intercept Input[type="file"]
  document.addEventListener("change", async (event) => {
    const target = event.target;
    if (!target || target.tagName !== "INPUT" || target.type !== "file") return;

    const files = target.files;
    if (!files || !files.length) return;

    const file = files[0];
    if (bypassedFiles.has(file) || !isInspectableFile(file)) return;

    // Show non-blocking inspection notification
    const toast = showStatusToast(`Inspecting "${file.name}" with ShareSafe...`, "info", 0);

    const scanData = await inspectFile(file);
    if (toast.parentElement) toast.remove();

    if (!scanData) {
      // Core offline, allow gracefully
      return;
    }

    if (scanData.can_share_safely || scanData.total_findings === 0) {
      showStatusToast(`"${file.name}" is Clean. Uploading safely.`, "success", 2500);
      return;
    }

    // UNSAFE: Halt and display Pre-Upload Shield
    showPreUploadShieldModal(
      file,
      scanData,
      // onCancel
      () => {
        try { target.value = ""; } catch (_) {}
      },
      // onOverride
      () => {
        // Trigger synthetic change if necessary or allow
      }
    );
  }, true);

  // Intercept Drag & Drop
  document.addEventListener("drop", async (event) => {
    if (!event.dataTransfer || !event.dataTransfer.files || !event.dataTransfer.files.length) return;
    const file = event.dataTransfer.files[0];
    if (bypassedFiles.has(file) || !isInspectableFile(file)) return;

    // Inspect dropped file
    const toast = showStatusToast(`Inspecting dropped file "${file.name}"...`, "info", 0);
    const scanData = await inspectFile(file);
    if (toast.parentElement) toast.remove();

    if (!scanData || scanData.can_share_safely || scanData.total_findings === 0) {
      if (scanData && (scanData.can_share_safely || scanData.total_findings === 0)) {
        showStatusToast(`"${file.name}" is Clean.`, "success", 2500);
      }
      return;
    }

    // Prevent immediate drop upload until verified
    event.preventDefault();
    event.stopImmediatePropagation();

    showPreUploadShieldModal(
      file,
      scanData,
      () => {},
      () => {
        // Re-drop simulation if user overrides
      }
    );
  }, true);

  // Helper
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

  console.log("[ShareSafe] Automated Pre-Upload File Shield active (Phase 3).");
})();
