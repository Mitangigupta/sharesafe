/**
 * ShareSafe Chrome Extension — Popup Logic
 * Coordinates tab switching, scan state rendering, context changes, and clipboard operations.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const serverStatus = document.getElementById("serverStatus");
  const statusLabel = document.getElementById("statusLabel");
  const statusDot = serverStatus.querySelector(".status-dot");
  const contextSelect = document.getElementById("contextSelect");

  const riskBadge = document.getElementById("riskBadge");
  const riskScore = document.getElementById("riskScore");
  const findingsCount = document.getElementById("findingsCount");
  const riskMessage = document.getElementById("riskMessage");

  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanels = document.querySelectorAll(".tab-panel");
  const tabBadgeFindings = document.getElementById("tabBadgeFindings");

  const findingsList = document.getElementById("findingsList");
  const sanitizedText = document.getElementById("sanitizedText");
  const btnCopySanitized = document.getElementById("btnCopySanitized");
  const copyBtnText = document.getElementById("copyBtnText");

  const assistantPanel = document.getElementById("assistantPanel");
  const manualInput = document.getElementById("manualInput");
  const btnRunManualScan = document.getElementById("btnRunManualScan");
  const btnClearManual = document.getElementById("btnClearManual");
  const btnClearAll = document.getElementById("btnClearAll");

  let currentScanRecord = null;

  // 1. Check Server Connection
  function checkServer() {
    chrome.runtime.sendMessage({ action: "CHECK_HEALTH" }, (response) => {
      if (response && response.success) {
        statusDot.className = "status-dot online";
        statusLabel.textContent = "Online (:5000)";
        serverStatus.title = `Connected to ShareSafe Engine v${response.data.version || "1.0"}`;
      } else {
        statusDot.className = "status-dot offline";
        statusLabel.textContent = "Offline";
        serverStatus.title = "ShareSafe Flask server is not responding at http://127.0.0.1:5000";
      }
    });
  }

  // 2. Load Saved Settings (Sharing Context)
  chrome.storage.sync.get(["sharingContext"], (items) => {
    if (items.sharingContext) {
      contextSelect.value = items.sharingContext;
    }
  });

  contextSelect.addEventListener("change", () => {
    const newContext = contextSelect.value;
    chrome.storage.sync.set({ sharingContext: newContext });

    // If we have an active scan, re-scan with the updated context
    if (currentScanRecord && currentScanRecord.sourceText) {
      triggerScan(currentScanRecord.sourceText, newContext);
    }
  });

  // 3. Tab Switching
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      tabButtons.forEach((b) => b.classList.remove("active"));
      tabPanels.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPanel = document.getElementById(targetTab);
      if (targetPanel) targetPanel.classList.add("active");
    });
  });

  // 4. Render Scan Results
  function renderScan(record) {
    currentScanRecord = record;

    if (!record || record.error) {
      renderError(record ? record.error : "No scan data available");
      return;
    }

    const scanData = record.data || {};
    const risk = scanData.risk_summary || {};
    const detections = scanData.detections || [];
    const assistant = scanData.assistant || {};
    const masked = scanData.masked_text || record.sourceText || "";

    // Update Risk Card
    const level = (risk.level || "CLEAN").toUpperCase();
    riskBadge.textContent = level;
    riskBadge.className = `risk-pill pill-${level.toLowerCase()}`;
    riskScore.textContent = `Score: ${risk.score !== undefined ? risk.score : 0}`;
    findingsCount.textContent = `${detections.length} Finding${detections.length === 1 ? "" : "s"}`;
    tabBadgeFindings.textContent = String(detections.length);

    if (detections.length === 0) {
      riskMessage.textContent = risk.recommendation || "No sensitive information detected. The text appears clear for sharing.";
    } else {
      riskMessage.textContent = risk.recommendation || "Review the detected sensitive items before sharing.";
    }

    // Render Findings List
    if (detections.length === 0) {
      findingsList.innerHTML = `
        <div class="empty-state">
          <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
          <p class="empty-title">All clear — 0 sensitive items detected</p>
          <p class="empty-desc">No PII, payment credentials, or secrets were identified in the scanned text.</p>
        </div>
      `;
    } else {
      findingsList.innerHTML = "";
      detections.forEach((d) => {
        const item = document.createElement("div");
        const itemRisk = (d.risk || "LOW").toLowerCase();
        item.className = `finding-item risk-${itemRisk}`;

        item.innerHTML = `
          <div class="finding-header">
            <span class="finding-label">${escapeHtml(d.label || d.type)}</span>
            <div class="finding-meta">
              <span class="finding-category">${escapeHtml(d.category || "General")}</span>
              <span class="risk-pill pill-${itemRisk}">${escapeHtml(d.risk || "LOW")}</span>
            </div>
          </div>
          <div class="finding-masked" title="Masked representation">${escapeHtml(d.masked || d.value)}</div>
          <div class="finding-details">${escapeHtml(d.details || "")}</div>
        `;
        findingsList.appendChild(item);
      });
    }

    // Populate Sanitized Text Panel
    sanitizedText.value = masked;

    // Populate Privacy Assistant Panel
    renderAssistant(assistant);
  }

  function renderAssistant(assistant) {
    if (!assistant || (!assistant.summary && (!assistant.recommendations || assistant.recommendations.length === 0))) {
      assistantPanel.innerHTML = `
        <div class="empty-state">
          <p class="empty-desc">No specific assistant recommendations for this text.</p>
        </div>
      `;
      return;
    }

    const summaryText = typeof assistant.summary === 'string'
      ? assistant.summary
      : (assistant.summary?.overview || assistant.summary?.headline || "");
    const recs = assistant.recommendations || [];

    let html = "";
    if (summaryText) {
      html += `
        <div class="asst-summary-card">
          <div class="asst-headline">Executive Privacy Assessment</div>
          <div class="asst-overview">${escapeHtml(summaryText)}</div>
        </div>
      `;
    }

    if (recs.length > 0) {
      recs.forEach((r) => {
        const prioClass = (r.priority || "INFORMATIONAL").toLowerCase().replace("_", "-");
        const actionTag = escapeHtml(r.action_label || r.action || "Guidance");
        const itemLabel = escapeHtml(r.label || "Detected Item");
        const explanation = escapeHtml(r.explanation || "");
        const riskDesc = escapeHtml(r.risk_description || "");
        const advice = escapeHtml(r.recommendation || "");

        html += `
          <div class="rec-item priority-${prioClass}">
            <div class="rec-header">
              <span class="rec-title">${itemLabel}</span>
              <span class="rec-action-badge badge-${prioClass}">${actionTag}</span>
            </div>
            ${explanation ? `<div class="rec-desc"><span class="rec-field-label">Found:</span> ${explanation}</div>` : ""}
            ${riskDesc ? `<div class="rec-desc"><span class="rec-field-label">Risk:</span> ${riskDesc}</div>` : ""}
            ${advice ? `<div class="rec-advice"><span class="rec-field-label">Guidance:</span> ${advice}</div>` : ""}
          </div>
        `;
      });
    }

    assistantPanel.innerHTML = html;
  }

  function renderError(errMessage) {
    riskBadge.textContent = "ERROR";
    riskBadge.className = "risk-pill pill-critical";
    riskScore.textContent = "Offline";
    findingsCount.textContent = "0 Findings";
    riskMessage.innerHTML = `
      <span style="color: var(--red-finding); font-weight: 600;">Scan Failed:</span>
      ${escapeHtml(errMessage)}. Make sure the ShareSafe server is running at <code>http://127.0.0.1:5000</code>.
    `;
    findingsList.innerHTML = `
      <div class="empty-state">
        <p class="empty-title">Cannot reach ShareSafe server</p>
        <p class="empty-desc">Start your local server with <code>python app.py</code> or <code>run.bat</code>.</p>
      </div>
    `;
    sanitizedText.value = "";
    assistantPanel.innerHTML = "";
  }

  // 5. Trigger Scan
  function triggerScan(text, context) {
    if (!text || !text.trim()) return;

    btnRunManualScan.disabled = true;
    btnRunManualScan.textContent = "Scanning...";
    riskMessage.textContent = "Analyzing sensitive patterns and validating checksums...";

    chrome.runtime.sendMessage(
      {
        action: "SCAN_TEXT",
        text: text,
        sharingContext: context || contextSelect.value
      },
      (res) => {
        btnRunManualScan.disabled = false;
        btnRunManualScan.textContent = "Scan with ShareSafe";

        if (res && res.success) {
          renderScan(res.record);
          // Switch to findings tab
          document.querySelector('[data-tab="tab-findings"]').click();
        } else {
          renderError(res?.error || "Failed to communicate with background worker.");
        }
      }
    );
  }

  // 6. Action Listeners
  btnRunManualScan.addEventListener("click", () => {
    const text = manualInput.value.trim();
    if (text) {
      triggerScan(text, contextSelect.value);
    }
  });

  btnClearManual.addEventListener("click", () => {
    manualInput.value = "";
  });

  btnCopySanitized.addEventListener("click", async () => {
    const textToCopy = sanitizedText.value;
    if (!textToCopy) return;

    try {
      await navigator.clipboard.writeText(textToCopy);
      btnCopySanitized.classList.add("copied");
      copyBtnText.textContent = "Copied!";
      setTimeout(() => {
        btnCopySanitized.classList.remove("copied");
        copyBtnText.textContent = "Copy Text";
      }, 2000);
    } catch (e) {
      console.error("Clipboard copy failed:", e);
    }
  });

  btnClearAll.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "CLEAR_SCAN" }, () => {
      currentScanRecord = null;
      riskBadge.textContent = "RESET";
      riskBadge.className = "risk-pill pill-neutral";
      riskScore.textContent = "Score: --";
      findingsCount.textContent = "0 Findings";
      tabBadgeFindings.textContent = "0";
      riskMessage.textContent = "Scan reset. Select text on a page to scan.";
      sanitizedText.value = "";
      manualInput.value = "";
      findingsList.innerHTML = `
        <div class="empty-state">
          <p class="empty-title">No scanned findings</p>
          <p class="empty-desc">Right-click selected text on a webpage or paste text in Quick Input.</p>
        </div>
      `;
      assistantPanel.innerHTML = `
        <div class="empty-state">
          <p class="empty-desc">Run a scan to generate context-aware privacy recommendations.</p>
        </div>
      `;
    });
  });

  // 7. Initial Load: Check session storage for existing scan
  chrome.storage.session.get(["sharesafe_last_scan"], (res) => {
    if (res && res.sharesafe_last_scan) {
      renderScan(res.sharesafe_last_scan);
    } else {
      // Check if user has active text selection on the current webpage tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].id) {
          chrome.scripting.executeScript(
            {
              target: { tabId: tabs[0].id },
              func: () => window.getSelection().toString()
            },
            (results) => {
              if (chrome.runtime.lastError) {
                // Cannot access chrome:// or restricted page; harmless
                return;
              }
              const selectedText = results && results[0] && results[0].result ? results[0].result.trim() : "";
              if (selectedText && selectedText.length > 2) {
                manualInput.value = selectedText;
                triggerScan(selectedText, contextSelect.value);
              }
            }
          ).catch(() => {});
        }
      });
    }
  });

  checkServer();

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
