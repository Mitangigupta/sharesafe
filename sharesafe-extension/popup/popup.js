/**
 * ShareSafe Chrome Extension — Popup Logic (Phase 2 Integrated)
 * Coordinates tab switching, scan state rendering, context changes, 
 * in-situ Gmail/WhatsApp draft scanning, and clipboard/replacement operations.
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

  // Phase 2 Elements
  const platformBanner = document.getElementById("platformBanner");
  const platformPill = document.getElementById("platformPill");
  const platformDesc = document.getElementById("platformDesc");
  const btnPlatformScan = document.getElementById("btnPlatformScan");
  const btnReplaceDraft = document.getElementById("btnReplaceDraft");
  const replaceBtnText = document.getElementById("replaceBtnText");

  const assistantPanel = document.getElementById("assistantPanel");
  const manualInput = document.getElementById("manualInput");
  const btnRunManualScan = document.getElementById("btnRunManualScan");
  const btnClearManual = document.getElementById("btnClearManual");
  const btnClearAll = document.getElementById("btnClearAll");

  let currentScanRecord = null;
  let activePlatformTab = null;

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
  function renderScan(scanRecord) {
    if (!scanRecord || !scanRecord.data) return;
    currentScanRecord = scanRecord;

    const data = scanRecord.data;
    const detections = data.detections || [];
    const risk = data.risk_summary || {};
    const assistant = data.assistant || {};
    const masked = data.masked_text || "";

    // Update Risk Badge & Summary
    const riskLevel = risk.level || "CLEAN";
    riskBadge.textContent = `${riskLevel} RISK`;
    riskBadge.className = `risk-pill pill-${riskLevel.toLowerCase()}`;
    riskScore.textContent = `Score: ${risk.score || 0}/100`;
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

    // If on a supported platform (Gmail/WhatsApp), trigger in-page pre-send warning badge
    if (activePlatformTab && detections.length > 0) {
      chrome.tabs.sendMessage(activePlatformTab.tabId, {
        action: "SHOW_PRE_SEND_WARNING",
        findingsCount: detections.length,
        riskLevel: riskLevel
      }).catch(() => {});
    }
  }

  function getCleanGuidance(r) {
    const type = (r.type || "").toLowerCase();
    const isHigh = r.priority === "HIGH_PRIORITY" || r.action === "REDACT";

    let priorityLabel = isHigh ? "High Priority" : "Review Recommended";
    let priClass = isHigh ? "pri-high" : "pri-review";
    let badgeClass = isHigh ? "badge-pri-high" : "badge-pri-review";
    let confidenceLabel = r.confidence === "high" ? "Confirmed" : "Unverified";

    let why = "";
    let risk = "";

    if (type.includes("aadhaar")) {
      why = "Aadhaar numbers are government-issued identity credentials under the DPDP Act 2023.";
      risk = "Sharing in cleartext risks unauthorized KYC verification or identity theft.";
    } else if (type.includes("pan")) {
      why = "PAN cards are statutory tax identifiers linked to banking and tax records.";
      risk = "Exposing PANs enables fraudulent financial filings and credit profiling.";
    } else if (type.includes("card") || type.includes("credit") || type.includes("debit")) {
      why = "Payment card numbers fall strictly under PCI-DSS standards.";
      risk = "Cleartext transmission enables unauthorized billing and card-not-present fraud.";
    } else if (type.includes("phone")) {
      why = "Direct mobile contact identifier linked to communication services.";
      risk = "Leaking phone numbers causes targeted phishing, spam, and social engineering.";
    } else if (type.includes("email")) {
      why = "Primary electronic communication endpoint and account recovery identifier.";
      risk = "Exposure increases credential stuffing attacks and unsolicited contact.";
    } else if (type.includes("secret") || type.includes("key") || type.includes("jwt") || type.includes("token")) {
      why = "Cryptographic infrastructure credential or API authentication secret.";
      risk = "Leaking secret keys compromises backend systems and cloud resources immediately.";
    } else {
      why = r.recommendation || "Sensitive personal or configuration entity detected.";
      risk = "Unrestricted disclosure risks privacy and security non-compliance.";
    }

    return {
      title: r.recommendation || `${r.type} Detected`,
      priorityLabel,
      confidenceLabel,
      priClass,
      badgeClass,
      why,
      risk
    };
  }

  function renderAssistant(assistant) {
    const recs = assistant.recommendations || [];
    if (recs.length === 0) {
      assistantPanel.innerHTML = `
        <div class="empty-state">
          <p class="empty-title">Privacy Assistant: Clear</p>
          <p class="empty-desc">No high-risk concerns identified for the current sharing context.</p>
        </div>
      `;
      return;
    }

    assistantPanel.innerHTML = `
      <div class="asst-container">
        <div class="asst-intro">
          Actionable privacy guidance evaluated for <strong>${escapeHtml(contextSelect.value)}</strong> mode:
        </div>
        ${recs
          .map((r) => {
            const g = getCleanGuidance(r);
            return `
              <div class="asst-card ${g.priClass}">
                <div class="asst-header">
                  <span class="asst-badge ${g.badgeClass}">${g.priorityLabel}</span>
                  <span class="asst-confidence">${g.confidenceLabel}</span>
                </div>
                <div class="asst-title">${escapeHtml(g.title)}</div>
                <div class="asst-body">
                  <div class="asst-section">
                    <span class="asst-label">Why:</span>
                    <span class="asst-text">${escapeHtml(g.why)}</span>
                  </div>
                  <div class="asst-section">
                    <span class="asst-label">Risk:</span>
                    <span class="asst-text">${escapeHtml(g.risk)}</span>
                  </div>
                </div>
              </div>
            `;
          })
          .join("")}
      </div>
    `;
  }

  function renderError(errMessage) {
    riskBadge.textContent = "OFFLINE";
    riskBadge.className = "risk-pill pill-neutral";
    riskScore.textContent = "Score: --";
    findingsCount.textContent = "Server Offline";
    riskMessage.innerHTML = `
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
          document.querySelector('[data-tab="tab-findings"]').click();
        } else {
          renderError(res?.error || "Failed to communicate with background worker.");
        }
      }
    );
  }

  // 6. Platform Detection (Phase 2)
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs.length) return;
    const tab = tabs[0];
    const url = tab.url || "";

    if (url.includes("mail.google.com")) {
      activePlatformTab = { tabId: tab.id, platform: "Gmail" };
      platformPill.textContent = "Gmail";
      platformDesc.textContent = "Active Gmail compose session";
      platformBanner.style.display = "flex";
      btnReplaceDraft.style.display = "inline-flex";
    } else if (url.includes("web.whatsapp.com")) {
      activePlatformTab = { tabId: tab.id, platform: "WhatsApp Web" };
      platformPill.textContent = "WhatsApp";
      platformDesc.textContent = "Active message compose box";
      platformBanner.style.display = "flex";
      btnReplaceDraft.style.display = "inline-flex";
    }
  });

  if (btnPlatformScan) {
    btnPlatformScan.addEventListener("click", () => {
      if (!activePlatformTab) return;
      btnPlatformScan.disabled = true;
      const originalLabel = btnPlatformScan.innerHTML;
      btnPlatformScan.innerHTML = "<span>Reading draft...</span>";

      chrome.tabs.sendMessage(activePlatformTab.tabId, { action: "GET_DRAFT_TEXT" }, (response) => {
        btnPlatformScan.disabled = false;
        btnPlatformScan.innerHTML = originalLabel;

        if (response && response.found && response.text) {
          manualInput.value = response.text;
          triggerScan(response.text, contextSelect.value);
        } else {
          alert(response?.error || `No active text found in ${activePlatformTab.platform} compose area. Please type or click into the message box first.`);
        }
      });
    });
  }

  if (btnReplaceDraft) {
    btnReplaceDraft.addEventListener("click", () => {
      if (!activePlatformTab || !sanitizedText.value) return;
      chrome.tabs.sendMessage(
        activePlatformTab.tabId,
        { action: "REPLACE_DRAFT_TEXT", sanitizedText: sanitizedText.value },
        (res) => {
          if (res && res.success) {
            btnReplaceDraft.classList.add("replaced");
            replaceBtnText.textContent = "Replaced in Draft!";
            setTimeout(() => {
              btnReplaceDraft.classList.remove("replaced");
              replaceBtnText.textContent = "Replace in Draft";
            }, 2500);
          } else {
            alert(res?.error || "Could not replace text in active compose box.");
          }
        }
      );
    });
  }

  // 7. Action Listeners
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

  // 8. Initial Load: Check session storage for existing scan
  chrome.storage.session.get(["sharesafe_last_scan"], (res) => {
    if (res && res.sharesafe_last_scan) {
      renderScan(res.sharesafe_last_scan);
    } else {
      // Check if user has active text selection on the current webpage tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].id) {
          chrome.tabs.sendMessage(tabs[0].id, { action: "GET_SELECTION" }, (res) => {
            if (chrome.runtime.lastError) return;
            const selectedText = res && res.text ? res.text.trim() : "";
            if (selectedText && selectedText.length > 2) {
              manualInput.value = selectedText;
              triggerScan(selectedText, contextSelect.value);
            }
          });
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
