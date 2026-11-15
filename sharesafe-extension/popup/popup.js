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
        statusLabel.textContent = "Offline Mode";
        serverStatus.title = "ShareSafe local server is offline; client-side privacy scanner is active.";
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

  // 9. Popup Attachment Shield & Auto-Redaction (Prioritized Attachment Workflow)
  const popupFileInput = document.getElementById("popupFileInput");
  const btnPopupChooseFile = document.getElementById("btnPopupChooseFile");
  const popupDropzone = document.getElementById("popupDropzone");
  const dropzonePrompt = document.getElementById("dropzonePrompt");
  const attachmentResultCard = document.getElementById("attachmentResultCard");
  const resultFileName = document.getElementById("resultFileName");
  const resultMeta = document.getElementById("resultMeta");
  const resultRiskBadge = document.getElementById("resultRiskBadge");
  const resultPreviewImg = document.getElementById("resultPreviewImg");
  const resultItemsList = document.getElementById("resultItemsList");
  const btnDownloadPopupSanitized = document.getElementById("btnDownloadPopupSanitized");
  const btnClearPopupAttachment = document.getElementById("btnClearPopupAttachment");

  let activeAttachmentScan = null;
  const popupExcludedDetectionIds = new Set();

  if (btnPopupChooseFile && popupFileInput) {
    btnPopupChooseFile.addEventListener("click", () => {
      popupFileInput.click();
    });
  }

  if (popupDropzone && popupFileInput) {
    popupDropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      popupDropzone.style.background = "var(--coral-soft)";
    });

    popupDropzone.addEventListener("dragleave", () => {
      popupDropzone.style.background = "";
    });

    popupDropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      popupDropzone.style.background = "";
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        handlePopupAttachment(e.dataTransfer.files[0]);
      }
    });

    popupFileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files.length) {
        handlePopupAttachment(e.target.files[0]);
      }
    });
  }

  function handlePopupAttachment(file) {
    if (!file) return;

    dropzonePrompt.innerHTML = `
      <div class="dropzone-icon">⏳</div>
      <div class="dropzone-text">Scanning & auto-redacting "${escapeHtml(file.name)}"...</div>
      <div class="dropzone-sub">Extracting text & applying Verhoeff/Luhn checksums</div>
    `;

    const reader = new FileReader();
    reader.onload = () => {
      const base64Data = reader.result;
      chrome.runtime.sendMessage(
        {
          action: "AUTO_REDACT_ATTACHMENT",
          filename: file.name,
          fileType: file.type,
          fileSize: file.size,
          base64Data: base64Data,
          sharingContext: contextSelect.value
        },
        (res) => {
          if (!res || !res.success) {
            const isOffline = res?.isOffline || (res?.error && (res.error.includes("offline") || res.error.includes("Failed to fetch")));
            const title = isOffline ? "ShareSafe Engine Offline" : "Scan Failed / Unsupported";
            const sub = isOffline
              ? "Start the engine in terminal: <code>python app.py</code> (:5000)"
              : escapeHtml(res?.error || "Make sure ShareSafe server is running (:5000)");

            dropzonePrompt.innerHTML = `
              <div class="dropzone-icon">${isOffline ? "🛑" : "⚠️"}</div>
              <div class="dropzone-text" style="color: #A74440;">${title}</div>
              <div class="dropzone-sub">${sub}</div>
              <div style="display: flex; gap: 8px; margin-top: 8px; justify-content: center;">
                <button type="button" class="btn-choose-file" id="btnRetryPopupFile">${isOffline ? "Retry Connection" : "Try Another File"}</button>
              </div>
            `;
            document.getElementById("btnRetryPopupFile")?.addEventListener("click", () => {
              if (isOffline) {
                checkServer();
                handlePopupAttachment(file);
              } else {
                popupFileInput.click();
              }
            });
            return;
          }

          activeAttachmentScan = res;
          popupExcludedDetectionIds.clear();
          renderPopupAttachmentResult(file, res);
        }
      );
    };
    reader.readAsDataURL(file);
  }

  function getFindingIconSvg(type, label) {
    const t = ((type || "") + " " + (label || "")).toLowerCase();
    if (t.includes("qr") || t.includes("upi")) {
      return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="5" height="5" x="3" y="3" rx="1"/><rect width="5" height="5" x="16" y="3" rx="1"/><rect width="5" height="5" x="3" y="16" rx="1"/><path d="M21 16h-3a2 2 0 0 0-2 2v3"/><path d="M21 21v.01"/><path d="M12 7v3a2 2 0 0 1-2 2H7"/><path d="M3 12h.01"/><path d="M12 3h.01"/><path d="M12 16v.01"/><path d="M16 12h1"/><path d="M21 12v.01"/><path d="M12 21v-1"/></svg>`;
    }
    if (t.includes("card") || t.includes("visa") || t.includes("payment")) {
      return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/></svg>`;
    }
    if (t.includes("aadhaar") || t.includes("pan") || t.includes("passport") || t.includes("ssn") || t.includes("identity")) {
      return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="14" x="3" y="5" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M15 9h2"/><path d="M15 13h2"/><path d="M5 19a4 4 0 0 1 8 0"/></svg>`;
    }
    if (t.includes("phone")) {
      return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>`;
    }
    if (t.includes("mail")) {
      return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>`;
    }
    return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
  }

  function formatFindingData(d) {
    if (d.data_line) return d.data_line;
    const val = d.masked || d.value || "";
    const det = d.details || d.detail || "";
    if (val && det) return `${val} • ${det}`;
    return val || det || "Verified sensitive pattern";
  }

  function renderPopupAttachmentResult(file, scan) {
    const previewWrap = document.getElementById("previewImageWrap");
    const findingsLabel = document.getElementById("findingsSectionLabel");

    popupDropzone.style.display = "none";
    if (previewWrap) previewWrap.style.display = "block";
    attachmentResultCard.style.display = "block";

    resultFileName.textContent = scan.file_name || file.name;
    const isClean = scan.is_clean || scan.total_findings === 0;

    if (isClean) {
      resultRiskBadge.textContent = "CLEAN";
      resultRiskBadge.style.background = "#EAF3EE";
      resultRiskBadge.style.color = "#2E7D5B";
      resultMeta.textContent = `0 sensitive items • Clean to share`;
      if (findingsLabel) findingsLabel.textContent = "Detected — 0 items";
      resultItemsList.innerHTML = `
        <div style="font-size: 12px; color: #2E7D5B; padding: 12px; text-align: center; background: #EAF3EE; border-radius: 8px;">
          ✓ No sensitive PII or credentials detected. Safe to share!
        </div>
      `;
      btnDownloadPopupSanitized.style.display = "none";
    } else {
      const riskLevel = scan.risk_summary?.level || "CRITICAL";
      resultRiskBadge.textContent = `${riskLevel} RISK`;
      resultRiskBadge.style.background = "#C65A4A";
      resultRiskBadge.style.color = "#FFFFFF";
      resultMeta.textContent = `${scan.total_findings} findings auto-redacted • ${scan.is_pdf ? "PDF" : "Image"}`;
      btnDownloadPopupSanitized.style.display = "flex";
      renderPopupDetectionRows(scan.detections || []);
    }

    if (scan.preview_data_url) {
      resultPreviewImg.src = scan.preview_data_url;
      resultPreviewImg.style.display = "block";
    } else {
      resultPreviewImg.style.display = "none";
    }
  }

  function renderPopupDetectionRows(detections) {
    resultItemsList.innerHTML = "";
    const activeCount = detections.filter((d) => !popupExcludedDetectionIds.has(d.id)).length;
    const findingsLabel = document.getElementById("findingsSectionLabel");
    if (findingsLabel) {
      findingsLabel.textContent = `Detected — ${activeCount} item${activeCount === 1 ? '' : 's'} redacted`;
    }

    detections.forEach((d) => {
      const isExcluded = popupExcludedDetectionIds.has(d.id);
      const row = document.createElement("div");
      row.className = "finding-card-row";
      row.innerHTML = `
        <div class="finding-icon-circle">
          ${getFindingIconSvg(d.type, d.label)}
        </div>
        <div class="finding-content">
          <div class="finding-header-line">
            <span class="finding-title">${escapeHtml(d.label || d.type)}</span>
            <span class="finding-pill ${isExcluded ? 'kept' : 'redacted'}">${isExcluded ? 'KEPT' : 'REDACTED'}</span>
          </div>
          <div class="finding-data-line">${escapeHtml(formatFindingData(d))}</div>
        </div>
        <button type="button" class="finding-toggle-btn ${isExcluded ? 'btn-redact' : 'btn-undo'}" title="${isExcluded ? 'Re-apply redaction' : 'Undo redaction and keep'}">
          ${isExcluded ? '↩ Redact' : '✕ Undo'}
        </button>
      `;

      row.querySelector(".finding-toggle-btn").addEventListener("click", () => {
        if (popupExcludedDetectionIds.has(d.id)) {
          popupExcludedDetectionIds.delete(d.id);
        } else {
          popupExcludedDetectionIds.add(d.id);
        }
        renderPopupDetectionRows(detections);

        // Update on backend
        chrome.runtime.sendMessage(
          {
            action: "UPDATE_ATTACHMENT_REDACTIONS",
            sessionId: activeAttachmentScan.session_id,
            excludedDetectionIds: Array.from(popupExcludedDetectionIds)
          },
          (res) => {
            if (res && res.success) {
              activeAttachmentScan.sanitized_base64 = res.sanitized_base64;
              activeAttachmentScan.preview_data_url = res.preview_data_url;
              activeAttachmentScan.sanitized_filename = res.sanitized_filename;
              if (res.preview_data_url) {
                resultPreviewImg.src = res.preview_data_url;
              }
            }
          }
        );
      });

      resultItemsList.appendChild(row);
    });
  }

  if (btnDownloadPopupSanitized) {
    btnDownloadPopupSanitized.addEventListener("click", () => {
      if (!activeAttachmentScan || !activeAttachmentScan.sanitized_base64) return;
      try {
        const parts = activeAttachmentScan.sanitized_base64.split(",");
        const raw = parts.length > 1 ? parts[1] : parts[0];
        const bytes = atob(raw);
        const u8 = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) u8[i] = bytes.charCodeAt(i);
        const blob = new Blob([u8], { type: activeAttachmentScan.sanitized_mime || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = activeAttachmentScan.sanitized_filename || "safe_attachment";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      } catch (err) {
        console.error("Popup download failed:", err);
      }
    });
  }

  if (btnClearPopupAttachment) {
    btnClearPopupAttachment.addEventListener("click", () => {
      activeAttachmentScan = null;
      popupExcludedDetectionIds.clear();
      popupFileInput.value = "";
      const previewWrap = document.getElementById("previewImageWrap");
      if (previewWrap) previewWrap.style.display = "none";
      attachmentResultCard.style.display = "none";
      popupDropzone.style.display = "block";
      dropzonePrompt.innerHTML = `
        <div class="dropzone-icon-peach">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#C65A4A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <div class="dropzone-title">Drop photo, image or PDF to redact</div>
        <button type="button" class="btn-choose-file-terracotta" id="btnPopupChooseFileAgain">Choose File to Audit</button>
        <div class="dropzone-subtext">PDF, PNG, JPG, WEBP &bull; Zero Text Stream Leakage</div>
      `;
      document.getElementById("btnPopupChooseFileAgain")?.addEventListener("click", () => {
        popupFileInput.click();
      });
    });
  }

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
