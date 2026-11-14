/**
 * ShareSafe Chrome Extension — Background Service Worker (Manifest V3)
 * Orchestrates context menu actions, backend API requests, badge state,
 * offline fallback detection, and secure pre-upload file screening.
 */

const DEFAULT_API_URL = "http://127.0.0.1:5000";
const DEFAULT_CONTEXT = "academic";

// Context Menu Setup
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "sharesafe-scan-selection",
    title: "Scan with ShareSafe",
    contexts: ["selection"]
  });

  // Initialize default settings if not configured
  chrome.storage.sync.get(["apiUrl", "sharingContext"], (res) => {
    if (!res.apiUrl) chrome.storage.sync.set({ apiUrl: DEFAULT_API_URL });
    if (!res.sharingContext) chrome.storage.sync.set({ sharingContext: DEFAULT_CONTEXT });
  });

  console.log("[ShareSafe] Service worker active. Manifest V3 ready.");
});

// Helper to get configuration
async function getConfig() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiUrl", "sharingContext"], (items) => {
      resolve({
        apiUrl: (items.apiUrl || DEFAULT_API_URL).replace(/\/+$/, ""),
        sharingContext: items.sharingContext || DEFAULT_CONTEXT
      });
    });
  });
}

// Update extension icon badge based on risk level
function updateBadge(riskLevel, count) {
  if (count === 0 || riskLevel === "CLEAN") {
    chrome.action.setBadgeText({ text: "0" });
    chrome.action.setBadgeBackgroundColor({ color: "#647C70" }); // Muted Sage
  } else {
    chrome.action.setBadgeText({ text: String(count) });
    if (riskLevel === "CRITICAL") {
      chrome.action.setBadgeBackgroundColor({ color: "#A74440" }); // Deep Red
    } else if (riskLevel === "HIGH") {
      chrome.action.setBadgeBackgroundColor({ color: "#C96D67" }); // Muted Coral
    } else {
      chrome.action.setBadgeBackgroundColor({ color: "#B27329" }); // Pale Amber
    }
  }
}

// ============================================================================
// Mathematical Checksum Validators for Offline Fallback (Verhoeff & Luhn)
// ============================================================================
const dTable = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
];
const pTable = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
];

function validateVerhoeff(numStr) {
  const digits = String(numStr).replace(/\D/g, "");
  if (digits.length !== 12) return false;
  let c = 0;
  const reversed = digits.split("").reverse().map(Number);
  for (let i = 0; i < reversed.length; i++) {
    c = dTable[c][pTable[i % 8][reversed[i]]];
  }
  return c === 0;
}

function validateLuhn(numStr) {
  const digits = String(numStr).replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Client-Side Offline Detection Engine
 * Executes when the local Flask server is unreachable so the extension remains
 * 100% operational during independent demonstrations, academic audits, and offline evaluations.
 */
function runOfflineDetectionEngine(text, sharingContext = "academic") {
  const detections = [];
  let maskedText = text;

  // 1. Aadhaar UID: 12 digits, Verhoeff validated
  const aadhaarRegex = /\b([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})\b/g;
  let match;
  while ((match = aadhaarRegex.exec(text)) !== null) {
    const rawVal = match[1];
    const cleanDigits = rawVal.replace(/\D/g, "");
    if (validateVerhoeff(cleanDigits)) {
      const maskedVal = "XXXX XXXX " + cleanDigits.slice(-4);
      detections.push({
        type: "AADHAAR_UID",
        label: "Indian Aadhaar UID",
        value: rawVal,
        masked: maskedVal,
        risk: "CRITICAL",
        category: "Government Identity",
        details: "Verified via Verhoeff Mod-10 dihedral (D5) algorithm"
      });
      maskedText = maskedText.split(rawVal).join("[REDACTED_AADHAAR]");
    }
  }

  // 2. PAN Card: 5 letters, 4 numbers, 1 letter
  const panRegex = /\b([A-Z]{5}[0-9]{4}[A-Z])\b/g;
  while ((match = panRegex.exec(text)) !== null) {
    const rawVal = match[1];
    const maskedVal = rawVal.slice(0, 5) + "****" + rawVal.slice(-1);
    detections.push({
      type: "PAN_CARD",
      label: "Indian PAN Card",
      value: rawVal,
      masked: maskedVal,
      risk: "HIGH",
      category: "Tax & Financial",
      details: "Format verified: Income Tax statutory individual identifier"
    });
    maskedText = maskedText.split(rawVal).join("[REDACTED_PAN]");
  }

  // 3. Credit / Debit Cards: Luhn verified
  const cardRegex = /\b((?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,4})\b/g;
  while ((match = cardRegex.exec(text)) !== null) {
    const rawVal = match[1];
    const cleanDigits = rawVal.replace(/\D/g, "");
    if (validateLuhn(cleanDigits)) {
      const maskedVal = cleanDigits.slice(0, 4) + " **** **** " + cleanDigits.slice(-4);
      detections.push({
        type: "CREDIT_CARD",
        label: "Credit / Debit Card",
        value: rawVal,
        masked: maskedVal,
        risk: "CRITICAL",
        category: "Payment Card",
        details: "Luhn Mod-10 Checksum Algorithm verified"
      });
      maskedText = maskedText.split(rawVal).join("[REDACTED_CARD]");
    }
  }

  // 4. API Keys & Cloud Secrets
  const secretRegex = /\b(ghp_[a-zA-Z0-9]{36}|sk_live_[a-zA-Z0-9]{24,}|AKIA[0-9A-Z]{16})\b/g;
  while ((match = secretRegex.exec(text)) !== null) {
    const rawVal = match[1];
    detections.push({
      type: "SECRET_KEY",
      label: "API / Infrastructure Secret",
      value: rawVal,
      masked: rawVal.slice(0, 4) + "****************",
      risk: "CRITICAL",
      category: "Secrets & Tokens",
      details: "High-entropy API key or authentication token pattern"
    });
    maskedText = maskedText.split(rawVal).join("[REDACTED_SECRET]");
  }

  // 5. Phone Numbers
  const phoneRegex = /\b(?:\+91[\-\s]?)?([6-9]\d{9})\b/g;
  while ((match = phoneRegex.exec(text)) !== null) {
    const rawVal = match[0];
    const cleanDigits = rawVal.replace(/\D/g, "");
    if (cleanDigits.length >= 10) {
      detections.push({
        type: "PHONE_NUMBER",
        label: "Mobile / Phone Number",
        value: rawVal,
        masked: "+91 ***** " + cleanDigits.slice(-4),
        risk: "MEDIUM",
        category: "Contact Info",
        details: "Mobile contact identifier"
      });
      maskedText = maskedText.split(rawVal).join("[REDACTED_PHONE]");
    }
  }

  // 6. Email Addresses
  const emailRegex = /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
  while ((match = emailRegex.exec(text)) !== null) {
    const rawVal = match[1];
    const parts = rawVal.split("@");
    const user = parts[0];
    const domain = parts[1] || "";
    const maskedVal = user.charAt(0) + "***@" + domain;
    detections.push({
      type: "EMAIL_ADDRESS",
      label: "Email Address",
      value: rawVal,
      masked: maskedVal,
      risk: "LOW",
      category: "Contact Info",
      details: "Electronic communication address"
    });
    maskedText = maskedText.split(rawVal).join("[REDACTED_EMAIL]");
  }

  // Calculate Context-Aware Risk
  let multiplier = 1.0;
  if (sharingContext === "professional") multiplier = 1.1;
  else if (sharingContext === "private") multiplier = 0.85;
  else if (sharingContext === "public") multiplier = 1.3;

  let rawScore = 0;
  detections.forEach((d) => {
    if (d.risk === "CRITICAL") rawScore += 45;
    else if (d.risk === "HIGH") rawScore += 30;
    else if (d.risk === "MEDIUM") rawScore += 15;
    else rawScore += 5;
  });

  const finalScore = Math.min(100, Math.round(rawScore * multiplier));
  let level = "CLEAN";
  if (finalScore >= 70) level = "CRITICAL";
  else if (finalScore >= 40) level = "HIGH";
  else if (finalScore > 0) level = "MEDIUM";

  const recommendations = [];
  detections.forEach((d) => {
    recommendations.push({
      type: d.label,
      priority: d.risk === "CRITICAL" ? "HIGH_PRIORITY" : "REVIEW_RECOMMENDED",
      action: "REDACT",
      confidence: "high",
      recommendation: `Protect ${d.label} under applicable privacy guidelines.`
    });
  });

  return {
    success: true,
    is_offline_fallback: true,
    total_findings: detections.length,
    can_share_safely: detections.length === 0,
    masked_text: maskedText,
    detections: detections,
    risk_summary: {
      score: finalScore,
      level: level,
      recommendation: detections.length === 0
        ? "No sensitive information detected. Clear for sharing."
        : `Detected ${detections.length} sensitive item(s). Redaction recommended before sharing.`
    },
    assistant: {
      recommendations: recommendations
    }
  };
}

// Execute text scan via ShareSafe backend (with transparent client-side fallback)
async function executeScan(text, forcedContext = null) {
  const config = await getConfig();
  const context = forcedContext || config.sharingContext;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`${config.apiUrl}/api/scan-text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: text,
        sharing_context: context
      }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();
    const scanRecord = {
      timestamp: Date.now(),
      sourceText: text,
      sharingContext: context,
      data: data
    };

    await chrome.storage.session.set({ sharesafe_last_scan: scanRecord });

    const riskLevel = data.risk_summary?.level || "CLEAN";
    const totalFindings = data.total_findings || 0;
    updateBadge(riskLevel, totalFindings);

    return { success: true, record: scanRecord };
  } catch (err) {
    // If backend is unreachable or timed out, seamlessly execute client-side fallback engine
    console.log("[ShareSafe] Backend unreachable; activating Client-Side Offline Engine:", err.message);
    const offlineData = runOfflineDetectionEngine(text, context);
    const scanRecord = {
      timestamp: Date.now(),
      sourceText: text,
      sharingContext: context,
      data: offlineData,
      isOfflineFallback: true
    };

    await chrome.storage.session.set({ sharesafe_last_scan: scanRecord });
    updateBadge(offlineData.risk_summary.level, offlineData.total_findings);
    return { success: true, record: scanRecord, offlineFallback: true };
  }
}

// Convert Base64 Data URL to Blob for secure multipart transmission
function base64ToBlob(base64Data, contentType) {
  try {
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
  } catch (e) {
    console.error("[ShareSafe] Base64 decoding failed:", e);
    return null;
  }
}

// Right-click Context Menu Action Handler
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "sharesafe-scan-selection") {
    const selectedText = (info.selectionText || "").trim();
    if (!selectedText) return;

    chrome.action.setBadgeText({ text: "..." });
    chrome.action.setBadgeBackgroundColor({ color: "#77736D" });

    await executeScan(selectedText);

    try {
      if (chrome.action.openPopup) {
        await chrome.action.openPopup();
      }
    } catch (_) {}
  }
});

// Runtime Message Dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "SCAN_TEXT") {
    executeScan(message.text, message.sharingContext)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.action === "CHECK_HEALTH") {
    getConfig().then((config) => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      fetch(`${config.apiUrl}/api/health`, { signal: controller.signal })
        .then((r) => r.json())
        .then((data) => {
          clearTimeout(timeoutId);
          sendResponse({ success: true, data: data, apiUrl: config.apiUrl });
        })
        .catch((err) => {
          clearTimeout(timeoutId);
          sendResponse({ success: false, error: err.message, apiUrl: config.apiUrl });
        });
    });
    return true;
  }

  // Pre-Upload File Inspection via Core Endpoint (Bypasses Mixed Content / CORS)
  if (message.action === "INSPECT_FILE") {
    getConfig().then(async (config) => {
      try {
        const blob = base64ToBlob(message.base64Data, message.fileType);
        if (!blob) {
          throw new Error("Unable to parse file stream");
        }

        const formData = new FormData();
        formData.append("file", blob, message.filename || "file");
        formData.append("sharing_context", message.sharingContext || config.sharingContext);

        const res = await fetch(`${config.apiUrl}/api/inspect-file`, {
          method: "POST",
          body: formData
        });

        if (!res.ok) {
          throw new Error(`Server returned HTTP ${res.status}`);
        }

        const data = await res.json();
        sendResponse({ success: true, data: data });
      } catch (err) {
        console.warn("[ShareSafe] File inspection failed or server offline:", err.message);
        sendResponse({ success: false, error: err.message });
      }
    });
    return true;
  }

  // Automatic Attachment Redaction Workflow (Prioritized File Scanning)
  if (message.action === "AUTO_REDACT_ATTACHMENT") {
    getConfig().then(async (config) => {
      try {
        const blob = base64ToBlob(message.base64Data, message.fileType);
        if (!blob) {
          throw new Error("Unable to parse file stream");
        }

        const formData = new FormData();
        formData.append("file", blob, message.filename || "attachment");
        formData.append("sharing_context", message.sharingContext || config.sharingContext);
        if (message.defaultStyle) {
          formData.append("default_style", message.defaultStyle);
        }

        const res = await fetch(`${config.apiUrl}/api/auto-redact-attachment`, {
          method: "POST",
          body: formData
        });

        const data = await res.json();
        sendResponse(data);
      } catch (err) {
        console.warn("[ShareSafe] Auto-redaction attachment failed:", err.message);
        sendResponse({ success: false, error: err.message });
      }
    });
    return true;
  }

  // Selective Undo / Edit Redaction Update for Active Attachment
  if (message.action === "UPDATE_ATTACHMENT_REDACTIONS") {
    getConfig().then(async (config) => {
      try {
        const res = await fetch(`${config.apiUrl}/api/update-attachment-redactions/${message.sessionId}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            excluded_detection_ids: message.excludedDetectionIds || [],
            custom_styles: message.customStyles || {}
          })
        });

        const data = await res.json();
        sendResponse(data);
      } catch (err) {
        console.warn("[ShareSafe] Update attachment redactions failed:", err.message);
        sendResponse({ success: false, error: err.message });
      }
    });
    return true;
  }

  if (message.action === "CLEAR_SCAN") {
    chrome.storage.session.remove("sharesafe_last_scan", () => {
      chrome.action.setBadgeText({ text: "" });
      sendResponse({ success: true });
    });
    return true;
  }
});
