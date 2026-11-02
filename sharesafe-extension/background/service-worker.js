/**
 * ShareSafe Chrome Extension — Background Service Worker (Manifest V3)
 * Orchestrates context menu actions, backend API requests, badge state, and session caching.
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

  console.log("[ShareSafe] Service worker installed and context menu registered.");
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

// Execute text scan via ShareSafe backend
async function executeScan(text, forcedContext = null) {
  const config = await getConfig();
  const context = forcedContext || config.sharingContext;

  try {
    const res = await fetch(`${config.apiUrl}/api/scan-text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: text,
        sharing_context: context
      })
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Server responded with HTTP ${res.status}`);
    }

    const data = await res.json();
    const scanRecord = {
      timestamp: Date.now(),
      sourceText: text,
      sharingContext: context,
      data: data
    };

    // Cache in session storage for popup consumption
    await chrome.storage.session.set({ sharesafe_last_scan: scanRecord });

    const riskLevel = data.risk_summary?.level || "CLEAN";
    const totalFindings = data.total_findings || 0;
    updateBadge(riskLevel, totalFindings);

    return { success: true, record: scanRecord };
  } catch (err) {
    console.error("[ShareSafe] Scan failed:", err);
    const errorRecord = {
      timestamp: Date.now(),
      sourceText: text,
      sharingContext: context,
      error: err.message || "Unable to reach ShareSafe backend."
    };
    await chrome.storage.session.set({ sharesafe_last_scan: errorRecord });
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#A74440" });
    return { success: false, error: err.message };
  }
}

// Right-click Context Menu Action Handler
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "sharesafe-scan-selection") {
    const selectedText = (info.selectionText || "").trim();
    if (!selectedText) return;

    // Set badge to scanning state
    chrome.action.setBadgeText({ text: "..." });
    chrome.action.setBadgeBackgroundColor({ color: "#77736D" });

    await executeScan(selectedText);

    // Try to open popup if browser allows (Chrome 99+)
    try {
      if (chrome.action.openPopup) {
        await chrome.action.openPopup();
      }
    } catch (_) {
      // openPopup may be restricted if user interaction expired; badge is already updated
    }
  }
});

// Runtime Message Dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "SCAN_TEXT") {
    executeScan(message.text, message.sharingContext)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep message channel open for async response
  }

  if (message.action === "CHECK_HEALTH") {
    getConfig().then((config) => {
      fetch(`${config.apiUrl}/api/health`)
        .then((r) => r.json())
        .then((data) => sendResponse({ success: true, data: data, apiUrl: config.apiUrl }))
        .catch((err) => sendResponse({ success: false, error: err.message, apiUrl: config.apiUrl }));
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
