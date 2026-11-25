/**
 * ShareSafe Chrome Extension — Gmail Adapter (Phase 2 Architecture)
 * 
 * SECURITY & PRIVACY MANDATES:
 * 1. Strictly user-initiated: Executed ONLY when user triggers scan action.
 * 2. Zero background surveillance: Never hooks keystrokes, input events, or typing activity.
 * 3. Scoped extraction: Only reads the active compose box currently focused or active.
 * 4. Zero inbox access: Never queries or collects inbox threads, sent messages, or contacts.
 * 5. Non-destructive: Never auto-sends or deletes drafts without explicit user action.
 */

class GmailAdapter {
  constructor() {
    this.platform = "Gmail";
  }

  /**
   * Discovers the currently active email compose body element.
   * Handles dock compose windows, inline replies, and full-screen compose views.
   */
  getActiveComposeElement() {
    // 1. Check focused element first
    const active = document.activeElement;
    if (active && active.isContentEditable && (active.classList.contains("editable") || active.getAttribute("role") === "textbox")) {
      return active;
    }

    // 2. Query standard Gmail message body containers
    const candidates = [
      'div[role="textbox"][contenteditable="true"][aria-label*="Message Body"]',
      'div[role="textbox"][contenteditable="true"][aria-label*="Body"]',
      'div[role="textbox"][g_editable="true"]',
      'div.Am.Al.editable[contenteditable="true"]',
      'div.editable[contenteditable="true"]'
    ];

    for (const selector of candidates) {
      const el = document.querySelector(selector);
      if (el) return el;
    }

    return null;
  }

  /**
   * Extracts clean plain text from the active draft, stripping HTML formatting tags.
   */
  extractDraftText() {
    const composeEl = this.getActiveComposeElement();
    if (!composeEl) {
      return {
        found: false,
        error: "No active Gmail composition area found. Please click inside the email body."
      };
    }

    const text = (composeEl.innerText || composeEl.textContent || "").trim();
    return {
      found: true,
      text: text,
      length: text.length
    };
  }

  /**
   * Safely replaces draft text with sanitized / masked representation upon user confirmation.
   */
  replaceDraftText(sanitizedText) {
    const composeEl = this.getActiveComposeElement();
    if (!composeEl) {
      return { success: false, error: "Active Gmail compose area not found." };
    }

    try {
      composeEl.focus();
      // Select all content inside compose box
      document.execCommand("selectAll", false, null);
      // Replace with sanitized text
      document.execCommand("insertText", false, sanitizedText);

      // Dispatch input event so Gmail auto-save registers change
      composeEl.dispatchEvent(new Event("input", { bubbles: true }));
      return { success: true };
    } catch (err) {
      // Fallback direct assignment
      composeEl.innerText = sanitizedText;
      composeEl.dispatchEvent(new Event("input", { bubbles: true }));
      return { success: true, fallback: true };
    }
  }

  /**
   * Pre-send warning display attached to the compose box.
   */
  showPreSendWarning(findingsCount, riskLevel) {
    const composeEl = this.getActiveComposeElement();
    if (!composeEl) return;

    const composeContainer = composeEl.closest('div[role="region"]') || composeEl.parentElement;
    if (!composeContainer || !composeContainer.parentElement) return;

    window.ShareSafeUI.showComposeThreatBanner({
      id: "sharesafe-gmail-warning",
      findingsCount,
      riskLevel,
      mountFn: (banner) => {
        banner.style.margin = "10px 16px";
        banner.style.zIndex = "9999";
        composeContainer.parentElement.insertBefore(banner, composeContainer);
      }
    });
  }
}

const adapter = new GmailAdapter();
window.ShareSafeGmailAdapter = adapter;

// Runtime message listener for background/popup commands
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "GET_DRAFT_TEXT") {
    const res = adapter.extractDraftText();
    sendResponse(res);
    return true;
  }

  if (message.action === "REPLACE_DRAFT_TEXT") {
    const res = adapter.replaceDraftText(message.sanitizedText);
    sendResponse(res);
    return true;
  }

  if (message.action === "SHOW_PRE_SEND_WARNING") {
    adapter.showPreSendWarning(message.findingsCount || 0, message.riskLevel || "HIGH");
    sendResponse({ success: true });
    return true;
  }

  if (message.action === "CHECK_PLATFORM_SUPPORT") {
    const el = adapter.getActiveComposeElement();
    sendResponse({ supported: true, platform: "Gmail", hasActiveCompose: !!el });
    return true;
  }
});
