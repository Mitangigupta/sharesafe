/**
 * ShareSafe Chrome Extension — WhatsApp Web Adapter (Phase 2 Architecture)
 * 
 * SECURITY & PRIVACY MANDATES:
 * 1. Strictly user-initiated: Executed ONLY when user triggers scan action.
 * 2. Zero background surveillance: Never hooks keystrokes, input events, or typing activity.
 * 3. Scoped extraction: Only reads the active compose box currently focused.
 * 4. Zero thread access: Never queries or collects previous conversations, chat history, or contacts.
 * 5. Non-destructive: Never auto-sends or deletes messages without explicit user action.
 */

class WhatsAppWebAdapter {
  constructor() {
    this.platform = "WhatsApp Web";
  }

  /**
   * Discovers the currently active message composition element.
   * Uses resilient semantic/ARIA attributes instead of volatile minified class names.
   */
  getActiveComposeElement() {
    // 1. Check focused element first
    const active = document.activeElement;
    if (active && active.isContentEditable && (active.getAttribute("role") === "textbox" || active.closest("footer"))) {
      return active;
    }

    // 2. Query WhatsApp Web footer compose area
    const candidates = [
      'footer div[contenteditable="true"][role="textbox"]',
      'div[contenteditable="true"][data-tab="10"]',
      'footer div[contenteditable="true"]',
      'div[contenteditable="true"][aria-label*="Type a message"]',
      'div[contenteditable="true"][aria-label*="message"]'
    ];

    for (const selector of candidates) {
      const el = document.querySelector(selector);
      if (el) return el;
    }

    return null;
  }

  /**
   * Extracts clean plain text from the active draft, stripping custom WhatsApp emoji <img> tags.
   */
  extractDraftText() {
    const composeEl = this.getActiveComposeElement();
    if (!composeEl) {
      return {
        found: false,
        error: "No active WhatsApp message composition box found. Please click into the message input field."
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
      return { success: false, error: "Active WhatsApp compose box not found." };
    }

    try {
      composeEl.focus();
      document.execCommand("selectAll", false, null);
      document.execCommand("insertText", false, sanitizedText);
      composeEl.dispatchEvent(new Event("input", { bubbles: true }));
      return { success: true };
    } catch (err) {
      composeEl.innerText = sanitizedText;
      composeEl.dispatchEvent(new Event("input", { bubbles: true }));
      return { success: true, fallback: true };
    }
  }

  /**
   * Pre-send warning overlay (non-destructive visual indicator attached to compose bar).
   */
  showPreSendWarning(findingsCount, riskLevel) {
    const composeEl = this.getActiveComposeElement();
    if (!composeEl) return;

    const footer = composeEl.closest("footer") || composeEl.parentElement;
    if (!footer) return;

    window.ShareSafeUI.showComposeThreatBanner({
      id: "sharesafe-whatsapp-warning",
      findingsCount,
      riskLevel,
      mountFn: (banner) => {
        banner.style.position = "absolute";
        banner.style.bottom = "100%";
        banner.style.left = "16px";
        banner.style.right = "16px";
        banner.style.marginBottom = "10px";
        banner.style.zIndex = "1000";
        footer.style.position = "relative";
        footer.appendChild(banner);
      }
    });
  }
}

const waAdapter = new WhatsAppWebAdapter();
window.ShareSafeWhatsAppAdapter = waAdapter;

// Runtime message listener for background/popup commands
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "GET_DRAFT_TEXT") {
    const res = waAdapter.extractDraftText();
    sendResponse(res);
    return true;
  }

  if (message.action === "REPLACE_DRAFT_TEXT") {
    const res = waAdapter.replaceDraftText(message.sanitizedText);
    sendResponse(res);
    return true;
  }

  if (message.action === "SHOW_PRE_SEND_WARNING") {
    waAdapter.showPreSendWarning(message.findingsCount || 0, message.riskLevel || "HIGH");
    sendResponse({ success: true });
    return true;
  }

  if (message.action === "CHECK_PLATFORM_SUPPORT") {
    const el = waAdapter.getActiveComposeElement();
    sendResponse({ supported: true, platform: "WhatsApp Web", hasActiveCompose: !!el });
    return true;
  }
});
