/**
 * ShareSafe Chrome Extension — WhatsApp Web Adapter (Phase 2 Architecture)
 * 
 * SECURITY & PRIVACY MANDATES:
 * 1. Strictly user-initiated: Executed ONLY when user triggers scan action.
 * 2. Zero background surveillance: Never hooks keystrokes, input events, or typing activity.
 * 3. Scoped extraction: Only reads the active compose box currently focused.
 * 4. Zero thread access: Never queries or collects previous conversations, chat history, or contacts.
 * 5. Non-destructive: Never auto-sends, auto-edits, or deletes messages.
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

    // Extract text content while preserving line breaks and ignoring markup
    const text = (composeEl.innerText || composeEl.textContent || "").trim();
    return {
      found: true,
      text: text,
      element: composeEl
    };
  }

  /**
   * Pre-send warning overlay (non-destructive visual indicator)
   */
  showPreSendWarning(findings, riskSummary) {
    // Visual non-intrusive warning card attached to compose bar
    console.log("[ShareSafe] WhatsApp Web pre-send review findings:", findings);
  }
}

// Export for extension runtime
window.ShareSafeWhatsAppAdapter = new WhatsAppWebAdapter();
