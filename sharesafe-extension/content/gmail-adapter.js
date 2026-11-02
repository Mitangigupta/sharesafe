/**
 * ShareSafe Chrome Extension — Gmail Adapter (Phase 2 Architecture)
 * 
 * SECURITY & PRIVACY MANDATES:
 * 1. Strictly user-initiated: Executed ONLY when user triggers scan action.
 * 2. Zero background surveillance: Never hooks keystrokes, input events, or typing activity.
 * 3. Scoped extraction: Only reads the active compose box currently focused.
 * 4. Zero inbox access: Never queries or collects inbox threads, sent messages, or contacts.
 * 5. Non-destructive: Never auto-sends, auto-edits, or deletes drafts.
 */

class GmailAdapter {
  constructor() {
    this.platform = "Gmail";
  }

  /**
   * Discovers the currently active email compose body element.
   * Handles both dock compose windows and full-screen compose views.
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

    // Extract normalized plain text
    const text = (composeEl.innerText || composeEl.textContent || "").trim();
    return {
      found: true,
      text: text,
      element: composeEl
    };
  }

  /**
   * Pre-send warning display (non-destructive visual indicator)
   */
  showPreSendWarning(findings, riskSummary) {
    console.log("[ShareSafe] Gmail pre-send review findings:", findings);
  }
}

// Export for extension runtime
window.ShareSafeGmailAdapter = new GmailAdapter();
