/**
 * ShareSafe Chrome Extension — Selection Helper Content Script
 * Passive helper script for text selection retrieval across general web pages.
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "GET_SELECTION") {
    const selection = window.getSelection();
    let text = selection ? selection.toString().trim() : "";
    
    // Fallback: check focused textarea or input if no DOM selection range
    if (!text && document.activeElement) {
      const el = document.activeElement;
      if (el.tagName === "TEXTAREA" || (el.tagName === "INPUT" && el.type === "text")) {
        const start = el.selectionStart;
        const end = el.selectionEnd;
        if (start !== undefined && end !== undefined && start !== end) {
          text = el.value.substring(start, end).trim();
        } else if (el.value) {
          text = el.value.trim();
        }
      }
    }
    
    sendResponse({ text: text });
    return true;
  }
});
