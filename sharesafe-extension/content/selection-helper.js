/**
 * ShareSafe Chrome Extension — Selection Helper Content Script
 * Minimal, passive helper script for text selection retrieval.
 */

// Respond to background/popup queries for selected text
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "GET_SELECTION") {
    const selection = window.getSelection();
    const text = selection ? selection.toString().trim() : "";
    sendResponse({ text: text });
    return true;
  }
});
