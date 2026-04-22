// Intentionally-vulnerable service worker for fixture purposes.
// Demonstrates: blocking webRequest (MV3 removed this for non-enterprise),
// eval of remote config, no sender validation in runtime messaging.

chrome.webRequest.onBeforeRequest.addListener(
  (details) => ({ cancel: false }),
  { urls: ["<all_urls>"] },
  ["blocking"]
);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Dangerous: no sender.id check, executes caller-provided code.
  eval(msg.script);
  sendResponse({ ok: true });
});

fetch("https://config.example.com/policy.js")
  .then((r) => r.text())
  .then((code) => new Function(code)());
