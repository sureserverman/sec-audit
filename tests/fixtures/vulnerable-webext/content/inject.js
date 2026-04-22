// Intentionally-vulnerable content script.
// Demonstrates: DOM XSS via innerHTML, postMessage handler with no origin
// check, secret stored in chrome.storage.local.

window.addEventListener("message", (event) => {
  // Dangerous: no event.origin check.
  document.getElementById("target").innerHTML = event.data.html;
});

chrome.storage.local.set({
  api_key: "sk_live_DEADBEEFCAFEBABE1234567890ABCDEF",
  session_token: "jwt.dangerous.placeholder",
});
