/**
 * TrustLens background service worker (Manifest V3).
 *
 * Scope of this phase: listen for top-level navigations, ask the backend
 * to check the destination URL, and remember the (stubbed) verdict so the
 * popup can display it. This file does NOT:
 *   - block, redirect, or interrupt any navigation
 *   - show the warning interstitial automatically
 *   - make any safe/unsafe judgment itself
 * All of that is detection/response logic for a later phase. Right now the
 * backend always returns "unknown" with confidence "low" (see backend
 * scanner/views.py), and this worker treats that as informational only.
 *
 * No eval, no dynamically constructed/injected code, no remote script
 * loading — this file is the entire runtime logic of the extension's
 * background context, loaded as a static ES module per the manifest.
 */

import {
  DEFAULT_API_BASE_URL,
  getApiBaseUrl,
  isCheckableUrl,
} from "./utils.js";

const REQUEST_TIMEOUT_MS = 5000;

/**
 * Strips the URL fragment before the URL ever leaves the browser.
 *
 * This is a minimal, explicit exception to the rule that full sanitization
 * belongs to a later phase: fragments are a common carrier of sensitive
 * tokens (OAuth implicit-flow tokens, SPA route state) and are never
 * needed for server-side URL analysis, so removing them costs nothing and
 * closes an easy, obvious leak even at this early stage. Query-parameter
 * stripping (a much larger, denylist-driven task) is intentionally left
 * to the dedicated sanitization phase rather than being partially done
 * here.
 *
 * @param {string} url
 * @returns {string}
 */
function stripFragment(url) {
  const hashIndex = url.indexOf("#");
  return hashIndex === -1 ? url : url.slice(0, hashIndex);
}

/**
 * Calls the backend check-url endpoint with a bounded timeout. Never
 * retries silently forever, never treats a network failure as a verdict —
 * callers get either a parsed JSON body or null.
 *
 * @param {string} url
 * @param {string} apiBaseUrl
 * @returns {Promise<object|null>}
 */
async function requestVerdict(url, apiBaseUrl) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${apiBaseUrl}/api/v1/check-url/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    if (!response.ok) {
      return null; // 4xx/5xx — treated as "couldn't verify", never parsed as a verdict
    }

    const data = await response.json();

    // Defensive shape check — never trust a 200 response blindly. If the
    // backend contract changes unexpectedly, fail closed to "no verdict"
    // rather than passing malformed data on to the popup.
    if (typeof data.verdict !== "string" || typeof data.risk_score !== "number") {
      return null;
    }

    return data;
  } catch {
    // Network error, timeout, or JSON parse failure — all treated the same.
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Records the most recent verdict for a tab so popup.js can show it.
 * Session-scoped storage — cleared when the browser session ends, not a
 * persistent history of the user's browsing.
 *
 * @param {number} tabId
 * @param {string} url
 * @param {object|null} verdictData
 */
async function recordVerdictForTab(tabId, url, verdictData) {
  await chrome.storage.session.set({
    [`tabVerdict:${tabId}`]: {
      url,
      verdict: verdictData?.verdict ?? "unknown",
      riskScore: verdictData?.risk_score ?? 0,
      confidence: verdictData?.confidence ?? "low",
      reasons: verdictData?.reasons ?? ["Could not reach the TrustLens backend."],
      checkedAt: new Date().toISOString(),
    },
  });
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Only top-level frame navigations — not iframes, not sub-resource
  // loads. Keeps this to "the page the user is actually looking at."
  if (details.frameId !== 0) {
    return;
  }

  const apiBaseUrl = await getApiBaseUrl();

  if (!isCheckableUrl(details.url, apiBaseUrl)) {
    return;
  }

  const sanitizedUrl = stripFragment(details.url);
  const verdictData = await requestVerdict(sanitizedUrl, apiBaseUrl);

  await recordVerdictForTab(details.tabId, details.url, verdictData);

  // TODO (later phase): once the backend implements real detection, branch
  // on verdictData.verdict here to show the small notification (low_risk)
  // or redirect to warning.html (suspicious / malicious / unknown). For
  // now this worker only records what it learned — it never acts on it.
});

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get("apiBaseUrl");
  if (!existing.apiBaseUrl) {
    await chrome.storage.local.set({ apiBaseUrl: DEFAULT_API_BASE_URL });
  }
});
