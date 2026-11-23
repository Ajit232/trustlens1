/**
 * TrustLens shared utilities.
 *
 * Loaded as an ES module (manifest declares the service worker as
 * "type": "module"; popup/options/warning pages import it with
 * <script type="module" src="utils.js">). Every page shares this one
 * implementation instead of copy-pasting logic, so a fix here fixes it
 * everywhere.
 *
 * Detection is not implemented in this phase. Nothing in this file scores
 * or classifies a URL — these are plumbing helpers only (safe rendering,
 * config storage, and a coarse "should we even ask the backend" filter).
 */

export const DEFAULT_API_BASE_URL = "http://localhost:8000";

/**
 * Renders untrusted text into an element using safe DOM APIs.
 *
 * Security decision: this is the ONLY sanctioned way any page in this
 * extension displays a URL (or any other untrusted string) to the user.
 * textContent never interprets its input as markup, so a destination URL
 * containing "<img src=x onerror=...>" or similar is rendered as inert
 * literal text — it cannot break out of its container the way innerHTML
 * assignment could. Never replace calls to this function with innerHTML.
 *
 * @param {HTMLElement} element
 * @param {string} text
 */
export function renderTrustedText(element, text) {
  element.textContent = text;
}

/**
 * Builds the verdict badge element (see styles.css .tl-badge) without any
 * HTML-string concatenation — every piece of text content is set via
 * textContent, and the only thing driven by the verdict value is a CSS
 * class name drawn from a fixed allow-list, never interpolated directly
 * into markup.
 *
 * @param {"low_risk"|"suspicious"|"malicious"|"unknown"} verdict
 * @returns {HTMLSpanElement}
 */
export function buildVerdictBadge(verdict) {
  const allowedVerdicts = ["low_risk", "suspicious", "malicious", "unknown"];
  const safeVerdict = allowedVerdicts.includes(verdict) ? verdict : "unknown";

  const badge = document.createElement("span");
  badge.className = `tl-badge tl-badge--${safeVerdict}`;
  renderTrustedText(badge, safeVerdict.replace("_", " "));
  return badge;
}

/**
 * Coarse pre-filter deciding whether a navigation target is worth sending
 * to the backend at all. This is NOT detection logic — it never judges
 * whether a site is safe, only whether it's the kind of URL that could
 * ever be meaningfully checked (skips the extension's own pages, browser
 * internal pages, and the configured backend host itself, so the backend
 * never gets asked to evaluate a request to itself).
 *
 * @param {string} url
 * @param {string} apiBaseUrl
 * @returns {boolean}
 */
export function isCheckableUrl(url, apiBaseUrl) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return false; // skips chrome://, chrome-extension://, file://, etc.
  }

  try {
    const apiHost = new URL(apiBaseUrl).host;
    if (parsed.host === apiHost) {
      return false;
    }
  } catch {
    // Malformed configured API base URL — fail closed by still allowing
    // the caller to attempt the check rather than crashing here; the API
    // client itself will reject a bad base URL when it tries to fetch.
  }

  return true;
}

/**
 * Reads the configured backend API base URL from extension storage,
 * falling back to the local-dev default. Stored/read via chrome.storage
 * (not localStorage — MV3 service workers don't have DOM storage access,
 * and chrome.storage.sync/local is the supported mechanism).
 *
 * @returns {Promise<string>}
 */
export async function getApiBaseUrl() {
  const result = await chrome.storage.local.get("apiBaseUrl");
  return result.apiBaseUrl || DEFAULT_API_BASE_URL;
}

/**
 * @param {string} apiBaseUrl
 * @returns {Promise<void>}
 */
export async function setApiBaseUrl(apiBaseUrl) {
  await chrome.storage.local.set({ apiBaseUrl });
}
