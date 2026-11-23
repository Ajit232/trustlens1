/**
 * TrustLens warning page script.
 *
 * This page is web-accessible (see manifest.json web_accessible_resources)
 * so it can be navigated to directly for manual testing right now. Nothing
 * in service-worker.js redirects here automatically yet — that wiring is
 * later-phase detection/response logic. This file only implements: read
 * params → render safely → offer Go back / Continue anyway.
 *
 * Expected query params (all optional, all treated as untrusted):
 *   url      - the destination URL being described
 *   verdict  - one of low_risk | suspicious | malicious | unknown
 *   reasons  - JSON-encoded array of strings
 */

import { buildVerdictBadge, renderTrustedText } from "./utils.js";

const params = new URLSearchParams(window.location.search);

const rawUrl = params.get("url") || "";
const verdict = params.get("verdict") || "unknown";
let reasons = [];
try {
  const parsedReasons = JSON.parse(params.get("reasons") || "[]");
  if (Array.isArray(parsedReasons)) {
    reasons = parsedReasons.filter((r) => typeof r === "string");
  }
} catch {
  reasons = [];
}
if (reasons.length === 0) {
  reasons = ["No specific reasons were provided."];
}

/**
 * Validates that a string is a navigable http(s) URL before we ever assign
 * it to window.location — guards the "Continue anyway" action against a
 * crafted "url" query param containing a javascript: or data: URI.
 *
 * @param {string} candidate
 * @returns {string|null}
 */
function toSafeNavigableUrl(candidate) {
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed.href;
    }
  } catch {
    // fall through
  }
  return null;
}

const safeDestination = toSafeNavigableUrl(rawUrl);

document.getElementById("tl-badge-slot").appendChild(buildVerdictBadge(verdict));
renderTrustedText(
  document.getElementById("tl-url"),
  safeDestination || rawUrl || "(no destination provided)"
);

const summaryEl = document.getElementById("tl-summary");
const summaries = {
  low_risk: "This link looks low-risk, but you can still review it below.",
  suspicious: "This link has characteristics associated with phishing or scams.",
  malicious: "This link matches patterns associated with known malicious sites.",
  unknown: "TrustLens couldn't confidently evaluate this link.",
};
renderTrustedText(summaryEl, summaries[verdict] || summaries.unknown);

const reasonsList = document.getElementById("tl-reasons");
for (const reason of reasons) {
  const item = document.createElement("li");
  renderTrustedText(item, reason);
  reasonsList.appendChild(item);
}

document.getElementById("tl-go-back").addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
});

document.getElementById("tl-continue").addEventListener("click", () => {
  if (safeDestination) {
    window.location.href = safeDestination;
  }
  // If the destination didn't pass validation, "Continue anyway" is
  // silently inert rather than navigating somewhere unvalidated — fail
  // closed, don't guess.
});
