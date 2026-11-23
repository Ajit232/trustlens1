/**
 * TrustLens popup script.
 *
 * Displays the most recently recorded verdict for the active tab, read
 * from chrome.storage.session (written by service-worker.js). This script
 * makes no network calls itself and performs no analysis — it's a pure
 * read-and-render view.
 */

import { buildVerdictBadge, renderTrustedText } from "./utils.js";

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function render() {
  const badgeSlot = document.getElementById("tl-badge-slot");
  const urlEl = document.getElementById("tl-url");
  const reasonsSlot = document.getElementById("tl-reasons-slot");

  const tab = await getActiveTab();
  if (!tab || typeof tab.id !== "number") {
    renderTrustedText(urlEl, "No active tab.");
    return;
  }

  const key = `tabVerdict:${tab.id}`;
  const stored = await chrome.storage.session.get(key);
  const record = stored[key];

  if (!record) {
    badgeSlot.appendChild(buildVerdictBadge("unknown"));
    renderTrustedText(urlEl, "Not checked yet for this tab.");
    return;
  }

  badgeSlot.appendChild(buildVerdictBadge(record.verdict));
  renderTrustedText(urlEl, record.url); // safe DOM text insertion — see utils.js

  const list = document.createElement("ul");
  list.className = "tl-reasons";
  for (const reason of record.reasons) {
    const item = document.createElement("li");
    renderTrustedText(item, reason);
    list.appendChild(item);
  }
  reasonsSlot.appendChild(list);
}

document.getElementById("tl-options-link").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

render();
