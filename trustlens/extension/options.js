/**
 * TrustLens options page script.
 *
 * Note on host_permissions: manifest.json currently declares
 * "http://localhost:8000/*" as the only host the service worker is allowed
 * to fetch(). Changing the API base URL here to a different origin (e.g. a
 * deployed production API) will NOT work until that origin is also added
 * to host_permissions in manifest.json and the extension is reloaded —
 * MV3 does not allow fetch() to arbitrary cross-origin hosts just because
 * a user typed a URL into a settings field. This is intentional: it stops
 * a compromised or careless settings value from turning the extension into
 * a client for an arbitrary attacker-controlled backend.
 */

import { DEFAULT_API_BASE_URL, getApiBaseUrl, setApiBaseUrl } from "./utils.js";

const form = document.getElementById("tl-options-form");
const input = document.getElementById("tl-api-base-url");
const status = document.getElementById("tl-status");

async function load() {
  input.value = await getApiBaseUrl();
}

function showStatus(message, isError) {
  status.textContent = message;
  status.className = `tl-status-msg ${isError ? "tl-status-msg--error" : "tl-status-msg--success"}`;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const value = input.value.trim();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    showStatus("Enter a valid URL, e.g. http://localhost:8000", true);
    return;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    showStatus("URL must use http or https.", true);
    return;
  }

  await setApiBaseUrl(parsed.origin);
  showStatus("Saved.", false);
});

input.value = DEFAULT_API_BASE_URL;
load();
