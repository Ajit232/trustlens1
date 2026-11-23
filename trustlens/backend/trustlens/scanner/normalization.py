"""
URL normalization and sanitization.

This is the single place responsible for turning a raw, untrusted URL
string into:
  (a) a normalized_url safe to return to the client and store (as a hash),
  (b) a domain string safe to store in the clear,
  (c) validation signals (embedded credentials? internal host?) the
      serializer uses to reject unsupported input before it reaches the
      view.

Nothing in this module makes a network call, resolves DNS, or fetches
anything — every check here is pure string/URL-structure parsing.
"""

import hashlib
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Query parameters stripped before a URL is ever normalized, stored, or
# returned. This is an explicit deny-list, not an allow-list: an allow-list
# risks silently discarding legitimate params future analysis logic might
# need, while a deny-list directly targets known-sensitive categories.
# Matching is case-insensitive.
SENSITIVE_QUERY_PARAM_NAMES = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth",
    "authorization",
    "session",
    "sid",
    "sessionid",
    "otp",
    "password",
    "pwd",
    "passwd",
    "email",
    "key",
    "apikey",
    "api_key",
    "secret",
    "client_secret",
    "code",
    "state",
    "jwt",
    "credential",
    "credentials",
    "authuser",
}

# Hosts/host patterns treated as "internal" and rejected outright. This is
# purely a string comparison against the literal host in the URL — we never
# resolve DNS to check this, both because the backend has no business
# making network calls at all, and because a DNS-based check could itself
# be tricked (DNS rebinding) while adding latency for no real benefit here.
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _is_private_ipv4_literal(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    octets = [int(p) for p in parts]
    if any(o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:  # link-local
        return True
    return False


def is_internal_host(host: str) -> bool:
    """True if `host` (already lowercased, no port) is loopback/private/link-local."""
    host = host.lower()
    if host in _LOOPBACK_HOSTS:
        return True
    if host.startswith("fc00:") or host.startswith("fe80:") or host.startswith("::1"):
        return True
    return _is_private_ipv4_literal(host)


def has_embedded_credentials(parsed) -> bool:
    """True if the URL's netloc includes a user:pass@ (or bare user@) prefix."""
    return "@" in parsed.netloc


def _strip_sensitive_query_params(query: str) -> str:
    pairs = parse_qsl(query, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if k.lower() not in SENSITIVE_QUERY_PARAM_NAMES]
    return urlencode(kept)


def normalize_url(url: str) -> str:
    """
    Produces the sanitized URL used for the API response, for hashing, and
    for storage.

    Applies, in order:
      1. Lowercase scheme and host (path/query casing preserved).
      2. Strip default ports (:443 for https, :80 for http).
      3. Strip the fragment entirely (never needed server-side, common
         carrier of OAuth/SPA tokens).
      4. Strip query parameters matching SENSITIVE_QUERY_PARAM_NAMES.

    Callers must reject URLs with embedded credentials or internal hosts
    *before* calling this (see serializers.py) — this function assumes it
    has already received acceptable input and focuses only on normalization.
    """
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()

    port = parsed.port
    default_port = {"http": 80, "https": 443}.get(scheme)
    netloc = host if port is None or port == default_port else f"{host}:{port}"

    sanitized_query = _strip_sensitive_query_params(parsed.query)

    normalized = urlunparse((scheme, netloc, parsed.path, parsed.params, sanitized_query, ""))
    return normalized


def hash_url(normalized_url: str) -> str:
    """SHA-256 hex digest of the already-normalized URL.

    We hash rather than store the URL so URLCheckRecord never retains a
    reversible copy of what was checked, even for the sanitized version.
    """
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def extract_domain(normalized_url: str) -> str:
    """Bare host, already lowercased by normalize_url — safe to store in the clear."""
    return urlparse(normalized_url).hostname or ""
