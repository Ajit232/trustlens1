"""
Django settings for the TrustLens backend.

This is a single settings module (per the requested project structure),
not split into base/dev/prod files. Dev vs. prod behavior is switched by the
DJANGO_ENVIRONMENT env var instead — everything env-specific still comes
from environment variables, nothing is hardcoded, and there's no scenario
where "the wrong file got imported" the way a settings/ package could allow.
The trade-off: unlike a file split, a stray/misspelled env var falls back to
the dev branch below rather than failing to import a whole module. We treat
that as acceptable here because every *sensitive* prod value (SECRET_KEY,
ALLOWED_HOSTS, DATABASE_URL) still has no insecure default and raises
loudly if missing when DJANGO_ENVIRONMENT=production (see below).
"""

from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env()
env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(str(env_file))

# User-facing product name only (extension display name, admin site
# header). No code branches on this value, so renaming it — as happened
# here, TrustLens -> LinkAegis — never touches settings, models, or URLs,
# only this constant and the extension's manifest.json. The Python package
# is still named "trustlens" throughout the codebase; renaming that too is
# a separate, larger decision (see the Phase 3 delivery notes) and hasn't
# been done here.
PRODUCT_NAME = env("PRODUCT_NAME", default="LinkAegis")

ENVIRONMENT = env("DJANGO_ENVIRONMENT", default="development")
IS_PRODUCTION = ENVIRONMENT == "production"

# --- Secret key ---------------------------------------------------------
if IS_PRODUCTION:
    # No default in production — a missing key must break startup, not
    # silently run with a guessable value.
    SECRET_KEY = env("DJANGO_SECRET_KEY")
else:
    SECRET_KEY = env(
        "DJANGO_SECRET_KEY", default="dev-only-insecure-key-do-not-use-in-prod"
    )

DEBUG = env.bool("DJANGO_DEBUG", default=not IS_PRODUCTION)

# --- Allowed hosts -------------------------------------------------------
if IS_PRODUCTION:
    ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS")  # required, no default
else:
    ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "trustlens.scanner",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "trustlens.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "trustlens.wsgi.application"
ASGI_APPLICATION = "trustlens.asgi.application"

# --- Database --------------------------------------------------------------
# SQLite by default (zero-config local dev). Setting DATABASE_URL switches
# to that database (e.g. PostgreSQL) with no code change — this is what
# "PostgreSQL-ready" means here: the model layer has no SQLite-specific
# assumptions, so pointing DATABASE_URL at Postgres is the only step needed.
if env("DATABASE_URL", default=""):
    DATABASES = {"default": env.db("DATABASE_URL")}
else:
    if IS_PRODUCTION:
        # Don't let production silently fall back to a local SQLite file —
        # that's a dev convenience, not a production data store.
        raise RuntimeError(
            "DATABASE_URL must be set when DJANGO_ENVIRONMENT=production."
        )
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- CORS ------------------------------------------------------------------
# Configured for exactly ONE origin: the extension's own dev origin — never
# a wildcard, and never a list of arbitrary sites. In dev this is the
# unpacked extension's chrome-extension://<id> origin (that id is stable
# for a given unpacked-load path but does vary per machine/checkout — set
# it locally in .env once you've loaded the extension and Chrome shows you
# its id). In production this becomes the one published extension origin.
CORS_ALLOWED_ORIGINS = (
    [env("EXTENSION_DEV_ORIGIN")] if env("EXTENSION_DEV_ORIGIN", default="") else []
)

# --- DRF ---------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    # Anonymous by design — no accounts, no persistent user identifier.
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.AnonRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {
        "anon": env("ANON_RATE_LIMIT", default="60/min"),
        # Scoped rate specifically for POST check-url/ (CheckURLRateThrottle).
        # Separate from the general "anon" rate so it can be tuned
        # independently — check-url is the one endpoint that writes to the
        # database and is the most likely target of abuse.
        "check_url": env("CHECK_URL_RATE_LIMIT", default="30/min"),
    },
    "EXCEPTION_HANDLER": "trustlens.scanner.exceptions.custom_exception_handler",
}

# Default cache lifetime (seconds) the API tells the extension to use for a
# verdict before re-checking. Read by the check-url view via
# settings.CHECK_URL_DEFAULT_CACHE_TTL_SECONDS.
CHECK_URL_DEFAULT_CACHE_TTL_SECONDS = env.int("CHECK_URL_DEFAULT_CACHE_TTL_SECONDS", default=300)

# --- Logging -----------------------------------------------------------
# Explicit, minimal logging config so it's obvious what gets recorded and
# where. The "scanner" logger is what views.py writes to — always with
# structured `extra` fields (domain, url_hash, verdict), never a raw or
# even normalized URL string interpolated into the message itself. This
# config doesn't change that discipline, but keeps the request-log format
# plain so nobody is tempted to add `%(request)s`-style raw dumps later.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "loggers": {
        "scanner": {
            "handlers": ["console"],
            "level": env("SCANNER_LOG_LEVEL", default="INFO"),
        },
    },
}

# --- Production-only hardening ---------------------------------------------
if IS_PRODUCTION:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
