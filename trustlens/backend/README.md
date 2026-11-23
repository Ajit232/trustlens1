# LinkAegis Backend

Django + Django REST Framework backend for the LinkAegis Chrome extension
(formerly "TrustLens" — see the naming note below).

**Detection is not implemented yet.** `POST /api/v1/check-url/` validates,
normalizes, and sanitizes the URL, and always returns a stubbed `"unknown"`
verdict with confidence `0`. That's intentional — see "Why the verdict is
always unknown" below.

## Naming note

The product name changed from TrustLens to LinkAegis. The Python package
and app are still named `trustlens` throughout the codebase (e.g.
`trustlens.settings`, `trustlens.scanner`) — only the user-facing
`PRODUCT_NAME` setting changed. This was a deliberate original design
choice (see the Phase 0 design doc's naming-flexibility note) specifically
so a rename like this wouldn't require touching imports, migrations, or
the URL structure. Renaming the package itself is a separate, larger
change and hasn't been done here — flag it explicitly if you want that
follow-up.

## Project layout

```
backend/
├── manage.py
├── requirements.txt
├── .env.example
├── README.md          (this file)
└── trustlens/
    ├── settings.py     # single settings module, env-driven (see below)
    ├── urls.py
    ├── wsgi.py
    ├── asgi.py
    └── scanner/        # the one Django app: models, views, serializers, tests
```

## Installation

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env            # edit if you want a non-default SECRET_KEY

python manage.py migrate
python manage.py createsuperuser   # optional, for /admin/
python manage.py runserver
```

The API is now at `http://localhost:8000/api/v1/`.

```bash
curl -X POST http://localhost:8000/api/v1/check-url/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/path", "source": "gmail"}'
```

## Running tests

```bash
python manage.py test
```

## Configuration: development vs. production

Settings live in one file (`trustlens/settings.py`), switched by the
`DJANGO_ENVIRONMENT` environment variable rather than separate files. Every
value that matters for security has no insecure fallback once
`DJANGO_ENVIRONMENT=production` — the app refuses to start rather than
running with a guessable secret key or a local SQLite file in prod.

**Development example** (`.env`):
```env
DJANGO_ENVIRONMENT=development
DJANGO_SECRET_KEY=any-value-for-local-use
CORS_ALLOWED_ORIGINS=
```
`DJANGO_DEBUG` defaults to `True`, `ALLOWED_HOSTS` defaults to
`localhost,127.0.0.1`, and the database defaults to a local `db.sqlite3` —
none of these need to be set explicitly for local work.

**Production example** (real environment variables, not a committed file):
```env
DJANGO_ENVIRONMENT=production
DJANGO_SECRET_KEY=<a long random value>
DJANGO_ALLOWED_HOSTS=api.trustlens.example
DATABASE_URL=postgres://user:password@host:5432/trustlens
CORS_ALLOWED_ORIGINS=chrome-extension://<published-extension-id>
```
In production, `DJANGO_SECRET_KEY`, `DJANGO_ALLOWED_HOSTS`, and
`DATABASE_URL` are all required — the app raises on startup if any are
missing, rather than silently falling back to a dev-shaped config.
See `.env.example` for the full annotated list.

PostgreSQL isn't installed by default — add `psycopg[binary]` to
`requirements.txt` when you're actually ready to deploy against
`DATABASE_URL`.

## Why the verdict is always "unknown"

The project's rule is *treat unknown results as unknown, not safe*. A stub
with no real analysis logic has no basis to call anything safe, so it must
not return `"safe"`. Real detection (the rule-based scoring engine) is a
later phase, layered on top of this same request/response shape without
changing the API contract.

## What Phase 3 added

- Real URL normalization: lowercases scheme/host, strips default ports,
  strips the fragment, and strips a deny-list of sensitive query
  parameters (tokens, session ids, passwords, etc.) — see
  `scanner/normalization.py`.
- Input rejected outright (HTTP 400) for: unsupported schemes, missing
  host, embedded credentials (`https://user:pass@host/`), and
  loopback/private/link-local hosts.
- A dedicated rate limit for `check-url/` (`CHECK_URL_RATE_LIMIT`, default
  `30/min`), separate from the general anonymous rate.
- A structured error envelope for every error response — see
  `scanner/exceptions.py`.
- CORS restricted to exactly one configured origin
  (`EXTENSION_DEV_ORIGIN`) — no wildcard, no origin list.
- Safe logging: `views.py` only ever logs a domain and a URL hash, never a
  raw or normalized URL, and never a query string.
- A `UserReport` model for future user-submitted reports. **No endpoint
  exposes it yet** — this phase only adds the schema; a public report
  endpoint needs its own abuse-resistance work (validating the report
  references a real prior check, rate limiting, spam mitigation) before
  it should be exposed.

One migration note: because the `verdict` and `confidence` field
definitions changed (string enum → renamed choices / int), the Phase 1/2
migration was replaced with a fresh initial migration rather than an
incremental one. This is safe because no production data exists yet: if
this were already deployed, that data loss would need to be called out
explicitly and handled with a real migration instead.

## Extension

The companion Chrome extension lives in `../extension/`. It talks to
whatever backend is configured in its options page (`http://localhost:8000`
by default, matching this server). See `../extension/` and the setup
instructions provided alongside it for loading it in Chrome.
