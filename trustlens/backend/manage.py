#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    # Defaults to development settings for local convenience. Production
    # deployments must explicitly set DJANGO_ENVIRONMENT=production (plus
    # DJANGO_SECRET_KEY, DJANGO_ALLOWED_HOSTS, DATABASE_URL — see settings.py)
    # rather than relying on any implicit default.
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "trustlens.settings")
    os.environ.setdefault("DJANGO_ENVIRONMENT", "development")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
