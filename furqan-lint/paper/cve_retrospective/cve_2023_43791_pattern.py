# Bismillah ir-Rahman ir-Rahim
"""
CVE-2023-43791 pattern: Label Studio hardcoded Django SECRET_KEY.

Label Studio shipped with a hardcoded SECRET_KEY in settings, the same
across all installations. Combined with an ORM leak, this allowed
forging admin session tokens. CVSS 9.8.

Fixed in Label Studio 1.8.2.

furqan-lint rule mapping: TB-024 (hardcoded secret/key/token)
"""

# Vulnerable: hardcoded secret in settings module
SECRET_KEY = "QjA:jk6G}2ncl:6Fv1:80cy;SrdAhIE9LJ^g@XRI1lxV0Yr^FGMly"  # noqa

# Also vulnerable: common Django pattern with placeholder
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "PASSWORD": "mysecretpassword123",  # BUG: hardcoded DB password
    }
}

API_TOKEN = "sk-abc123def456ghi789"  # BUG: hardcoded API key

# Fixed: read from environment
import os
SECRET_KEY_SAFE = os.environ.get("DJANGO_SECRET_KEY", "")
DB_PASSWORD_SAFE = os.environ.get("DB_PASSWORD", "")
# Bismillah ir-Rahman ir-Rahim
