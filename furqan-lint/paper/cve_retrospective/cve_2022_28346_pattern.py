# Bismillah ir-Rahman ir-Rahim
"""
CVE-2022-28346 pattern: Django SQL injection via **kwargs in QuerySet.

The vulnerable pattern: crafted dictionary keys passed via **kwargs to
annotate(), aggregate(), or extra() became column aliases without
sanitization. Attacker controls dict keys → SQL injection.

CVSS: 9.8 (Critical). Fixed in Django 2.2.28, 3.2.13, 4.0.4.

furqan-lint rule mapping: MISS -- SI-005 detects **kwargs in function
definitions, not at call sites. TB-018 detects f-string SQL, not ORM kwargs.
This CVE falls in a gap: furqan-lint does not currently detect unsanitized
dict keys passed to ORM methods.
"""

def get_aggregated_data_vulnerable(request):
    """Vulnerable: user-controlled kwargs forwarded to ORM."""
    from django.db.models import Count
    # Attacker sends: {"injected_col'); DROP TABLE auth_user; --": "id"}
    user_params = request.GET.dict()
    annotations = {k: Count(v) for k, v in user_params.items()}
    # BUG: **kwargs forwarded without key sanitization
    return MyModel.objects.annotate(**annotations).values()

def get_aggregated_data_fixed(request):
    """Fixed: validate annotation keys against allowlist."""
    from django.db.models import Count
    ALLOWED_ANNOTATIONS = {"total_count", "avg_score", "max_date"}
    user_params = request.GET.dict()
    annotations = {}
    for k, v in user_params.items():
        if k not in ALLOWED_ANNOTATIONS:
            raise ValueError(f"Invalid annotation key: {k}")
        if v not in {"id", "score", "date"}:
            raise ValueError(f"Invalid annotation field: {v}")
        annotations[k] = Count(v)
    return MyModel.objects.annotate(**annotations).values()

class MyModel:
    objects = None
# Bismillah ir-Rahman ir-Rahim
