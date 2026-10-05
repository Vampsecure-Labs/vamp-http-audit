# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Fixtures compartidos para los tests de vamp-http-audit.
Proporciona AuditResult simulados, cabeceras HTTP típicas y objetos Finding/CookieInfo.
"""

import sys
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_http_audit import AuditResult, Finding, CookieInfo, compute_grade


# ---------------------------------------------------------------------------
# Fixtures de cabeceras HTTP
# ---------------------------------------------------------------------------

@pytest.fixture()
def cabeceras_seguras():
    """Cabeceras HTTP con todas las medidas de seguridad configuradas."""
    return {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }


@pytest.fixture()
def cabeceras_sin_seguridad():
    """Cabeceras HTTP sin ninguna cabecera de seguridad."""
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "Apache/2.4.51 (Ubuntu)",
    }


@pytest.fixture()
def cabeceras_cors_wildcard():
    """Cabeceras con CORS wildcard."""
    return {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
    }


@pytest.fixture()
def cabeceras_cors_credenciales():
    """Cabeceras con CORS wildcard + credentials (vulnerabilidad crítica)."""
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Fixtures de cookies
# ---------------------------------------------------------------------------

@pytest.fixture()
def cookie_segura():
    """Cookie con todos los flags de seguridad correctos."""
    return CookieInfo(
        name="session",
        value_preview="abc123",
        secure=True,
        httponly=True,
        samesite="Strict",
        path="/",
        domain="",
        host_prefix=False,
        secure_prefix=False,
    )


@pytest.fixture()
def cookie_insegura():
    """Cookie sin flags de seguridad."""
    return CookieInfo(
        name="tracking",
        value_preview="xyz",
        secure=False,
        httponly=False,
        samesite=None,
        path="/",
        domain="",
        host_prefix=False,
        secure_prefix=False,
    )


# ---------------------------------------------------------------------------
# Fixtures de AuditResult
# ---------------------------------------------------------------------------

@pytest.fixture()
def resultado_http_limpio():
    """AuditResult HTTP sin hallazgos de seguridad → grado A+."""
    r = AuditResult(
        url="https://example.com",
        final_url="https://example.com/",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    r.status_code = 200
    r.headers = {}
    r.cookies = []
    r.findings = []
    r.grade = "A+"
    r.error = None
    return r


@pytest.fixture()
def resultado_http_con_hallazgos():
    """AuditResult HTTP con varios hallazgos de seguridad."""
    r = AuditResult(
        url="https://example.com",
        final_url="https://example.com/",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    r.status_code = 200
    r.headers = {}
    r.cookies = []
    r.findings = [
        Finding(
            severity="HIGH",
            category="HEADER",
            name="HSTS ausente",
            detail="No se encontró Strict-Transport-Security",
            remediation="Añadir cabecera HSTS con max-age >= 15552000",
            grade_cap="C",
        ),
        Finding(
            severity="MEDIUM",
            category="HEADER",
            name="CSP ausente",
            detail="No se encontró Content-Security-Policy",
            remediation="Implementar política CSP restrictiva",
            grade_cap="B",
        ),
    ]
    r.grade = "A+"
    r.error = None
    return r
