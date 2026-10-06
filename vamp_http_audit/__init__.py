# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_http_audit — Auditor de seguridad HTTP: cabeceras, CORS, cookies, info-disclosure.

Paquete importable. API pública sin cambios respecto a v1.2.0.
  from vamp_http_audit import HTTPAuditor, AuditResult, compute_grade
"""

from ._models import (
    VERSION,
    TOOL_NAME,
    GRADE_ORDER_LIST,
    GRADE_COLOR,
    GRADE_DESCRIPTION,
    HTML_GRADE_COLOR,
    SEVERITY_ORDER,
    SEVERITY_COLOR,
    REDIRECT_PARAMS,
    GRAPHQL_PATHS,
    UNSAFE_REFERRER_POLICIES,
    Finding,
    CookieInfo,
    AuditResult,
)
from ._core import HTTPAuditor, compute_grade
from ._report import to_json, to_html, to_markdown, to_csv, _findings_vsl
from .cli import main

__all__ = [
    # Versión y nombre
    "VERSION",
    "TOOL_NAME",
    # Calificación
    "GRADE_ORDER_LIST",
    "GRADE_COLOR",
    "GRADE_DESCRIPTION",
    "HTML_GRADE_COLOR",
    # Severidad
    "SEVERITY_ORDER",
    "SEVERITY_COLOR",
    # Constantes de checks
    "REDIRECT_PARAMS",
    "GRAPHQL_PATHS",
    "UNSAFE_REFERRER_POLICIES",
    # Tipos de datos
    "Finding",
    "CookieInfo",
    "AuditResult",
    # Motor y calificación
    "HTTPAuditor",
    "compute_grade",
    # Generación de informes
    "to_json",
    "to_html",
    "to_markdown",
    "to_csv",
    "_findings_vsl",
    # CLI
    "main",
]
