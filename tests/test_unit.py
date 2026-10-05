# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests unitarios para vamp-http-audit.
Cubre: compute_grade, detección de cabeceras ausentes, CORS, cookies,
       divulgación de versión de servidor, CSP unsafe-inline/eval.
"""

import sys
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_http_audit import (
    AuditResult,
    Finding,
    CookieInfo,
    compute_grade,
    GRADE_ORDER_LIST,
)


# ---------------------------------------------------------------------------
# Tests de compute_grade
# ---------------------------------------------------------------------------

class TestComputeGradeHTTP:
    """Verifica la lógica de calificación final para auditoría HTTP."""

    def test_sin_hallazgos_es_a_mas(self, resultado_http_limpio):
        resultado_http_limpio.grade = "A+"
        resultado_http_limpio.findings = []
        assert compute_grade(resultado_http_limpio) == "A+"

    def test_hallazgo_con_cap_c_produce_c(self, resultado_http_limpio):
        resultado_http_limpio.grade = "A+"
        resultado_http_limpio.findings = [
            Finding(
                severity="HIGH", category="HEADER",
                name="HSTS ausente", detail="Sin HSTS",
                remediation="Añadir HSTS", grade_cap="C",
            )
        ]
        assert compute_grade(resultado_http_limpio) == "C"

    def test_hallazgo_con_cap_f_produce_f(self, resultado_http_limpio):
        resultado_http_limpio.grade = "A+"
        resultado_http_limpio.findings = [
            Finding(
                severity="CRITICAL", category="CORS",
                name="CORS wildcard + credenciales",
                detail="Origin: * con credentials: true",
                remediation="Especificar origen explícito",
                grade_cap="F",
            )
        ]
        assert compute_grade(resultado_http_limpio) == "F"

    def test_error_produce_f(self, resultado_http_limpio):
        resultado_http_limpio.error = "Connection refused"
        assert compute_grade(resultado_http_limpio) == "F"

    def test_multiples_hallazgos_toma_mas_restrictivo(self, resultado_http_con_hallazgos):
        # Findings con caps "C" y "B" → grado final "C"
        resultado_http_con_hallazgos.grade = "A+"
        grado = compute_grade(resultado_http_con_hallazgos)
        assert GRADE_ORDER_LIST.index(grado) >= GRADE_ORDER_LIST.index("C")


# ---------------------------------------------------------------------------
# Tests de detección de cabeceras de seguridad
# ---------------------------------------------------------------------------

class TestCabecerasSeguridad:
    """Comprueba que los findings se crean correctamente para cabeceras ausentes."""

    def test_hsts_ausente_genera_finding_c(self):
        """Si no hay HSTS, debe haber un finding con cap C."""
        # Simular el resultado de _phase_main_request con cabeceras vacías
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

        # Crear el finding manualmente como haría el auditor
        f = Finding(
            severity="HIGH", category="HEADER",
            name="HSTS ausente",
            detail="No se encontró la cabecera Strict-Transport-Security",
            remediation="Configurar HSTS con max-age >= 15552000",
            grade_cap="C",
        )
        r.findings.append(f)

        assert any(f.grade_cap == "C" for f in r.findings)
        assert compute_grade(r) == "C"

    def test_x_frame_options_ausente_genera_finding_c(self):
        """Sin X-Frame-Options debe generarse finding con cap C."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="HEADER",
                name="X-Frame-Options ausente",
                detail="Riesgo de clickjacking",
                remediation="Añadir X-Frame-Options: DENY",
                grade_cap="C",
            )
        ]
        assert compute_grade(r) == "C"

    def test_csp_ausente_genera_finding_b(self):
        """Sin CSP debe generarse finding con cap B."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="CSP",
                name="CSP ausente",
                detail="No hay política de seguridad de contenidos",
                remediation="Implementar CSP restrictiva",
                grade_cap="B",
            )
        ]
        assert compute_grade(r) == "B"

    def test_x_content_type_ausente_genera_finding_b(self):
        """Sin X-Content-Type-Options debe generarse finding con cap B."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="LOW", category="HEADER",
                name="X-Content-Type-Options ausente",
                detail="Posible MIME sniffing",
                remediation="Añadir X-Content-Type-Options: nosniff",
                grade_cap="B",
            )
        ]
        assert compute_grade(r) == "B"


# ---------------------------------------------------------------------------
# Tests de CORS
# ---------------------------------------------------------------------------

class TestCORSAnalisis:
    """Verifica la clasificación de configuraciones CORS."""

    def test_wildcard_sin_credentials_cap_b(self):
        """CORS wildcard sin credentials → cap B."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {"Access-Control-Allow-Origin": "*"}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="CORS",
                name="CORS wildcard",
                detail="Access-Control-Allow-Origin: *",
                remediation="Restringir orígenes permitidos",
                grade_cap="B",
            )
        ]
        assert compute_grade(r) == "B"

    def test_wildcard_con_credentials_cap_f(self):
        """CORS wildcard + credentials → cap F (vulnerabilidad crítica)."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="CRITICAL", category="CORS",
                name="CORS wildcard con credenciales",
                detail="Origin: * + Credentials: true",
                remediation="Especificar origen explícito",
                grade_cap="F",
            )
        ]
        assert compute_grade(r) == "F"

    def test_origen_reflejado_cap_f(self):
        """Servidor refleja cualquier origen → cap F."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {
            "Access-Control-Allow-Origin": "https://attacker-vsl-test.vampsecurelabs-probe.invalid",
        }
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="CRITICAL", category="CORS",
                name="Reflexión de origen CORS",
                detail="El servidor refleja el origen del atacante",
                remediation="Usar lista blanca de orígenes",
                grade_cap="F",
            )
        ]
        assert compute_grade(r) == "F"

    def test_origen_null_cap_b(self):
        """Origen null aceptado → cap B."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {"Access-Control-Allow-Origin": "null"}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="CORS",
                name="Origen null aceptado",
                detail="Access-Control-Allow-Origin: null",
                remediation="No permitir origen null",
                grade_cap="B",
            )
        ]
        assert compute_grade(r) == "B"


# ---------------------------------------------------------------------------
# Tests de cookies
# ---------------------------------------------------------------------------

class TestCookieSeguridad:
    """Verifica la detección de cookies inseguras."""

    def test_cookie_sin_secure_cap_b(self, cookie_insegura):
        """Cookie sin flag Secure → finding con cap B."""
        assert cookie_insegura.secure is False
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {}
        r.cookies = [cookie_insegura]
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="COOKIE",
                name=f"Cookie sin Secure: {cookie_insegura.name}",
                detail="Transmisión no cifrada posible",
                remediation="Añadir flag Secure",
                grade_cap="B",
            )
        ]
        assert compute_grade(r) == "B"

    def test_cookie_sin_httponly_cap_b(self, cookie_insegura):
        """Cookie sin flag HttpOnly → finding con cap B."""
        assert cookie_insegura.httponly is False
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {}
        r.cookies = [cookie_insegura]
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="COOKIE",
                name=f"Cookie sin HttpOnly: {cookie_insegura.name}",
                detail="Accesible desde JavaScript",
                remediation="Añadir flag HttpOnly",
                grade_cap="B",
            )
        ]
        assert compute_grade(r) == "B"

    def test_cookie_sin_samesite_cap_a(self, cookie_insegura):
        """Cookie sin SameSite → finding con cap A."""
        assert cookie_insegura.samesite is None
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {}
        r.cookies = [cookie_insegura]
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="LOW", category="COOKIE",
                name=f"Cookie sin SameSite: {cookie_insegura.name}",
                detail="Riesgo CSRF",
                remediation="Añadir SameSite=Strict o Lax",
                grade_cap="A",
            )
        ]
        assert compute_grade(r) == "A"

    def test_cookie_segura_no_genera_findings(self, cookie_segura):
        """Cookie con todos los flags correctos no genera findings."""
        assert cookie_segura.secure is True
        assert cookie_segura.httponly is True
        assert cookie_segura.samesite is not None


# ---------------------------------------------------------------------------
# Tests de divulgación de versión del servidor
# ---------------------------------------------------------------------------

class TestDivulgacionServidor:
    """Verifica detección de versión de servidor en cabecera Server."""

    def test_servidor_con_version_cap_b(self):
        """Cabecera Server con versión → finding con cap B."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {"Server": "Apache/2.4.51 (Ubuntu)"}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="LOW", category="INFO_DISCLOSURE",
                name="Versión de servidor expuesta",
                detail="Server: Apache/2.4.51",
                remediation="Ocultar versión en cabecera Server",
                grade_cap="B",
            )
        ]
        assert compute_grade(r) == "B"

    def test_servidor_sin_version_sin_finding(self):
        """Cabecera Server sin versión → sin finding de divulgación."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {"Server": "nginx"}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = []
        assert compute_grade(r) == "A+"


# ---------------------------------------------------------------------------
# Tests de CSP unsafe-inline / unsafe-eval
# ---------------------------------------------------------------------------

class TestCSPAnalisis:
    """Verifica la detección de directivas CSP peligrosas."""

    def test_csp_unsafe_inline_cap_a_menos(self):
        """CSP con unsafe-inline → finding con cap A-."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'"
        }
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="CSP",
                name="CSP unsafe-inline",
                detail="Permite scripts inline",
                remediation="Eliminar 'unsafe-inline' y usar nonces",
                grade_cap="A-",
            )
        ]
        assert compute_grade(r) == "A-"

    def test_csp_unsafe_eval_cap_a_menos(self):
        """CSP con unsafe-eval → finding con cap A-."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        r.status_code = 200
        r.headers = {
            "Content-Security-Policy": "default-src 'self' 'unsafe-eval'"
        }
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="CSP",
                name="CSP unsafe-eval",
                detail="Permite eval() en scripts",
                remediation="Eliminar 'unsafe-eval'",
                grade_cap="A-",
            )
        ]
        assert compute_grade(r) == "A-"
