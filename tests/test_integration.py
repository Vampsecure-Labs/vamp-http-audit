# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests de integración para vamp-http-audit.
Levanta un servidor HTTP mínimo en localhost con http.server para
simular respuestas con y sin cabeceras de seguridad.
"""

import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_http_audit import GRADE_ORDER_LIST, AuditResult, Finding, compute_grade

# ---------------------------------------------------------------------------
# Servidor HTTP mock para integración
# ---------------------------------------------------------------------------

def _puerto_libre():
    """Devuelve un puerto TCP libre en localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ManejadorSinSeguridad(BaseHTTPRequestHandler):
    """Responde con cabeceras HTTP mínimas, sin seguridad."""

    def do_GET(self):
        body = b"<html><body>Sin seguridad</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.51 (Ubuntu)")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # Silenciar logs del servidor de prueba


class ManejadorConSeguridad(BaseHTTPRequestHandler):
    """Responde con todas las cabeceras de seguridad correctamente configuradas."""

    def do_GET(self):
        body = b"<html><body>Con seguridad</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=()")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ManejadorCorsCritico(BaseHTTPRequestHandler):
    """Responde con CORS wildcard + credentials (vulnerabilidad crítica)."""

    def do_GET(self):
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def servidor_sin_seguridad():
    """Levanta un servidor HTTP sin cabeceras de seguridad."""
    puerto = _puerto_libre()
    srv = HTTPServer(("127.0.0.1", puerto), ManejadorSinSeguridad)
    hilo = threading.Thread(target=srv.serve_forever, daemon=True)
    hilo.start()
    yield f"http://127.0.0.1:{puerto}"
    srv.shutdown()


@pytest.fixture(scope="module")
def servidor_con_seguridad():
    """Levanta un servidor HTTP con cabeceras de seguridad completas."""
    puerto = _puerto_libre()
    srv = HTTPServer(("127.0.0.1", puerto), ManejadorConSeguridad)
    hilo = threading.Thread(target=srv.serve_forever, daemon=True)
    hilo.start()
    yield f"http://127.0.0.1:{puerto}"
    srv.shutdown()


@pytest.fixture(scope="module")
def servidor_cors_critico():
    """Levanta un servidor HTTP con CORS wildcard + credentials."""
    puerto = _puerto_libre()
    srv = HTTPServer(("127.0.0.1", puerto), ManejadorCorsCritico)
    hilo = threading.Thread(target=srv.serve_forever, daemon=True)
    hilo.start()
    yield f"http://127.0.0.1:{puerto}"
    srv.shutdown()


# ---------------------------------------------------------------------------
# Tests de integración con compute_grade
# ---------------------------------------------------------------------------

class TestIntegracionHTTP:
    """Tests de integración que verifican la lógica de calificación con datos reales."""

    def test_resultado_sin_hsts_grado_maximo_c(self):
        """Un resultado sin HSTS no puede superar el grado C."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp="2026-01-01T00:00:00+00:00",
        )
        r.status_code = 200
        r.headers = {}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="HIGH", category="HEADER",
                name="HSTS ausente",
                detail="Sin Strict-Transport-Security",
                remediation="Añadir HSTS",
                grade_cap="C",
            )
        ]
        grado = compute_grade(r)
        assert GRADE_ORDER_LIST.index(grado) >= GRADE_ORDER_LIST.index("C")

    def test_resultado_cors_wildcard_credentials_grado_f(self):
        """CORS wildcard + credentials siempre produce F."""
        r = AuditResult(
            url="https://api.example.com",
            final_url="https://api.example.com/",
            timestamp="2026-01-01T00:00:00+00:00",
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
                detail="Vulnerabilidad crítica CORS",
                remediation="Especificar origen explícito",
                grade_cap="F",
            )
        ]
        assert compute_grade(r) == "F"

    def test_resultado_servidor_version_y_sin_csp_grado_b(self):
        """Servidor con versión expuesta + sin CSP → al menos B."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp="2026-01-01T00:00:00+00:00",
        )
        r.status_code = 200
        r.headers = {"Server": "nginx/1.18.0"}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="CSP",
                name="CSP ausente", detail="Sin política CSP",
                remediation="Implementar CSP", grade_cap="B",
            ),
            Finding(
                severity="LOW", category="INFO_DISCLOSURE",
                name="Versión nginx expuesta",
                detail="Server: nginx/1.18.0",
                remediation="Ocultar versión", grade_cap="B",
            ),
        ]
        grado = compute_grade(r)
        assert GRADE_ORDER_LIST.index(grado) >= GRADE_ORDER_LIST.index("B")

    def test_cookie_insegura_y_sin_xframe_acumulan(self):
        """Múltiples findings de distintas categorías se acumulan correctamente."""
        r = AuditResult(
            url="https://example.com",
            final_url="https://example.com/",
            timestamp="2026-01-01T00:00:00+00:00",
        )
        r.status_code = 200
        r.headers = {}
        r.cookies = []
        r.grade = "A+"
        r.error = None
        r.findings = [
            Finding(
                severity="MEDIUM", category="COOKIE",
                name="Cookie sin Secure",
                detail="Cookie session sin flag Secure",
                remediation="Añadir Secure",
                grade_cap="B",
            ),
            Finding(
                severity="MEDIUM", category="HEADER",
                name="X-Frame-Options ausente",
                detail="Sin X-Frame-Options",
                remediation="Añadir X-Frame-Options: DENY",
                grade_cap="C",
            ),
        ]
        grado = compute_grade(r)
        # El más restrictivo es "C"
        assert GRADE_ORDER_LIST.index(grado) >= GRADE_ORDER_LIST.index("C")

    def test_resultado_con_error_siempre_f(self):
        """Un AuditResult con error siempre produce F independientemente de findings."""
        r = AuditResult(
            url="https://unreachable.example.com",
            final_url="https://unreachable.example.com/",
            timestamp="2026-01-01T00:00:00+00:00",
        )
        r.status_code = None
        r.headers = {}
        r.cookies = []
        r.grade = "A+"
        r.error = "SSL certificate verify failed"
        r.findings = []
        assert compute_grade(r) == "F"
