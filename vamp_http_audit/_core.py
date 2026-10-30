# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_core.py — Motor de auditoría HTTP (lógica pura, sin I/O ni presentación).
Implementa HTTPAuditor y las funciones de calificación A+→F.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from ._models import (
    VERSION,
    GRADE_ORDER_LIST,
    REDIRECT_PARAMS,
    GRAPHQL_PATHS,
    UNSAFE_REFERRER_POLICIES,
    _R_CSP_ABSENT,
    _R_CSP_UNSAFE_INLINE,
    _R_CSP_UNSAFE_EVAL,
    _R_CSP_WILDCARD,
    _R_CSP_NO_FRAME_ANCESTORS,
    _R_HSTS_ABSENT,
    _R_XFO_ABSENT,
    _R_XCTO_ABSENT,
    _R_RP_ABSENT,
    _R_PP_ABSENT,
    _R_COEP_ABSENT,
    _R_COOP_ABSENT,
    _R_CORP_ABSENT,
    _R_CORS_WILDCARD_CREDS,
    _R_CORS_WILDCARD,
    _R_CORS_REFLECT,
    _R_CORS_NULL,
    _R_COOKIE_NOSECURE,
    _R_COOKIE_NOHTTPONLY,
    _R_COOKIE_NOSAMESITE,
    _R_SERVER_VERSION,
    _R_XPOWEREDBY,
    _R_DEBUG_HEADER,
    _R_OPEN_REDIRECT,
    _R_GRAPHQL_INTROSPECTION,
    Finding,
    CookieInfo,
    AuditResult,
    _T,
)

# ---------------------------------------------------------------------------
# Lógica de calificación
# ---------------------------------------------------------------------------

def _apply_cap(current: str, cap: str) -> str:
    """Aplica un cap: devuelve la nota más restrictiva."""
    ci = GRADE_ORDER_LIST.index(current) if current in GRADE_ORDER_LIST else 0
    ca = GRADE_ORDER_LIST.index(cap)     if cap     in GRADE_ORDER_LIST else 0
    return GRADE_ORDER_LIST[max(ci, ca)]


def compute_grade(result: AuditResult) -> str:
    """
    Calcula la calificación HTTP SSLabs-style.

    Caps aplicados:
      F : CORS wildcard + credenciales · open redirect confirmado
      C : X-Frame-Options ausente sin frame-ancestors · HSTS ausente
      B : CSP ausente · X-Content-Type-Options ausente · versión del servidor expuesta
          · cookie sin Secure / HttpOnly · CORS wildcard sin credenciales
      A : CORS wildcard sin credenciales · SameSite ausente en cookies
          · cabeceras COOP/COEP/CORP ausentes · Referrer-Policy ausente
      A-: CSP con unsafe-inline/eval/wildcard · Referrer-Policy insegura
          · Permissions-Policy ausente
      A+: Todo en orden
    """
    if result.error:
        return "F"

    grade = "A+"
    for f in result.findings:
        if f.grade_cap:
            grade = _apply_cap(grade, f.grade_cap)
    return grade


# ---------------------------------------------------------------------------
# Motor de auditoría HTTP
# ---------------------------------------------------------------------------

class HTTPAuditor:
    """
    Motor de auditoría de seguridad HTTP.

    Fases de análisis:
      1. Petición principal + cabeceras de seguridad
      2. Análisis profundo de Content-Security-Policy
      3. Prueba de misconfiguraciones CORS
      4. Seguridad de cookies (flags y prefijos)
      5. Filtración de información técnica
      6. Detección de open redirect
    """

    # Origin ficticio para las pruebas CORS
    _CORS_TEST_ORIGIN = "https://attacker-vsl-test.vampsecurelabs-probe.invalid"

    def __init__(self, timeout: int = 10, verify_ssl: bool = False, active: bool = False) -> None:
        self._timeout    = timeout
        self._verify_ssl = verify_ssl
        # Bandera para activar pruebas activas (IDOR, Host Header, Open Redirect avanzado)
        self._active     = active
        # Contexto SSL sin verificación para pruebas (no usamos los datos del cert)
        self._ssl_ctx    = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    # ------------------------------------------------------------------ API pública

    def audit(self, url: str) -> AuditResult:
        """Audita una URL completa. Devuelve AuditResult con todos los hallazgos."""
        result = AuditResult(url=url, final_url=url, timestamp=datetime.now(timezone.utc).isoformat())
        try:
            self._phase_main_request(result)
            if not result.error:
                self._phase_csp_analysis(result)
                self._phase_cors(result)
                self._phase_cookies(result)
                self._phase_info_disclosure(result)
                self._phase_open_redirect(result)
                self._phase_graphql(result)
                # Pruebas activas: solo si se habilitó --active
                if self._active:
                    self._probe_idor(result)
                    self._probe_host_header_injection(result)
                    self._probe_open_redirect_active(result)
                    self._probe_php_active(result)
        except Exception as exc:
            result.error = str(exc)
        finally:
            result.findings.sort(key=lambda f: f.order)
            result.grade = compute_grade(result)
        return result

    # --------------------------------------------------------- Utilidad de petición

    def _fetch(
        self,
        url: str,
        method: str = "GET",
        extra_headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """
        Realiza una petición HTTP y devuelve (status_code, headers_dict, body).
        headers_dict normaliza todas las claves a minúsculas.
        """
        req = urllib.request.Request(url, method=method, data=body)
        req.add_header("User-Agent", f"VampSecureLabs-HTTPAudit/{VERSION}")
        req.add_header("Accept", "*/*")
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)

        if not follow_redirects:
            # Interceptar redirecciones manualmente
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None

            opener = urllib.request.build_opener(
                _NoRedirect,
                urllib.request.HTTPSHandler(context=self._ssl_ctx),
            )
        else:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ssl_ctx),
            )

        try:
            with opener.open(req, timeout=self._timeout) as resp:
                status   = resp.status
                hdrs     = {k.lower(): v for k, v in resp.headers.items()}
                # set-cookie puede haber múltiples; getallmatchingheaders no existe en urllib
                # Extraer manualmente las líneas raw de Set-Cookie
                set_cookies = resp.headers.get_all("Set-Cookie") or []
                hdrs["_set_cookie_list"] = "|||".join(set_cookies)
                body_bytes = resp.read(65536)  # Limitado para evitar descargas enormes
            return status, hdrs, body_bytes
        except urllib.error.HTTPError as exc:
            hdrs = {k.lower(): v for k, v in exc.headers.items()}
            return exc.code, hdrs, b""

    # --------------------------------------------------------- Fase 1: petición principal + cabeceras

    def _phase_main_request(self, result: AuditResult) -> None:
        """Petición principal y análisis de cabeceras de seguridad."""
        try:
            status, headers, body = self._fetch(result.url, method="GET", follow_redirects=True)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"No se puede conectar: {exc.reason}") from exc
        except OSError as exc:
            raise RuntimeError(f"Error de red: {exc}") from exc

        result.status_code = status
        result.headers     = headers
        result._raw_body   = body

        h = headers  # Alias corto

        # --- Strict-Transport-Security ---
        hsts = h.get("strict-transport-security")
        if not hsts:
            result.findings.append(Finding(
                severity="HIGH", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                name=str(_T("HSTS absent", "HSTS ausente")),
                detail=str(_T("Missing Strict-Transport-Security — downgrade attacks possible", "Falta Strict-Transport-Security — posibles ataques de downgrade")),
                remediation=str(_R_HSTS_ABSENT), grade_cap="C",
            ))
        else:
            max_age = 0
            for part in hsts.split(";"):
                p = part.strip()
                if p.lower().startswith("max-age="):
                    try:
                        max_age = int(p.split("=", 1)[1].strip())
                    except ValueError:
                        pass
            if max_age < 10_886_400:
                result.findings.append(Finding(
                    severity="MEDIUM", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                    name=str(_T("HSTS max-age insufficient", "HSTS max-age insuficiente")),
                    detail=str(_T(f"max-age={max_age}s — recommended minimum 180 days (15 552 000s)", f"max-age={max_age}s — mínimo recomendado 180 días (15 552 000s)")),
                    remediation=str(_R_HSTS_ABSENT), grade_cap="A-",
                ))

        # --- X-Frame-Options ---
        xfo = h.get("x-frame-options")
        if not xfo:
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                name=str(_T("X-Frame-Options absent", "X-Frame-Options ausente")),
                detail=str(_T("No protection against clickjacking via iframes (no X-Frame-Options or frame-ancestors)", "Sin protección contra clickjacking mediante iframes (sin X-Frame-Options ni frame-ancestors)")),
                remediation=str(_R_XFO_ABSENT), grade_cap="C",
            ))
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            result.findings.append(Finding(
                severity="LOW", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                name=str(_T(f"X-Frame-Options non-standard value: {xfo}", f"X-Frame-Options con valor no estándar: {xfo}")),
                detail=str(_T("Unknown value — browsers will ignore it", "Valor desconocido — los navegadores lo ignorarán")),
                remediation=str(_R_XFO_ABSENT),
            ))

        # --- X-Content-Type-Options ---
        xcto = h.get("x-content-type-options")
        if not xcto:
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                name=str(_T("X-Content-Type-Options absent", "X-Content-Type-Options ausente")),
                detail=str(_T("Possible MIME-type sniffing by the browser", "Posible MIME-type sniffing por el navegador")),
                remediation=str(_R_XCTO_ABSENT), grade_cap="B",
            ))
        elif xcto.lower() != "nosniff":
            result.findings.append(Finding(
                severity="LOW", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                name=f"X-Content-Type-Options incorrecto: {xcto}",
                detail=str(_T("The only valid value is 'nosniff'", "El único valor válido es 'nosniff'")),
                remediation=str(_R_XCTO_ABSENT),
            ))

        # --- Referrer-Policy ---
        rp = h.get("referrer-policy")
        if not rp:
            result.findings.append(Finding(
                severity="LOW", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                name=str(_T("Referrer-Policy absent", "Referrer-Policy ausente")),
                detail=str(_T("The browser uses the default policy — may leak full URLs to third parties", "El navegador usa la política por defecto — puede filtrar URLs completas a terceros")),
                remediation=str(_R_RP_ABSENT), grade_cap="A",
            ))
        elif rp.lower() in UNSAFE_REFERRER_POLICIES:
            result.findings.append(Finding(
                severity="LOW", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                name=f"Referrer-Policy insegura: {rp}",
                detail=str(UNSAFE_REFERRER_POLICIES[rp.lower()]),
                remediation=str(_R_RP_ABSENT), grade_cap="A-",
            ))

        # --- Permissions-Policy ---
        pp = h.get("permissions-policy") or h.get("feature-policy")
        if not pp:
            result.findings.append(Finding(
                severity="LOW", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                name=str(_T("Permissions-Policy absent", "Permissions-Policy ausente")),
                detail=str(_T("No browser API control (camera, microphone, geolocation, etc.)", "Sin control de APIs del navegador (cámara, micrófono, geolocalización, etc.)")),
                remediation=str(_R_PP_ABSENT), grade_cap="A-",
            ))
        else:
            # Parsear directivas y alertar si APIs sensibles no están restringidas
            apis_sensibles = ["geolocation", "camera", "microphone"]
            sin_restriccion: list[str] = []
            pp_lower = pp.lower()
            for api in apis_sensibles:
                if api not in pp_lower:
                    # La directiva no aparece — API no controlada explícitamente
                    sin_restriccion.append(api)
                else:
                    # Buscar si tiene valor restrictivo: api=() o api=(self) o api=self
                    m = re.search(rf'{api}\s*=\s*\(([^)]*)\)', pp_lower)
                    if m:
                        val = m.group(1).strip()
                        # () o (self) son restrictivos; cualquier otra cosa es permisivo
                        if val not in ("", "self"):
                            sin_restriccion.append(api)
                    elif re.search(rf'{api}\s*=\s*\*', pp_lower):
                        # api=* es explícitamente permisivo
                        sin_restriccion.append(api)
            if sin_restriccion:
                result.findings.append(Finding(
                    severity="LOW", category=str(_T("HTTP Headers", "Cabeceras HTTP")),
                    name=str(_T("Permissions-Policy: sensitive APIs without explicit restriction", "Permissions-Policy: APIs sensibles sin restricción explícita")),
                    detail=(
                        f"Las siguientes APIs del navegador no están explícitamente restringidas "
                        f"a '()' o '(self)' en Permissions-Policy: {', '.join(sin_restriccion)}. "
                        "Cualquier script en la página podría acceder a ellas."
                    ),
                    remediation=str(_R_PP_ABSENT),
                ))

        # ── Sección: Aislamiento Cross-Origin (COEP / COOP / CORP) ─────────────

        # --- Cross-Origin-Embedder-Policy ---
        coep = h.get("cross-origin-embedder-policy")
        if not coep:
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("Cross-Origin Isolation", "Aislamiento Cross-Origin")),
                name=str(_T("COEP absent", "COEP ausente")),
                detail=(
                    "Cross-Origin-Embedder-Policy no configurada. "
                    "Sin esta cabecera el navegador no aísla el contexto de navegación, "
                    "impidiendo el uso seguro de SharedArrayBuffer y dificultando "
                    "la mitigación de ataques Spectre cross-origin."
                ),
                remediation=str(_R_COEP_ABSENT), grade_cap="B",
            ))
        elif coep.lower() not in ("require-corp", "credentialless"):
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("Cross-Origin Isolation", "Aislamiento Cross-Origin")),
                name=f"COEP con valor no restrictivo: {coep!r}",
                detail=(
                    f"Cross-Origin-Embedder-Policy está configurada con valor '{coep}', "
                    "que no proporciona aislamiento completo. "
                    "Se recomienda 'require-corp' o 'credentialless'."
                ),
                remediation=str(_R_COEP_ABSENT), grade_cap="B",
            ))

        # --- Cross-Origin-Opener-Policy ---
        coop = h.get("cross-origin-opener-policy")
        if not coop:
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("Cross-Origin Isolation", "Aislamiento Cross-Origin")),
                name=str(_T("COOP absent", "COOP ausente")),
                detail=(
                    "Cross-Origin-Opener-Policy no configurada. "
                    "Sin esta cabecera la página comparte grupo de contexto de navegación "
                    "con ventanas de otros orígenes, facilitando ataques Spectre y "
                    "el robo de información mediante canales de tiempo."
                ),
                remediation=str(_R_COOP_ABSENT), grade_cap="B",
            ))
        elif "same-origin" not in coop.lower():
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("Cross-Origin Isolation", "Aislamiento Cross-Origin")),
                name=f"COOP con valor no restrictivo: {coop!r}",
                detail=(
                    f"Cross-Origin-Opener-Policy está configurada con valor '{coop}', "
                    "que no proporciona aislamiento completo del grupo de contexto. "
                    "Se recomienda 'same-origin'."
                ),
                remediation=str(_R_COOP_ABSENT), grade_cap="B",
            ))

        # --- Cross-Origin-Resource-Policy ---
        corp = h.get("cross-origin-resource-policy")
        if not corp:
            result.findings.append(Finding(
                severity="LOW", category=str(_T("Cross-Origin Isolation", "Aislamiento Cross-Origin")),
                name=str(_T("CORP absent", "CORP ausente")),
                detail=(
                    "Cross-Origin-Resource-Policy no configurada. "
                    "Cualquier origen puede incluir estos recursos (imágenes, scripts, etc.) "
                    "en su contexto, facilitando ataques de filtración de datos cross-origin."
                ),
                remediation=str(_R_CORP_ABSENT), grade_cap="A",
            ))
        elif corp.lower() == "cross-origin":
            result.findings.append(Finding(
                severity="INFO", category=str(_T("Cross-Origin Isolation", "Aislamiento Cross-Origin")),
                name=str(_T("CORP: cross-origin (public resource)", "CORP: cross-origin (recurso público)")),
                detail="Intencionalmente accesible desde cualquier origen",
            ))

        # --- Content-Security-Policy (presencia) ---
        csp = h.get("content-security-policy")
        if not csp:
            result.findings.append(Finding(
                severity="HIGH", category=str(_T("CSP", "CSP")),
                name=str(_T("Content-Security-Policy absent", "Content-Security-Policy ausente")),
                detail=str(_T("No CSP — no protection against script injection (XSS), clickjacking or data theft", "Sin CSP — sin protección contra inyección de scripts (XSS), clickjacking y data theft")),
                remediation=str(_R_CSP_ABSENT), grade_cap="B",
            ))

    # --------------------------------------------------------- Fase 2: análisis CSP

    def _phase_csp_analysis(self, result: AuditResult) -> None:
        """Análisis profundo de la política Content-Security-Policy."""
        csp = result.headers.get("content-security-policy")
        if not csp:
            return  # Hallazgo de ausencia ya añadido en phase 1

        # Parsear directivas
        directives: dict[str, list[str]] = {}
        for directive in csp.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                name   = parts[0].lower()
                values = [v.lower() for v in parts[1:]]
                directives[name] = values

        # Determinar script-src efectivo (fallback a default-src)
        script_src = directives.get("script-src") or directives.get("default-src") or []
        style_src  = directives.get("style-src")  or directives.get("default-src") or []
        directives.get("default-src") or []

        # unsafe-inline
        if "'unsafe-inline'" in script_src:
            result.findings.append(Finding(
                severity="HIGH", category=str(_T("CSP", "CSP")),
                name=str(_T("CSP: 'unsafe-inline' in script-src", "CSP: 'unsafe-inline' en script-src")),
                detail=str(_T("Allows inline script execution — disables CSP XSS protection", "Permite ejecución de scripts inline — anula la protección XSS de CSP")),
                remediation=str(_R_CSP_UNSAFE_INLINE), grade_cap="A-",
            ))
        if "'unsafe-inline'" in style_src:
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("CSP", "CSP")),
                name=str(_T("CSP: 'unsafe-inline' in style-src", "CSP: 'unsafe-inline' en style-src")),
                detail="Permite estilos inline — permite CSS injection",
                remediation=str(_R_CSP_UNSAFE_INLINE), grade_cap="A-",
            ))

        # unsafe-eval
        if "'unsafe-eval'" in script_src:
            result.findings.append(Finding(
                severity="HIGH", category=str(_T("CSP", "CSP")),
                name=str(_T("CSP: 'unsafe-eval' in script-src", "CSP: 'unsafe-eval' en script-src")),
                detail=str(_T("Allows eval() and equivalent functions — enables arbitrary code execution", "Permite eval() y funciones equivalentes — permite ejecución de código arbitrario")),
                remediation=str(_R_CSP_UNSAFE_EVAL), grade_cap="A-",
            ))

        # Wildcard en fuentes
        for dname, dvals in directives.items():
            if dname in ("report-uri", "report-to", "sandbox"):
                continue
            if "*" in dvals or "http://*" in dvals or "https://*" in dvals:
                result.findings.append(Finding(
                    severity="MEDIUM", category=str(_T("CSP", "CSP")),
                    name=str(_T(f"CSP: wildcard (*) in {dname}", f"CSP: comodín (*) en {dname}")),
                    detail=f"La directiva '{dname}' permite cargar recursos desde cualquier dominio",
                    remediation=str(_R_CSP_WILDCARD), grade_cap="A-",
                ))

        # frame-ancestors ausente (X-Frame-Options ya puede cubrirlo)
        if "frame-ancestors" not in directives:
            xfo = result.headers.get("x-frame-options")
            if not xfo:
                # Ya existe el hallazgo de XFO ausente — este es complementario
                result.findings.append(Finding(
                    severity="INFO", category=str(_T("CSP", "CSP")),
                    name=str(_T("CSP: frame-ancestors directive absent", "CSP: directiva frame-ancestors ausente")),
                    detail=str(_T("No frame-ancestors in CSP or X-Frame-Options — clickjacking possible via iframe", "Sin frame-ancestors en CSP ni X-Frame-Options — clickjacking posible vía iframe")),
                    remediation=str(_R_CSP_NO_FRAME_ANCESTORS),
                ))

        # Modo report-only (no aplicado)
        csp_ro = result.headers.get("content-security-policy-report-only")
        if csp_ro and not csp:
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("CSP", "CSP")),
                name=str(_T("CSP in Report-Only mode (not enforced)", "CSP en modo Report-Only (no aplicado)")),
                detail=str(_T("Content-Security-Policy-Report-Only blocks nothing — monitoring only", "Content-Security-Policy-Report-Only no bloquea nada — es solo monitorización")),
                remediation=str(_R_CSP_ABSENT), grade_cap="B",
            ))

    # --------------------------------------------------------- Fase 3: CORS

    def _phase_cors(self, result: AuditResult) -> None:
        """
        Prueba misconfigurations CORS enviando origins controlados y
        verificando si son reflejados en Access-Control-Allow-Origin.
        """
        test_origins = [
            self._CORS_TEST_ORIGIN,
            "null",  # Iframe sandbox bypass
        ]

        for origin in test_origins:
            try:
                _, hdrs, _ = self._fetch(
                    result.url,
                    method="GET",
                    extra_headers={"Origin": origin},
                    follow_redirects=False,
                )
            except Exception:
                continue

            acao = hdrs.get("access-control-allow-origin", "")
            acac = hdrs.get("access-control-allow-credentials", "").lower() == "true"

            if not acao:
                continue  # Sin CORS — normal

            if acao == "*" and acac:
                # Spec inválida pero algunos servidores lo hacen con reflejo
                result.cors_origin_reflected = True
                result.cors_credentials      = True
                result.findings.append(Finding(
                    severity="CRITICAL", category=str(_T("CORS", "CORS")),
                    name=str(_T("CORS: wildcard (*) + credentials", "CORS: wildcard (*) + credenciales")),
                    detail="Access-Control-Allow-Origin: * con Access-Control-Allow-Credentials: true — "
                           "permite robo de sesión cross-origin",
                    remediation=str(_R_CORS_WILDCARD_CREDS), grade_cap="F",
                ))
            elif acao == "*":
                result.findings.append(Finding(
                    severity="MEDIUM", category=str(_T("CORS", "CORS")),
                    name=str(_T("CORS: wildcard (*) without credentials", "CORS: wildcard (*) sin credenciales")),
                    detail=str(_T("Any origin can read responses — assess if intentional (public API)", "Cualquier origen puede leer las respuestas — evaluar si es intencional (API pública)")),
                    remediation=str(_R_CORS_WILDCARD), grade_cap="B",
                ))
            elif acao == origin and origin != "null":
                # Reflejo del origin del atacante
                result.cors_origin_reflected = True
                result.cors_origin_value     = acao
                result.cors_credentials      = acac
                sev  = "CRITICAL" if acac else "HIGH"
                cap  = "F" if acac else "B"
                remed = _R_CORS_REFLECT
                result.findings.append(Finding(
                    severity=sev, category=str(_T("CORS", "CORS")),
                    name="CORS: reflejo del origen del atacante" + (" + credenciales" if acac else ""),
                    detail=(
                        f"El servidor refleja el origen {origin!r} en ACAO"
                        + ("; con credenciales — permite robo de sesión" if acac else "")
                    ),
                    remediation=remed, grade_cap=cap,
                ))
            elif acao == "null" and origin == "null":
                result.cors_null_accepted = True
                result.findings.append(Finding(
                    severity="HIGH", category=str(_T("CORS", "CORS")),
                    name="CORS: acepta origen 'null'",
                    detail="El origen 'null' es generado por iframes sandbox — bypass de restricciones de origen",
                    remediation=str(_R_CORS_NULL), grade_cap="B",
                ))

    # --------------------------------------------------------- Fase 4: cookies

    def _phase_cookies(self, result: AuditResult) -> None:
        """Análisis de flags de seguridad en las cookies."""
        raw_list_str = result.headers.get("_set_cookie_list", "")
        if not raw_list_str:
            return

        raw_cookies = raw_list_str.split("|||")

        for raw in raw_cookies:
            raw = raw.strip()
            if not raw:
                continue

            # Parsear nombre=valor y atributos
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue

            name_val = parts[0]
            if "=" in name_val:
                name, val = name_val.split("=", 1)
            else:
                name, val = name_val, ""

            name   = name.strip()
            val    = val.strip()
            attrs  = {p.split("=", 1)[0].strip().lower(): p.split("=", 1)[1].strip() if "=" in p else ""
                      for p in parts[1:]}

            secure      = "secure"   in attrs
            httponly    = "httponly" in attrs
            samesite    = attrs.get("samesite")
            path        = attrs.get("path", "/")
            domain      = attrs.get("domain", "")
            host_prefix   = name.startswith("__Host-")
            secure_prefix = name.startswith("__Secure-")

            cookie = CookieInfo(
                name=name,
                value_preview=val[:4] + "…" if len(val) > 4 else val,
                secure=secure,
                httponly=httponly,
                samesite=samesite,
                path=path,
                domain=domain,
                host_prefix=host_prefix,
                secure_prefix=secure_prefix,
            )
            result.cookies.append(cookie)

            is_session_like = any(k in name.lower() for k in
                                  ("session", "sess", "auth", "token", "jwt", "sid", "id"))

            if not secure:
                result.findings.append(Finding(
                    severity="HIGH" if is_session_like else "MEDIUM",
                    category=str(_T("Cookies", "Cookies")),
                    name=f"Cookie sin Secure: {name}",
                    detail=str(_T(f"Cookie '{name}' is also transmitted over HTTP", f"La cookie '{name}' se transmite también por HTTP")),
                    remediation=str(_R_COOKIE_NOSECURE),
                    grade_cap="B",
                ))
            if not httponly:
                result.findings.append(Finding(
                    severity="HIGH" if is_session_like else "MEDIUM",
                    category=str(_T("Cookies", "Cookies")),
                    name=f"Cookie sin HttpOnly: {name}",
                    detail=f"La cookie '{name}' es accesible desde JavaScript (riesgo XSS)",
                    remediation=str(_R_COOKIE_NOHTTPONLY),
                    grade_cap="B",
                ))
            if samesite is None:
                result.findings.append(Finding(
                    severity="LOW",
                    category=str(_T("Cookies", "Cookies")),
                    name=f"Cookie sin SameSite: {name}",
                    detail=str(_T(f"Cookie '{name}' is sent on cross-site requests (CSRF risk)", f"La cookie '{name}' se envía en peticiones cross-site (riesgo CSRF)")),
                    remediation=str(_R_COOKIE_NOSAMESITE),
                    grade_cap="A",
                ))
            elif samesite.lower() == "none" and not secure:
                result.findings.append(Finding(
                    severity="HIGH",
                    category=str(_T("Cookies", "Cookies")),
                    name=f"Cookie SameSite=None sin Secure: {name}",
                    detail="SameSite=None requiere el flag Secure — los navegadores rechazan la cookie",
                    remediation=str(_R_COOKIE_NOSECURE),
                    grade_cap="B",
                ))

    # --------------------------------------------------------- Fase 5: información

    # Rangos de versiones PHP vulnerables a CVEs conocidos.
    # Formato: (desde_incl, hasta_excl, cve_id)
    # None en desde_incl significa "cualquier versión anterior a hasta_excl".
    _PHP_VULN_RANGES: list[tuple[str | None, str, str]] = [
        (None,    "8.2.35", "CVE-2026-109618"),  # php2shell — todas las ramas < 8.2.35
        ("8.3.0", "8.3.36", "CVE-2026-109618"),
        ("8.4.0", "8.4.27", "CVE-2026-109618"),
        ("8.5.0", "8.5.12", "CVE-2026-109618"),
    ]

    @staticmethod
    def _vt(ver: str) -> tuple[int, ...]:
        """Convierte '8.3.12' → (8, 3, 12) para comparaciones."""
        try:
            return tuple(int(x) for x in ver.split("."))
        except ValueError:
            return (0,)

    # ── Señales pasivas de PHP ───────────────────────────────────────────────

    # Cookies cuya presencia indica un framework PHP concreto
    _PHP_FRAMEWORK_COOKIES: dict[str, str] = {
        "phpsessid":           "PHP nativo (expose_php = Off)",
        "laravel_session":     "Laravel",
        "laravel_token":       "Laravel",
        "ci_session":          "CodeIgniter",
        "cakephp":             "CakePHP",
        "cake_":               "CakePHP",          # prefijo
        "moodlesession":       "Moodle",
        "roundcube_sessid":    "Roundcube Webmail",
        "roundcube_sessauth":  "Roundcube Webmail",
        "pmauser-":            "phpMyAdmin",        # prefijo
        "pmaccsrf-":           "phpMyAdmin",        # prefijo
        "wordpress_":          "WordPress",         # prefijo
        "wp_":                 "WordPress",         # prefijo
        "fuel_session":        "FuelPHP",
        "kohana_session":      "Kohana",
        "simplesam":           "SimpleSAMLphp",
        "piwik_auth":          "Matomo/Piwik",
        "zf_":                 "Zend Framework",    # prefijo
        "yii_csrf_token":      "Yii Framework",
        "_identity":           "Yii Framework",
        "prestashop":          "PrestaShop",        # prefijo
        "magento_":            "Magento",           # prefijo
        "frontend":            "Magento (posible)",
        "phpbb3_":             "phpBB",             # prefijo
        "drupal_uid_":         "Drupal",            # prefijo
        "drupal_session":      "Drupal",
        "symfony":             "Symfony",           # prefijo
        "silex_":              "Silex (Symfony)",
        "nette_":              "Nette Framework",
        "slim_session":        "Slim Framework",
        "typo3_":              "TYPO3",             # prefijo
    }

    # Headers de servidor/CMS que delatan PHP sin exponer la versión
    _PHP_CMS_HEADERS: tuple[str, ...] = (
        "x-drupal-cache", "x-drupal-dynamic-cache", "x-generator",
        "x-powered-cms", "x-wordpress-hit", "x-pingback",
        "x-magento-tags", "x-magento-cache-control",
    )

    # Firmas en el body (primeros 8 KB, lowercase)
    _PHP_BODY_PATTERNS: tuple[tuple[bytes, str], ...] = (
        (b"<?php",                           "código PHP expuesto"),
        (b"wp-content/",                     "WordPress"),
        (b"wp-includes/",                    "WordPress"),
        (b"wordpress.org",                   "WordPress"),
        (b"/wp-json",                        "WordPress REST API"),
        (b"joomla",                          "Joomla"),
        (b"com_content",                     "Joomla"),
        (b"drupal.js",                       "Drupal"),
        (b"drupal-settings-json",            "Drupal"),
        (b"phpmyadmin",                      "phpMyAdmin"),
        (b"pma_lang",                        "phpMyAdmin"),
        (b"roundcube",                       "Roundcube Webmail"),
        (b"typo3",                           "TYPO3"),
        (b"prestashop",                      "PrestaShop"),
        (b"magento",                         "Magento"),
        (b"fatal error:</b>",                "error PHP en producción"),
        (b"fatal error: ",                   "error PHP en producción"),
        (b"parse error:</b>",               "error PHP en producción"),
        (b"parse error: ",                   "error PHP en producción"),
        (b"warning: include",               "error PHP en producción"),
        (b"warning: require",               "error PHP en producción"),
        (b"phpsessid",                       "PHP nativo (cookie en body)"),
    )

    # Rutas que phpinfo() expone — para sondeo activo
    _PHPINFO_PATHS: tuple[str, ...] = (
        "/phpinfo.php", "/info.php", "/php.php", "/test.php", "/phptest.php",
        "/php_info.php", "/phpinfo/", "/server-status.php",
    )

    # Rutas de CMS PHP conocidos — para sondeo activo
    _PHP_CMS_PATHS: tuple[tuple[str, str], ...] = (
        ("/wp-login.php",            "WordPress"),
        ("/wp-json/wp/v2/",          "WordPress REST API"),
        ("/xmlrpc.php",              "WordPress XML-RPC"),
        ("/administrator/index.php", "Joomla"),
        ("/api/index.php",           "Joomla API"),
        ("/index.php?option=com_users", "Joomla"),
        ("/user/login",              "Drupal"),
        ("/core/misc/drupal.js",     "Drupal"),
        ("/phpmyadmin/",             "phpMyAdmin"),
        ("/pma/",                    "phpMyAdmin"),
        ("/roundcube/",              "Roundcube"),
        ("/webmail/",                "Roundcube (posible)"),
        ("/typo3/",                  "TYPO3 backend"),
    )

    # composer.lock: revela versión PHP exacta (platform-overrides) o restricción (platform)
    _COMPOSER_LOCK_PATHS: tuple[str, ...] = (
        "/composer.lock",
        "/public/composer.lock",
        "/app/composer.lock",
        "/backend/composer.lock",
        "/api/composer.lock",
        "/src/composer.lock",
    )

    # .env: CRITICAL por sí solo; puede contener PHP_VERSION=
    _DOTENV_PATHS: tuple[str, ...] = (
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.prod",
        "/.env.server",
    )

    # PHP-FPM status/ping: confirma PHP-FPM como backend
    _FPM_PROBE_PATHS: tuple[tuple[str, str], ...] = (
        ("/fpm-ping",        "ping"),
        ("/fpm-status",      "status"),
        ("/php-fpm-status",  "status"),
        ("/php-fpm-ping",    "ping"),
        ("/status",          "status"),   # algunos nginx lo exponen aquí
    )

    # Endpoints de debug de frameworks PHP — pueden revelar versión exacta
    _FRAMEWORK_DEBUG_PATHS: tuple[tuple[str, str], ...] = (
        ("/_ignition/health-check",  "Laravel Ignition"),
        ("/telescope/api/requests",  "Laravel Telescope"),
        ("/_profiler/",              "Symfony Profiler"),
        ("/_wdt/",                   "Symfony WDT"),
        ("/debug/",                  "debug endpoint"),
        ("/_debugbar/open",          "Laravel DebugBar"),
    )

    # Versiones de WP → requisito mínimo de PHP (para correlación)
    _WP_PHP_MIN: dict[tuple[int, int], str] = {
        (6, 7): "7.4", (6, 6): "7.4", (6, 5): "7.4", (6, 4): "7.4",
        (6, 3): "7.4", (6, 2): "7.4", (6, 1): "7.4", (6, 0): "7.4",
        (5, 9): "7.4", (5, 8): "7.4", (5, 7): "7.2", (5, 6): "7.2",
    }

    def _php_hallazgo_oculto(self, senal: str, remediacion_extra: str = "") -> "Finding":
        """Genera un hallazgo MEDIUM estándar para PHP detectado sin versión."""
        base_rem = (
            "Verificar la versión de PHP en el servidor:\n"
            "  php --version\n"
            "Si es vulnerable, actualizar a ≥8.2.35, ≥8.3.36, ≥8.4.27 o ≥8.5.12."
        )
        return Finding(
            severity="MEDIUM",
            category=str(_T("PHP Vulnerability", "Vulnerabilidad PHP")),
            name=str(_T(f"PHP detected — version hidden ({senal})", f"PHP detectado — versión oculta ({senal})")),
            detail=(
                f"PHP detectado a través de: {senal}. "
                "La versión exacta no está expuesta en cabeceras HTTP. "
                "Si la versión es < 8.2.35, < 8.3.36, < 8.4.27 o < 8.5.12, el servidor puede "
                "ser vulnerable a CVE-2026-109618 (RCE, CVSS 9.8)."
            ),
            remediation=base_rem + ("\n" + remediacion_extra if remediacion_extra else ""),
            grade_cap="B",
        )

    def _detectar_php(self, result: AuditResult) -> None:
        """
        Detección multi-señal de PHP (pasiva).

        Orden de prioridad:
          1. Versión explícita en X-Powered-By / Server → CVE check
          2. URL final con extensión .php
          3. Cookies de framework PHP (PHPSESSID, laravel_session, ci_session…)
          4. Headers CMS (X-Generator, X-Drupal-Cache, X-Pingback…)
          5. Meta generator en body → extrae CMS/versión si está disponible
          6. Firmas en body (wp-content/, Drupal JS, errores PHP…)
        """
        h       = result.headers
        version: str = ""

        # ── 1. Versión explícita en cabeceras ────────────────────────────────
        for cabecera in ("x-powered-by", "server"):
            val = h.get(cabecera, "")
            m   = re.search(r"PHP/(\d+\.\d+\.\d+)", val, re.IGNORECASE)
            if m:
                version = m.group(1)
                break

        if version:
            # Versión conocida → saltar al CVE check al final del método
            pass

        # ── 2. URL final con extensión .php ──────────────────────────────────
        if not version and result.final_url:
            parsed_final = urllib.parse.urlparse(result.final_url)
            path_lower   = parsed_final.path.lower()
            if path_lower.endswith(".php") or ".php?" in path_lower or ".php/" in path_lower:
                result.php_version = "detectado (extensión .php en URL)"
                result.findings.append(self._php_hallazgo_oculto(
                    f"extensión .php en URL final ({result.final_url})",
                    "Considera usar URL rewriting para ocultar extensiones de framework.",
                ))
                return

        # ── 3. Cookies de framework PHP ──────────────────────────────────────
        if not version:
            set_cookie_raw = h.get("_set_cookie_list", "").lower()
            cookie_names   = [ck.name.lower() for ck in result.cookies]
            all_cookies    = " ".join(cookie_names) + " " + set_cookie_raw

            matched_fw: str = ""
            for cookie_key, framework in self._PHP_FRAMEWORK_COOKIES.items():
                # Soporta prefijos (terminan en "_") y nombres exactos
                if cookie_key.endswith("_"):
                    if any(c.startswith(cookie_key) for c in cookie_names) or cookie_key in set_cookie_raw:
                        matched_fw = framework
                        break
                else:
                    if cookie_key in all_cookies:
                        matched_fw = framework
                        break

            if matched_fw:
                result.php_version = f"detectado (cookie {matched_fw})"
                result.findings.append(self._php_hallazgo_oculto(
                    f"cookie de framework {matched_fw}",
                    f"Para reducir fingerprinting de {matched_fw}, renombra la cookie de sesión.",
                ))
                return

        # ── 4. Headers de CMS / plataforma PHP ───────────────────────────────
        if not version:
            for hname in self._PHP_CMS_HEADERS:
                val = h.get(hname, "")
                if val:
                    # X-Generator puede revelar CMS y versión
                    cms_label = f"{hname}: {val[:60]}"
                    result.php_version = f"detectado (header {hname})"
                    result.findings.append(self._php_hallazgo_oculto(
                        cms_label,
                        f"Eliminar el header {hname!r} del servidor para reducir fingerprinting.",
                    ))
                    return

        # ── 5. Meta generator en body ─────────────────────────────────────────
        if not version:
            body_sample = result._raw_body[:16384] if result._raw_body else b""
            meta_m      = re.search(
                rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\'<>]{3,80})["\']',
                body_sample, re.IGNORECASE,
            )
            if not meta_m:
                # Orden alternativo de atributos
                meta_m = re.search(
                    rb'<meta[^>]+content=["\']([^"\'<>]{3,80})["\'][^>]+name=["\']generator["\']',
                    body_sample, re.IGNORECASE,
                )
            if meta_m:
                generator = meta_m.group(1).decode("utf-8", errors="replace").strip()
                gen_lower = generator.lower()
                if any(kw in gen_lower for kw in (
                    "wordpress", "joomla", "drupal", "typo3",
                    "magento", "prestashop", "moodle", "phpbb",
                )):
                    result.php_version = f"detectado (meta generator: {generator[:40]})"
                    result.findings.append(self._php_hallazgo_oculto(
                        f"meta generator: {generator[:60]}",
                        "Elimina o vacía el tag <meta name=\"generator\"> para reducir fingerprinting.",
                    ))
                    return

        # ── 6. Firmas en body ─────────────────────────────────────────────────
        if not version:
            body_lower = (result._raw_body[:8192].lower() if result._raw_body else b"")
            for pattern, descripcion in self._PHP_BODY_PATTERNS:
                if pattern in body_lower:
                    result.php_version = f"detectado (body: {descripcion})"
                    result.findings.append(self._php_hallazgo_oculto(
                        descripcion,
                        ("Desactiva la visualización de errores PHP en producción:\n"
                         "  display_errors = Off  (php.ini)")
                        if "error" in descripcion else "",
                    ))
                    return

        if not version:
            return

        result.php_version = version
        self._evaluar_php_cves(result, version)

    def _evaluar_php_cves(self, result: AuditResult, version: str) -> None:
        """Evalúa si una versión PHP concreta cae en rangos CVE conocidos y añade el hallazgo.
        Idempotente: no añade hallazgos duplicados si ya se llamó con la misma versión."""
        # Evitar duplicados (puede ser llamado desde pasiva + activa)
        cve_finding_name = f"PHP/{version} — versión vulnerable"
        if any(cve_finding_name in f.name for f in result.findings):
            return
        v = self._vt(version)

        cves_aplicables: list[str] = []
        for desde, hasta, cve in self._PHP_VULN_RANGES:
            lo = self._vt(desde) if desde else (0,)
            hi = self._vt(hasta)
            if lo <= v < hi:
                cves_aplicables.append(cve)

        if cves_aplicables:
            result.php_vulnerable = True
            result.php_cves = cves_aplicables
            cve_str = ", ".join(cves_aplicables)
            result.findings.append(Finding(
                severity="CRITICAL",
                category=str(_T("PHP Vulnerability", "Vulnerabilidad PHP")),
                name=str(_T(f"PHP/{version} — vulnerable version ({cve_str})", f"PHP/{version} — versión vulnerable ({cve_str})")),
                detail=(
                    f"La versión PHP/{version} detectada en {result.url} está afectada por {cve_str}. "
                    f"CVE-2026-109618 (php2shell): PHP usa longjmp() para errores OOM dejando memoria "
                    f"de la request sin inicializar, lo que puede derivar en RCE remoto sin autenticación. "
                    f"CVSS 3.1: 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). "
                    f"Versiones seguras: ≥8.2.35 · ≥8.3.36 · ≥8.4.27 · ≥8.5.12."
                ),
                remediation=(
                    "Actualizar PHP inmediatamente a la versión parcheada:\n"
                    "  PHP 8.2.x → actualizar a 8.2.35 o superior\n"
                    "  PHP 8.3.x → actualizar a 8.3.36 o superior\n"
                    "  PHP 8.4.x → actualizar a 8.4.27 o superior\n"
                    "  PHP 8.5.x → actualizar a 8.5.12 o superior\n"
                    "  Ref: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w\n"
                    "  Ref: https://www.wiz.io/blog/php2shell-php-rce"
                ),
                grade_cap="F",
            ))

    def _phase_info_disclosure(self, result: AuditResult) -> None:
        """Detección de cabeceras que revelan información técnica del servidor."""
        h = result.headers

        # Detección de versión PHP y CVEs conocidos (antes del resto para prioridad)
        self._detectar_php(result)

        # Server con versión
        server = h.get("server", "")
        if server:
            # Detectar si contiene versión numérica
            version_pattern = re.search(r"[\d\.]{3,}", server)
            if version_pattern or "/" in server:
                result.findings.append(Finding(
                    severity="MEDIUM", category=str(_T("Information", "Información")),
                    name=str(_T(f"Server: reveals version — {server}", f"Server: revela versión — {server}")),
                    detail=str(_T(f"Exposes server software and version: {server!r}", f"Expone el software y versión del servidor: {server!r}")),
                    remediation=str(_R_SERVER_VERSION), grade_cap="B",
                ))

        # X-Powered-By
        xpb = h.get("x-powered-by", "")
        if xpb:
            result.findings.append(Finding(
                severity="LOW", category=str(_T("Information", "Información")),
                name=str(_T(f"X-Powered-By: reveals technology — {xpb}", f"X-Powered-By: revela tecnología — {xpb}")),
                detail=str(_T(f"Exposes backend technology: {xpb!r}", f"Expone la tecnología del backend: {xpb!r}")),
                remediation=str(_R_XPOWEREDBY), grade_cap="B",
            ))

        # Cabeceras de versión de frameworks
        for h_name in ("x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-wordpress-hit"):
            val = h.get(h_name)
            if val:
                result.findings.append(Finding(
                    severity="LOW", category=str(_T("Information", "Información")),
                    name=f"{h_name}: {val}",
                    detail=f"La cabecera {h_name!r} revela detalles del CMS/framework",
                    remediation=str(_R_SERVER_VERSION),
                ))

        # Cabeceras de debug
        for h_name, h_val in h.items():
            if h_name.startswith(("x-debug", "x-sf-")) or "debug" in h_name:
                result.findings.append(Finding(
                    severity="MEDIUM", category=str(_T("Information", "Información")),
                    name=f"Cabecera de debug expuesta: {h_name}: {h_val[:80]}",
                    detail=str(_T("Debug headers active in production — may reveal internal paths and tokens", "Cabeceras de depuración activas en producción — puede revelar rutas y tokens internos")),
                    remediation=str(_R_DEBUG_HEADER), grade_cap="A-",
                ))
                break  # Una sola notificación por fase

    # --------------------------------------------------------- Fase 6: open redirect

    def _phase_open_redirect(self, result: AuditResult) -> None:
        """
        Prueba parámetros de redirección comunes para detectar open redirects.
        Inyecta una URL externa y verifica si el Location header la refleja.
        """
        test_url = "https://evil.vampsecurelabs-openredirect-test.invalid/pwned"
        parsed   = urllib.parse.urlparse(result.url)
        base_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, "", "", ""
        ))

        vulnerable_params = []

        for param in REDIRECT_PARAMS:
            probe_url = f"{base_url}?{param}={urllib.parse.quote(test_url, safe='')}"
            try:
                status, hdrs, _ = self._fetch(
                    probe_url, method="GET",
                    follow_redirects=False,
                )
                if status in (301, 302, 303, 307, 308):
                    location = hdrs.get("location", "")
                    if test_url in location or "evil.vampsecurelabs" in location:
                        vulnerable_params.append(param)
            except Exception:
                continue

        if vulnerable_params:
            result.open_redirect_params = vulnerable_params
            result.findings.append(Finding(
                severity="CRITICAL", category=str(_T("Open Redirect", "Open Redirect")),
                name=str(_T(f"Open redirect confirmed: parameters {', '.join(vulnerable_params)}", f"Open redirect confirmado: parámetros {', '.join(vulnerable_params)}")),
                detail=(
                    f"Los parámetros {vulnerable_params} redirigen a URLs externas sin validación — "
                    "permite phishing y bypass de seguridad"
                ),
                remediation=str(_R_OPEN_REDIRECT), grade_cap="F",
            ))

    # --------------------------------------------------------- Pruebas activas (--active)

    def _probe_idor(self, result: AuditResult) -> None:
        """
        Prueba básica de IDOR: si la URL contiene parámetros con IDs numéricos
        (?id=123, /user/123, /item/456), incrementa y decrementa el ID y compara
        el tamaño de las respuestas para detectar acceso no autorizado a recursos.
        """
        parsed = urllib.parse.urlparse(result.url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Buscar parámetros query string con valores numéricos (ej. ?id=123)
        id_params = {k: v[0] for k, v in params.items() if v and v[0].isdigit()}

        if not id_params:
            # Buscar IDs numéricos en el path (ej. /user/123, /item/456)
            path_match = re.search(r'/(\d{1,10})(?:/|$)', parsed.path)
            if not path_match:
                return  # No se encontraron IDs numéricos en la URL

        if id_params:
            # Probar el primer parámetro numérico encontrado
            param_name = next(iter(id_params))
            id_val     = int(id_params[param_name])
            responses  = {}

            for delta in (-1, 1):
                new_id = id_val + delta
                if new_id < 0:
                    continue
                new_params  = dict(params)
                new_params[param_name] = [str(new_id)]
                new_query   = urllib.parse.urlencode(new_params, doseq=True)
                probe_url   = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, ""
                ))
                try:
                    status, _, body = self._fetch(probe_url, follow_redirects=True)
                    if status == 200:
                        responses[delta] = len(body)
                    elif status in (403, 404):
                        result.findings.append(Finding(
                            severity="INFO", category=str(_T("Active Tests", "Pruebas Activas")),
                            name=f"IDOR: control de acceso activo para '{param_name}'",
                            detail=(
                                f"ID adyacente {new_id} devolvió HTTP {status} "
                                "— el servidor rechaza IDs no autorizados."
                            ),
                        ))
                        return
                except Exception:
                    pass

            if len(responses) == 2:
                size_a, size_b = list(responses.values())
                if size_a > 0 and size_b > 0:
                    ratio = max(size_a, size_b) / max(min(size_a, size_b), 1)
                    if ratio <= 1.25:
                        result.findings.append(Finding(
                            severity="MEDIUM", category=str(_T("Active Tests", "Pruebas Activas")),
                            name=str(_T(f"Possible IDOR — parameter '{param_name}'", f"Posible IDOR — parámetro '{param_name}'")),
                            detail=(
                                f"Los IDs adyacentes ({id_val - 1} y {id_val + 1}) devuelven "
                                f"HTTP 200 con tamaños similares ({size_a} y {size_b} bytes, "
                                f"ratio {ratio:.2f}). Podría indicar acceso no autorizado "
                                "a recursos de otros usuarios (IDOR / BOLA)."
                            ),
                            remediation=(
                                "Verificar que el acceso a cada recurso exige autorización "
                                "del propietario. Implementar controles a nivel de objeto. "
                                "Usar UUIDs en lugar de IDs secuenciales para dificultar la enumeración. "
                                "Ref: OWASP API Security — BOLA (API1:2023)"
                            ),
                            grade_cap="B",
                        ))

    def _probe_host_header_injection(self, result: AuditResult) -> None:
        """
        Prueba Host Header Injection enviando una cabecera Host manipulada
        y verificando si el valor manipulado aparece reflejado en la respuesta.
        """
        evil_host = "evil.attacker-vsl-probe.invalid"
        try:
            status, hdrs, body = self._fetch(
                result.url,
                extra_headers={"Host": evil_host},
                follow_redirects=False,
            )
            body_str = body.decode(errors="replace")
            location = hdrs.get("location", "")

            if evil_host in body_str or evil_host in location:
                result.findings.append(Finding(
                    severity="HIGH", category=str(_T("Active Tests", "Pruebas Activas")),
                    name="Host Header Injection — respuesta refleja el header Host manipulado",
                    detail=(
                        f"El servidor refleja el valor de la cabecera Host manipulada "
                        f"('{evil_host}') en el cuerpo o en la cabecera Location. "
                        "Esto puede facilitar password reset poisoning, cache poisoning "
                        "o generación de URLs maliciosas en correos electrónicos."
                    ),
                    remediation=(
                        "Validar la cabecera Host contra una lista blanca de hosts permitidos. "
                        "No usar el valor del header Host en redirecciones ni en enlaces generados. "
                        "Configurar el servidor web para rechazar cabeceras Host no reconocidas. "
                        "nginx: server_name_in_redirect off; + lista explícita de server_name."
                    ),
                    grade_cap="B",
                ))
            elif status in (400, 421):
                result.findings.append(Finding(
                    severity="INFO", category=str(_T("Active Tests", "Pruebas Activas")),
                    name="Host Header: servidor rechaza Host manipulado",
                    detail=(
                        f"El servidor devolvió HTTP {status} ante una cabecera Host inválida "
                        "— protección activa contra Host Header Injection."
                    ),
                ))
        except Exception:
            pass

    def _probe_php_active(self, result: AuditResult) -> None:
        """
        Sondeo activo de PHP — orquesta 7 vectores en orden de precisión.
        Se detiene en cuanto obtiene la versión exacta (x.y.z).
        Siempre ejecuta composer.lock y .env aunque ya haya versión exacta
        (son hallazgos de seguridad independientes).
        """
        parsed = urllib.parse.urlparse(result.final_url or result.url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        exact  = bool(result.php_version and re.match(r"\d+\.\d+\.\d+", result.php_version))

        # composer.lock y .env se sondean SIEMPRE (son hallazgos propios)
        if not self._probe_composer_lock(base, result) and not exact:
            exact = bool(result.php_version and re.match(r"\d+\.\d+\.\d+", result.php_version))
        self._probe_dotenv(base, result)
        if not exact:
            exact = bool(result.php_version and re.match(r"\d+\.\d+\.\d+", result.php_version))

        if exact:
            # Con versión exacta solo queda comprobar FPM/debug por sus hallazgos propios
            self._probe_fpm_status(base, result)
            self._probe_framework_debug(base, result)
            return

        # Sin versión exacta: continuar con los demás vectores
        if self._probe_phpinfo(base, result):
            self._probe_fpm_status(base, result)
            self._probe_framework_debug(base, result)
            return

        self._probe_fpm_status(base, result)
        self._probe_framework_debug(base, result)
        self._probe_wp_version(base, result)

        if not result.php_version:
            self._probe_cms_paths(base, result)

        # Fingerprinting de major version por diferencias de formato de error
        self._probe_php_error_fingerprint(base, result)

    # ── Sondeo: phpinfo() ─────────────────────────────────────────────────────

    def _probe_phpinfo(self, base: str, result: AuditResult) -> bool:
        """Sondea rutas phpinfo(). Devuelve True si obtiene versión exacta."""
        phpinfo_re = re.compile(
            rb"PHP Version\s*</td[^>]*>\s*<td[^>]*>([0-9]+\.[0-9]+\.[0-9]+)",
            re.IGNORECASE,
        )
        for path in self._PHPINFO_PATHS:
            try:
                url_probe = base + path
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=False)
                if status != 200 or not body:
                    continue
                body_lower = body[:32768].lower()
                if b"phpinfo()" not in body_lower and b"php version" not in body_lower:
                    continue
                m = phpinfo_re.search(body[:32768])
                if m:
                    version = m.group(1).decode("ascii", errors="replace")
                    result.php_version = version
                    self._evaluar_php_cves(result, version)
                    sev = "HIGH" if not result.php_vulnerable else "HIGH"
                    result.findings.append(Finding(
                        severity=sev,
                        category=str(_T("PHP Vulnerability", "Vulnerabilidad PHP")),
                        name=f"phpinfo() expuesto en {path}",
                        detail=(
                            f"La ruta {url_probe} devuelve phpinfo() completo (PHP {version}). "
                            "Expone versión exacta, variables de entorno, rutas del sistema "
                            "y módulos cargados — información crítica para un atacante."
                        ),
                        remediation=(
                            f"Eliminar {path} de la docroot inmediatamente.\n"
                            "  O bloquear desde nginx:  location = {path} {{ deny all; }}"
                        ),
                        grade_cap="C",
                    ))
                    return True
                else:
                    result.php_version = result.php_version or "detectado (phpinfo expuesto)"
                    result.findings.append(Finding(
                        severity="HIGH",
                        category=str(_T("PHP Vulnerability", "Vulnerabilidad PHP")),
                        name=f"phpinfo() expuesto en {path}",
                        detail=(
                            f"La ruta {url_probe} devuelve phpinfo() pero la versión no se pudo extraer. "
                            "Expone configuración sensible del servidor."
                        ),
                        remediation=f"Eliminar {path} de la docroot.",
                        grade_cap="C",
                    ))
                    return False
            except Exception:
                continue
        return False

    # ── Sondeo: composer.lock ─────────────────────────────────────────────────

    def _probe_composer_lock(self, base: str, result: AuditResult) -> bool:
        """
        Sondea composer.lock. Es un hallazgo de divulgación de información independiente.
        Devuelve True si obtiene versión PHP exacta (platform-overrides).
        """
        for path in self._COMPOSER_LOCK_PATHS:
            try:
                url_probe = base + path
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=False)
                if status != 200 or not body:
                    continue
                body_text = body[:131072].decode("utf-8", errors="replace").strip()
                if not body_text.startswith("{"):
                    continue
                try:
                    data = json.loads(body_text)
                except Exception:
                    continue

                platform   = data.get("platform", {}) or {}
                overrides  = data.get("platform-overrides", {}) or {}
                php_req    = overrides.get("php") or platform.get("php") or ""

                # Contar dependencias para el detalle del hallazgo
                n_packages = len(data.get("packages", []))
                n_dev      = len(data.get("packages-dev", []))

                result.findings.append(Finding(
                    severity="HIGH",
                    category=str(_T("Information Disclosure", "Divulgación de información")),
                    name=f"composer.lock expuesto ({path})",
                    detail=(
                        f"El fichero composer.lock es público en {url_probe}. "
                        f"Expone el árbol completo de dependencias ({n_packages} paquetes, "
                        f"{n_dev} de desarrollo) con sus versiones exactas, "
                        "facilitando la búsqueda dirigida de CVEs en componentes del servidor."
                        + (f" PHP declarado: {php_req}." if php_req else "")
                    ),
                    remediation=(
                        "Bloquear el acceso a composer.lock desde nginx/apache:\n"
                        "  nginx:  location ~* composer\\.lock$ { deny all; }\n"
                        "  apache: <Files \"composer.lock\"> Require all denied </Files>"
                    ),
                    grade_cap="C",
                ))

                if php_req:
                    exact = re.match(r"^(\d+\.\d+\.\d+)$", php_req.strip())
                    if exact:
                        version = exact.group(1)
                        result.php_version = version
                        self._evaluar_php_cves(result, version)
                        return True
                    # Restricción de rango (^8.1, >=8.0…) — no exacta pero útil
                    if not result.php_version:
                        result.php_version = f"detectado (composer.lock: PHP {php_req})"
                        result.findings.append(self._php_hallazgo_oculto(
                            f"composer.lock — restricción PHP {php_req}",
                        ))
                return False
            except Exception:
                continue
        return False

    # ── Sondeo: .env ──────────────────────────────────────────────────────────

    def _probe_dotenv(self, base: str, result: AuditResult) -> bool:
        """
        Sondea ficheros .env. SIEMPRE genera hallazgo CRITICAL si está expuesto.
        También extrae PHP_VERSION= si aparece.
        Devuelve True si obtiene versión PHP exacta.
        """
        for path in self._DOTENV_PATHS:
            try:
                url_probe = base + path
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=False)
                if status != 200 or not body:
                    continue
                body_text = body[:65536].decode("utf-8", errors="replace")
                body_lower = body_text.lower()
                # Rechazar respuestas HTML (páginas de error del servidor)
                if "<html" in body_lower or "<body" in body_lower:
                    continue
                if "=" not in body_text:
                    continue

                # Recopilar keys sensibles presentes (para el detalle del hallazgo)
                sensitive_keys: list[str] = []
                php_version_found: str = ""
                php_binary_hint:   str = ""
                for line in body_text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key_upper = key.strip().upper()
                    val_clean = val.strip().strip('"').strip("'")
                    # Keys sensibles conocidas
                    if any(kw in key_upper for kw in (
                        "SECRET", "KEY", "TOKEN", "PASSWORD", "PASS", "PWD",
                        "DATABASE_URL", "DB_PASS", "DB_PASSWORD", "REDIS_URL",
                        "AWS_", "S3_", "STRIPE_", "SENDGRID_", "MAILGUN_",
                        "JWT_", "OAUTH_", "AUTH_", "API_KEY", "PRIVATE",
                    )):
                        sensitive_keys.append(key.strip())
                    # PHP version
                    if key_upper == "PHP_VERSION":
                        m = re.match(r"(\d+\.\d+\.\d+)", val_clean)
                        if m:
                            php_version_found = m.group(1)
                    elif key_upper == "PHP_BINARY":
                        m = re.search(r"php(\d+\.\d+)", val_clean)
                        if m:
                            php_binary_hint = f"php{m.group(1)}.x"

                keys_str = (
                    f" Claves sensibles detectadas: {', '.join(sensitive_keys[:8])}."
                    if sensitive_keys else ""
                )
                result.findings.append(Finding(
                    severity="CRITICAL",
                    category=str(_T("Information Disclosure", "Divulgación de información")),
                    name=f"Fichero .env expuesto ({path})",
                    detail=(
                        f"El fichero {path} es accesible públicamente en {url_probe}. "
                        "Puede contener credenciales de base de datos, claves API, "
                        "tokens OAuth, claves de cifrado y secretos de aplicación."
                        + keys_str
                    ),
                    remediation=(
                        "Bloquear el acceso a ficheros .env inmediatamente:\n"
                        "  nginx:  location ~ /\\. { deny all; }\n"
                        "  apache: <FilesMatch \"^\\.(env|git|htaccess)\">"
                        " Require all denied </FilesMatch>\n"
                        "Rotar TODOS los secretos que hayan podido quedar expuestos."
                    ),
                    grade_cap="F",
                ))

                if php_version_found:
                    result.php_version = php_version_found
                    self._evaluar_php_cves(result, php_version_found)
                    return True
                if php_binary_hint and not result.php_version:
                    result.php_version = f"detectado (.env PHP_BINARY: {php_binary_hint})"
                    result.findings.append(self._php_hallazgo_oculto(
                        f".env expuesto — PHP_BINARY apunta a {php_binary_hint}",
                    ))
                # Solo procesamos el primer .env encontrado
                return False
            except Exception:
                continue
        return False

    # ── Sondeo: PHP-FPM status/ping ───────────────────────────────────────────

    def _probe_fpm_status(self, base: str, result: AuditResult) -> None:
        """Detecta endpoints de PHP-FPM expuestos. Genera hallazgo propio."""
        for path, kind in self._FPM_PROBE_PATHS:
            try:
                url_probe = base + path
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=False)
                if status != 200 or not body:
                    continue
                body_text = body[:4096].decode("utf-8", errors="replace")
                body_lower = body_text.lower()
                # fpm-ping → "pong"
                if kind == "ping" and body_text.strip().lower() == "pong":
                    result.findings.append(Finding(
                        severity="MEDIUM",
                        category=str(_T("Information Disclosure", "Divulgación de información")),
                        name=f"PHP-FPM ping expuesto ({path})",
                        detail=(
                            f"El endpoint de ping de PHP-FPM responde en {url_probe}. "
                            "Confirma PHP-FPM como backend y puede usarse para enumerar "
                            "la presencia del servicio."
                        ),
                        remediation=(
                            "Restringir el acceso al endpoint de PHP-FPM:\n"
                            f"  location = {path} {{ allow 127.0.0.1; deny all; }}"
                        ),
                        grade_cap="B",
                    ))
                    if not result.php_version:
                        result.php_version = "detectado (PHP-FPM ping)"
                        result.findings.append(self._php_hallazgo_oculto("PHP-FPM ping activo"))
                    return
                # fpm-status → pool info
                if kind == "status" and "pool" in body_lower and (
                    "accepted conn" in body_lower or "start time" in body_lower
                    or "active processes" in body_lower
                ):
                    # Intentar extraer versión de la cabecera X-Powered-By que a veces acompaña
                    powered = hdrs.get("x-powered-by", "")
                    ver_m   = re.search(r"PHP/(\d+\.\d+\.\d+)", powered, re.IGNORECASE)
                    if ver_m and not result.php_version:
                        version = ver_m.group(1)
                        result.php_version = version
                        self._evaluar_php_cves(result, version)
                    result.findings.append(Finding(
                        severity="HIGH",
                        category=str(_T("Information Disclosure", "Divulgación de información")),
                        name=f"PHP-FPM status expuesto ({path})",
                        detail=(
                            f"El endpoint de estado de PHP-FPM es público en {url_probe}. "
                            "Expone información del pool: conexiones aceptadas, procesos "
                            "activos/inactivos, tiempo de inicio y métricas de rendimiento."
                        ),
                        remediation=(
                            "Restringir el acceso al status de PHP-FPM:\n"
                            f"  location = {path} {{ allow 127.0.0.1; deny all; }}"
                        ),
                        grade_cap="B",
                    ))
                    if not result.php_version:
                        result.php_version = "detectado (PHP-FPM status)"
                        result.findings.append(self._php_hallazgo_oculto("PHP-FPM status expuesto"))
                    return
            except Exception:
                continue

    # ── Sondeo: framework debug/profiler ─────────────────────────────────────

    def _probe_framework_debug(self, base: str, result: AuditResult) -> None:
        """Detecta paneles de debug de frameworks PHP expuestos en producción."""
        for path, framework in self._FRAMEWORK_DEBUG_PATHS:
            try:
                url_probe = base + path
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=False)
                if status not in (200, 302) or not body:
                    continue
                body_lower = body[:16384].lower()
                # Validar contenido — evitar falsos positivos en rutas genéricas
                confirmed = False
                if "ignition" in path:
                    confirmed = b"ignition" in body_lower or b"phpversion" in body_lower
                elif "telescope" in path:
                    confirmed = b"telescope" in body_lower
                elif "profiler" in path:
                    confirmed = b"symfony" in body_lower or b"profiler" in body_lower
                elif "_wdt" in path:
                    confirmed = b"symfony" in body_lower or b"wdt" in body_lower
                elif "debugbar" in path:
                    confirmed = b"debugbar" in body_lower
                elif "debug" in path:
                    # Ruta genérica: exigir señales claras de panel de debug PHP
                    confirmed = (
                        b"phpversion" in body_lower
                        or (b"debug" in body_lower and (b"laravel" in body_lower or b"symfony" in body_lower))
                    )
                if not confirmed:
                    continue

                # Intentar extraer versión PHP del JSON
                # (Ignition y DebugBar devuelven JSON puro; Symfony es HTML)
                version = ""
                body_str = body[:32768].decode("utf-8", errors="replace")
                # Buscar el primer bloque JSON en el body (maneja prefijos HTML)
                json_start = body_str.find("{")
                if json_start != -1:
                    try:
                        data = json.loads(body_str[json_start:])
                        php_ver = (
                            data.get("phpVersion")
                            or data.get("php_version")
                            or (data.get("info", {}) or {}).get("php")
                            or ""
                        )
                        if php_ver:
                            m = re.match(r"(\d+\.\d+\.\d+)", str(php_ver))
                            if m:
                                version = m.group(1)
                    except Exception:
                        pass

                # Symfony profiler a veces muestra la versión en HTML
                if not version and b"php version" in body_lower:
                    m = re.search(
                        rb"php version[^0-9]*(\d+\.\d+\.\d+)",
                        body[:16384], re.IGNORECASE,
                    )
                    if m:
                        version = m.group(1).decode("ascii", errors="replace")

                sev = "CRITICAL" if "debug" in path or "telescope" in path else "HIGH"
                result.findings.append(Finding(
                    severity=sev,
                    category=str(_T("Information Disclosure", "Divulgación de información")),
                    name=f"Panel de debug {framework} expuesto ({path})",
                    detail=(
                        f"El panel de depuración de {framework} es accesible en {url_probe}. "
                        "Expone stack traces, variables de entorno, consultas SQL, "
                        "configuración de la aplicación y potencialmente credenciales."
                        + (f" PHP {version} confirmado." if version else "")
                    ),
                    remediation=(
                        f"Deshabilitar {framework} en producción:\n"
                        "  Laravel: APP_DEBUG=false en .env\n"
                        "  Symfony: APP_ENV=prod APP_DEBUG=0\n"
                        f"  O bloquear vía nginx: location ~* {path} {{ deny all; }}"
                    ),
                    grade_cap="F" if sev == "CRITICAL" else "C",
                ))

                if version:
                    result.php_version = version
                    self._evaluar_php_cves(result, version)
                elif not result.php_version:
                    result.php_version = f"detectado ({framework} debug expuesto)"
                    result.findings.append(self._php_hallazgo_oculto(
                        f"panel {framework} en {path}",
                    ))
            except Exception:
                continue

    # ── Sondeo: WordPress version.php ────────────────────────────────────────

    def _probe_wp_version(self, base: str, result: AuditResult) -> None:
        """Extrae la versión de WordPress de wp-includes/version.php y la correlaciona con PHP."""
        paths = ("/wp-includes/version.php", "/wp-readme.php")
        for path in paths:
            try:
                url_probe = base + path
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=False)
                if status != 200 or not body:
                    continue
                body_text = body[:8192].decode("utf-8", errors="replace")
                m = re.search(
                    r"\$wp_version\s*=\s*['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)['\"]",
                    body_text,
                )
                if not m:
                    continue
                wp_version = m.group(1)
                parts      = wp_version.split(".")
                wp_key     = (int(parts[0]), int(parts[1]))
                php_min    = self._WP_PHP_MIN.get(wp_key, "7.4")

                result.findings.append(Finding(
                    severity="MEDIUM",
                    category=str(_T("Information Disclosure", "Divulgación de información")),
                    name=f"wp-includes/version.php accesible — WordPress {wp_version}",
                    detail=(
                        f"La ruta {url_probe} expone la versión exacta de WordPress ({wp_version}). "
                        f"WordPress {wp_version} requiere PHP ≥{php_min}. "
                        "La versión del CMS facilita la búsqueda de vulnerabilidades específicas."
                    ),
                    remediation=(
                        "Bloquear el acceso directo a ficheros PHP de wp-includes:\n"
                        "  location ~* /wp-includes/.*\\.php$ { deny all; }"
                    ),
                    grade_cap="B",
                ))

                if not result.php_version:
                    result.php_version = f"detectado (WP {wp_version} → PHP ≥{php_min})"
                    result.findings.append(self._php_hallazgo_oculto(
                        f"WordPress {wp_version} requiere PHP ≥{php_min}",
                        "Verificar la versión exacta de PHP en el servidor con `php --version`.",
                    ))
                return
            except Exception:
                continue

    # ── Sondeo: fingerprinting de major version por error ────────────────────

    def _probe_php_error_fingerprint(self, base: str, result: AuditResult) -> None:
        """
        Distingue PHP 7 de PHP 8 por diferencias de formato en mensajes de error.
        Solo actúa si hay PHP detectado pero sin major version conocida.
        PHP 8.0 introdujo "Uncaught Error:" y cambió el formato de los errores.
        """
        if not result.php_version:
            return
        if re.search(r"\b[78]\.", result.php_version):
            return  # Ya tenemos al menos la major version

        # Sondear un .php inexistente para provocar un 404 gestionado por PHP
        # o una ruta que suele devolver error de PHP si el framework está configurado
        probe_urls = [
            base + "/__vamp_php_probe__.php",
            base + "/index.php?vamp_probe_invalid_param=1",
        ]
        for url_probe in probe_urls:
            try:
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=False)
                if not body:
                    continue
                body_text = body[:4096].decode("utf-8", errors="replace").lower()

                # PHP 8.0+ usa "Uncaught Error:" y "Deprecated:" en lugar del viejo "Fatal error:"
                if "uncaught error:" in body_text or "deprecated:" in body_text:
                    major_hint = "8.x"
                elif "fatal error:" in body_text and "uncaught" not in body_text:
                    major_hint = "7.x"
                else:
                    continue

                # Enriquecer la descripción existente sin sobreescribir
                result.php_version = result.php_version.rstrip(")") + f"; fingerprint PHP {major_hint})"
                return
            except Exception:
                continue

    # ── Sondeo: rutas de CMS PHP conocidos ───────────────────────────────────

    def _probe_cms_paths(self, base: str, result: AuditResult) -> None:
        """Confirma PHP mediante rutas características de CMS conocidos."""
        for path, cms_name in self._PHP_CMS_PATHS:
            try:
                url_probe = base + path
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=True)
                if status not in (200, 301, 302, 401, 403):
                    continue
                body_lower = (body[:4096].lower() if body else b"")
                if "wp-login" in path and b"wordpress" not in body_lower and b"wp-" not in body_lower:
                    continue
                if "xmlrpc" in path and b"xml" not in body_lower:
                    continue
                result.php_version = f"detectado (sondeo activo: {cms_name})"
                result.findings.append(self._php_hallazgo_oculto(
                    f"sondeo activo — {cms_name} responde en {path}",
                    "Confirmar la versión exacta de PHP en el servidor con `php --version`.",
                ))
                return
            except Exception:
                continue

    def _probe_open_redirect_active(self, result: AuditResult) -> None:
        """
        Prueba Open Redirect activo: solo actúa si la URL ya contiene parámetros
        de tipo redirect=, url=, next=, returnUrl=, goto=, etc.
        """
        REDIRECT_PARAMS_ACTIVE = [
            "redirect", "url", "next", "returnUrl", "goto", "return_url",
            "redirect_uri", "redirect_url", "destination", "redir", "target",
        ]
        evil_url  = "https://evil.example.com"
        parsed    = urllib.parse.urlparse(result.url)
        params_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Solo probar si la URL ya incluye algún parámetro de redirección
        params_lower_map = {k.lower(): k for k in params_qs}
        found_params = [
            params_lower_map[p.lower()]
            for p in REDIRECT_PARAMS_ACTIVE
            if p.lower() in params_lower_map
        ]

        if not found_params:
            return  # No hay parámetros de redirección en la URL — no procede

        for param in found_params:
            new_params = dict(params_qs)
            new_params[param] = [evil_url]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            probe_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, ""
            ))
            try:
                status, hdrs, _ = self._fetch(probe_url, follow_redirects=False)
                if status in (301, 302, 303, 307, 308):
                    location = hdrs.get("location", "")
                    if evil_url in location or "evil.example.com" in location:
                        result.findings.append(Finding(
                            severity="HIGH", category=str(_T("Active Tests", "Pruebas Activas")),
                            name=str(_T(f"Open Redirect confirmed — parameter '{param}'", f"Open Redirect confirmado — parámetro '{param}'")),
                            detail=(
                                f"El parámetro '{param}' redirige a una URL externa sin validación. "
                                f"Location devuelto: {location[:120]}"
                            ),
                            remediation=str(_R_OPEN_REDIRECT),
                            grade_cap="F",
                        ))
                        break  # Un Open Redirect confirmado es suficiente
            except Exception:
                pass

    def _phase_graphql(self, result: AuditResult) -> None:
        """
        Detecta endpoints GraphQL y verifica si la introspección está habilitada.
        """
        parsed   = urllib.parse.urlparse(result.url)
        base     = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        # Query mínima de detección (sólo pide __typename)
        probe_body = b'{"query":"{ __typename }"}'
        # Query de introspección completa
        intro_body = (
            b'{"query":"query IntrospectionQuery { __schema { '
            b'types { name kind } queryType { name } } }"}'
        )

        introspection_on  : list[str] = []
        endpoint_found    : list[str] = []

        for path in GRAPHQL_PATHS:
            url = f"{base}{path}"
            try:
                status, hdrs, body = self._fetch(
                    url, method="POST",
                    extra_headers={"Content-Type": "application/json"},
                    body=probe_body,
                )
            except Exception:
                continue

            ct = hdrs.get("content-type", "")
            if status not in (200, 400, 422) or "json" not in ct:
                continue

            try:
                data = json.loads(body)
            except Exception:
                continue

            # Presencia confirmada: la respuesta tiene la estructura GraphQL
            if not (isinstance(data, dict) and ("data" in data or "errors" in data)):
                continue

            endpoint_found.append(path)
            result.graphql_endpoints.append(url)

            # Ahora intenta introspección completa
            try:
                _, _, intro_raw = self._fetch(
                    url, method="POST",
                    extra_headers={"Content-Type": "application/json"},
                    body=intro_body,
                )
                intro_data = json.loads(intro_raw)
                schema = (
                    intro_data.get("data", {})
                    .get("__schema", {})
                )
                if schema and schema.get("types"):
                    introspection_on.append(path)
            except Exception:
                pass

        if introspection_on:
            result.findings.append(Finding(
                severity="HIGH", category=str(_T("GraphQL", "GraphQL")),
                name=str(_T(f"GraphQL introspection enabled: {', '.join(introspection_on)}", f"Introspección GraphQL habilitada: {', '.join(introspection_on)}")),
                detail=(
                    f"Los endpoints {introspection_on} responden a consultas de introspección "
                    "y exponen el schema completo de la API (tipos, campos, mutaciones). "
                    "Un atacante puede mapear la superficie de ataque de la API sin autenticación."
                ),
                remediation=str(_R_GRAPHQL_INTROSPECTION), grade_cap="B",
            ))
        elif endpoint_found:
            result.findings.append(Finding(
                severity="MEDIUM", category=str(_T("GraphQL", "GraphQL")),
                name=str(_T(f"GraphQL endpoint detected without introspection: {', '.join(endpoint_found)}", f"Endpoint GraphQL detectado sin introspección: {', '.join(endpoint_found)}")),
                detail=(
                    f"Se detectó presencia de GraphQL en {endpoint_found} "
                    "pero la introspección está deshabilitada (configuración correcta). "
                    "Verificar autenticación, depth limiting y query complexity en producción."
                ),
                remediation=(
                    "Verificar que la autenticación y autorización son correctas en todos los "
                    "resolvers. Implementar depth limiting y query complexity para evitar DoS. "
                    "Ref: OWASP API Security — GraphQL Cheat Sheet"
                ),
                grade_cap="",
            ))
