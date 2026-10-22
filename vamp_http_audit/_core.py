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
                severity="HIGH", category="Cabeceras HTTP",
                name="HSTS ausente",
                detail="Falta Strict-Transport-Security — posibles ataques de downgrade",
                remediation=_R_HSTS_ABSENT, grade_cap="C",
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
                    severity="MEDIUM", category="Cabeceras HTTP",
                    name="HSTS max-age insuficiente",
                    detail=f"max-age={max_age}s — mínimo recomendado 180 días (15 552 000s)",
                    remediation=_R_HSTS_ABSENT, grade_cap="A-",
                ))

        # --- X-Frame-Options ---
        xfo = h.get("x-frame-options")
        if not xfo:
            result.findings.append(Finding(
                severity="MEDIUM", category="Cabeceras HTTP",
                name="X-Frame-Options ausente",
                detail="Sin protección contra clickjacking mediante iframes (sin X-Frame-Options ni frame-ancestors)",
                remediation=_R_XFO_ABSENT, grade_cap="C",
            ))
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name=f"X-Frame-Options con valor no estándar: {xfo}",
                detail="Valor desconocido — los navegadores lo ignorarán",
                remediation=_R_XFO_ABSENT,
            ))

        # --- X-Content-Type-Options ---
        xcto = h.get("x-content-type-options")
        if not xcto:
            result.findings.append(Finding(
                severity="MEDIUM", category="Cabeceras HTTP",
                name="X-Content-Type-Options ausente",
                detail="Posible MIME-type sniffing por el navegador",
                remediation=_R_XCTO_ABSENT, grade_cap="B",
            ))
        elif xcto.lower() != "nosniff":
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name=f"X-Content-Type-Options incorrecto: {xcto}",
                detail="El único valor válido es 'nosniff'",
                remediation=_R_XCTO_ABSENT,
            ))

        # --- Referrer-Policy ---
        rp = h.get("referrer-policy")
        if not rp:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name="Referrer-Policy ausente",
                detail="El navegador usa la política por defecto — puede filtrar URLs completas a terceros",
                remediation=_R_RP_ABSENT, grade_cap="A",
            ))
        elif rp.lower() in UNSAFE_REFERRER_POLICIES:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name=f"Referrer-Policy insegura: {rp}",
                detail=UNSAFE_REFERRER_POLICIES[rp.lower()],
                remediation=_R_RP_ABSENT, grade_cap="A-",
            ))

        # --- Permissions-Policy ---
        pp = h.get("permissions-policy") or h.get("feature-policy")
        if not pp:
            result.findings.append(Finding(
                severity="LOW", category="Cabeceras HTTP",
                name="Permissions-Policy ausente",
                detail="Sin control de APIs del navegador (cámara, micrófono, geolocalización, etc.)",
                remediation=_R_PP_ABSENT, grade_cap="A-",
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
                    severity="LOW", category="Cabeceras HTTP",
                    name="Permissions-Policy: APIs sensibles sin restricción explícita",
                    detail=(
                        f"Las siguientes APIs del navegador no están explícitamente restringidas "
                        f"a '()' o '(self)' en Permissions-Policy: {', '.join(sin_restriccion)}. "
                        "Cualquier script en la página podría acceder a ellas."
                    ),
                    remediation=_R_PP_ABSENT,
                ))

        # ── Sección: Aislamiento Cross-Origin (COEP / COOP / CORP) ─────────────

        # --- Cross-Origin-Embedder-Policy ---
        coep = h.get("cross-origin-embedder-policy")
        if not coep:
            result.findings.append(Finding(
                severity="MEDIUM", category="Aislamiento Cross-Origin",
                name="COEP ausente",
                detail=(
                    "Cross-Origin-Embedder-Policy no configurada. "
                    "Sin esta cabecera el navegador no aísla el contexto de navegación, "
                    "impidiendo el uso seguro de SharedArrayBuffer y dificultando "
                    "la mitigación de ataques Spectre cross-origin."
                ),
                remediation=_R_COEP_ABSENT, grade_cap="B",
            ))
        elif coep.lower() not in ("require-corp", "credentialless"):
            result.findings.append(Finding(
                severity="MEDIUM", category="Aislamiento Cross-Origin",
                name=f"COEP con valor no restrictivo: {coep!r}",
                detail=(
                    f"Cross-Origin-Embedder-Policy está configurada con valor '{coep}', "
                    "que no proporciona aislamiento completo. "
                    "Se recomienda 'require-corp' o 'credentialless'."
                ),
                remediation=_R_COEP_ABSENT, grade_cap="B",
            ))

        # --- Cross-Origin-Opener-Policy ---
        coop = h.get("cross-origin-opener-policy")
        if not coop:
            result.findings.append(Finding(
                severity="MEDIUM", category="Aislamiento Cross-Origin",
                name="COOP ausente",
                detail=(
                    "Cross-Origin-Opener-Policy no configurada. "
                    "Sin esta cabecera la página comparte grupo de contexto de navegación "
                    "con ventanas de otros orígenes, facilitando ataques Spectre y "
                    "el robo de información mediante canales de tiempo."
                ),
                remediation=_R_COOP_ABSENT, grade_cap="B",
            ))
        elif "same-origin" not in coop.lower():
            result.findings.append(Finding(
                severity="MEDIUM", category="Aislamiento Cross-Origin",
                name=f"COOP con valor no restrictivo: {coop!r}",
                detail=(
                    f"Cross-Origin-Opener-Policy está configurada con valor '{coop}', "
                    "que no proporciona aislamiento completo del grupo de contexto. "
                    "Se recomienda 'same-origin'."
                ),
                remediation=_R_COOP_ABSENT, grade_cap="B",
            ))

        # --- Cross-Origin-Resource-Policy ---
        corp = h.get("cross-origin-resource-policy")
        if not corp:
            result.findings.append(Finding(
                severity="LOW", category="Aislamiento Cross-Origin",
                name="CORP ausente",
                detail=(
                    "Cross-Origin-Resource-Policy no configurada. "
                    "Cualquier origen puede incluir estos recursos (imágenes, scripts, etc.) "
                    "en su contexto, facilitando ataques de filtración de datos cross-origin."
                ),
                remediation=_R_CORP_ABSENT, grade_cap="A",
            ))
        elif corp.lower() == "cross-origin":
            result.findings.append(Finding(
                severity="INFO", category="Aislamiento Cross-Origin",
                name="CORP: cross-origin (recurso público)",
                detail="Intencionalmente accesible desde cualquier origen",
            ))

        # --- Content-Security-Policy (presencia) ---
        csp = h.get("content-security-policy")
        if not csp:
            result.findings.append(Finding(
                severity="HIGH", category="CSP",
                name="Content-Security-Policy ausente",
                detail="Sin CSP — sin protección contra inyección de scripts (XSS), clickjacking y data theft",
                remediation=_R_CSP_ABSENT, grade_cap="B",
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
                severity="HIGH", category="CSP",
                name="CSP: 'unsafe-inline' en script-src",
                detail="Permite ejecución de scripts inline — anula la protección XSS de CSP",
                remediation=_R_CSP_UNSAFE_INLINE, grade_cap="A-",
            ))
        if "'unsafe-inline'" in style_src:
            result.findings.append(Finding(
                severity="MEDIUM", category="CSP",
                name="CSP: 'unsafe-inline' en style-src",
                detail="Permite estilos inline — permite CSS injection",
                remediation=_R_CSP_UNSAFE_INLINE, grade_cap="A-",
            ))

        # unsafe-eval
        if "'unsafe-eval'" in script_src:
            result.findings.append(Finding(
                severity="HIGH", category="CSP",
                name="CSP: 'unsafe-eval' en script-src",
                detail="Permite eval() y funciones equivalentes — permite ejecución de código arbitrario",
                remediation=_R_CSP_UNSAFE_EVAL, grade_cap="A-",
            ))

        # Wildcard en fuentes
        for dname, dvals in directives.items():
            if dname in ("report-uri", "report-to", "sandbox"):
                continue
            if "*" in dvals or "http://*" in dvals or "https://*" in dvals:
                result.findings.append(Finding(
                    severity="MEDIUM", category="CSP",
                    name=f"CSP: comodín (*) en {dname}",
                    detail=f"La directiva '{dname}' permite cargar recursos desde cualquier dominio",
                    remediation=_R_CSP_WILDCARD, grade_cap="A-",
                ))

        # frame-ancestors ausente (X-Frame-Options ya puede cubrirlo)
        if "frame-ancestors" not in directives:
            xfo = result.headers.get("x-frame-options")
            if not xfo:
                # Ya existe el hallazgo de XFO ausente — este es complementario
                result.findings.append(Finding(
                    severity="INFO", category="CSP",
                    name="CSP: directiva frame-ancestors ausente",
                    detail="Sin frame-ancestors en CSP ni X-Frame-Options — clickjacking posible vía iframe",
                    remediation=_R_CSP_NO_FRAME_ANCESTORS,
                ))

        # Modo report-only (no aplicado)
        csp_ro = result.headers.get("content-security-policy-report-only")
        if csp_ro and not csp:
            result.findings.append(Finding(
                severity="MEDIUM", category="CSP",
                name="CSP en modo Report-Only (no aplicado)",
                detail="Content-Security-Policy-Report-Only no bloquea nada — es solo monitorización",
                remediation=_R_CSP_ABSENT, grade_cap="B",
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
                    severity="CRITICAL", category="CORS",
                    name="CORS: wildcard (*) + credenciales",
                    detail="Access-Control-Allow-Origin: * con Access-Control-Allow-Credentials: true — "
                           "permite robo de sesión cross-origin",
                    remediation=_R_CORS_WILDCARD_CREDS, grade_cap="F",
                ))
            elif acao == "*":
                result.findings.append(Finding(
                    severity="MEDIUM", category="CORS",
                    name="CORS: wildcard (*) sin credenciales",
                    detail="Cualquier origen puede leer las respuestas — evaluar si es intencional (API pública)",
                    remediation=_R_CORS_WILDCARD, grade_cap="B",
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
                    severity=sev, category="CORS",
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
                    severity="HIGH", category="CORS",
                    name="CORS: acepta origen 'null'",
                    detail="El origen 'null' es generado por iframes sandbox — bypass de restricciones de origen",
                    remediation=_R_CORS_NULL, grade_cap="B",
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
                    category="Cookies",
                    name=f"Cookie sin Secure: {name}",
                    detail=f"La cookie '{name}' se transmite también por HTTP",
                    remediation=_R_COOKIE_NOSECURE,
                    grade_cap="B",
                ))
            if not httponly:
                result.findings.append(Finding(
                    severity="HIGH" if is_session_like else "MEDIUM",
                    category="Cookies",
                    name=f"Cookie sin HttpOnly: {name}",
                    detail=f"La cookie '{name}' es accesible desde JavaScript (riesgo XSS)",
                    remediation=_R_COOKIE_NOHTTPONLY,
                    grade_cap="B",
                ))
            if samesite is None:
                result.findings.append(Finding(
                    severity="LOW",
                    category="Cookies",
                    name=f"Cookie sin SameSite: {name}",
                    detail=f"La cookie '{name}' se envía en peticiones cross-site (riesgo CSRF)",
                    remediation=_R_COOKIE_NOSAMESITE,
                    grade_cap="A",
                ))
            elif samesite.lower() == "none" and not secure:
                result.findings.append(Finding(
                    severity="HIGH",
                    category="Cookies",
                    name=f"Cookie SameSite=None sin Secure: {name}",
                    detail="SameSite=None requiere el flag Secure — los navegadores rechazan la cookie",
                    remediation=_R_COOKIE_NOSECURE,
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

    def _php_hallazgo_oculto(self, senal: str, remediacion_extra: str = "") -> "Finding":
        """Genera un hallazgo MEDIUM estándar para PHP detectado sin versión."""
        base_rem = (
            "Verificar la versión de PHP en el servidor:\n"
            "  php --version\n"
            "Si es vulnerable, actualizar a ≥8.2.35, ≥8.3.36, ≥8.4.27 o ≥8.5.12."
        )
        return Finding(
            severity="MEDIUM",
            category="Vulnerabilidad PHP",
            name=f"PHP detectado — versión oculta ({senal})",
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
        """Evalúa si una versión PHP concreta cae en rangos CVE conocidos y añade el hallazgo."""
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
                category="Vulnerabilidad PHP",
                name=f"PHP/{version} — versión vulnerable ({cve_str})",
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
                    severity="MEDIUM", category="Información",
                    name=f"Server: revela versión — {server}",
                    detail=f"Expone el software y versión del servidor: {server!r}",
                    remediation=_R_SERVER_VERSION, grade_cap="B",
                ))

        # X-Powered-By
        xpb = h.get("x-powered-by", "")
        if xpb:
            result.findings.append(Finding(
                severity="LOW", category="Información",
                name=f"X-Powered-By: revela tecnología — {xpb}",
                detail=f"Expone la tecnología del backend: {xpb!r}",
                remediation=_R_XPOWEREDBY, grade_cap="B",
            ))

        # Cabeceras de versión de frameworks
        for h_name in ("x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-wordpress-hit"):
            val = h.get(h_name)
            if val:
                result.findings.append(Finding(
                    severity="LOW", category="Información",
                    name=f"{h_name}: {val}",
                    detail=f"La cabecera {h_name!r} revela detalles del CMS/framework",
                    remediation=_R_SERVER_VERSION,
                ))

        # Cabeceras de debug
        for h_name, h_val in h.items():
            if h_name.startswith(("x-debug", "x-sf-")) or "debug" in h_name:
                result.findings.append(Finding(
                    severity="MEDIUM", category="Información",
                    name=f"Cabecera de debug expuesta: {h_name}: {h_val[:80]}",
                    detail="Cabeceras de depuración activas en producción — puede revelar rutas y tokens internos",
                    remediation=_R_DEBUG_HEADER, grade_cap="A-",
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
                severity="CRITICAL", category="Open Redirect",
                name=f"Open redirect confirmado: parámetros {', '.join(vulnerable_params)}",
                detail=(
                    f"Los parámetros {vulnerable_params} redirigen a URLs externas sin validación — "
                    "permite phishing y bypass de seguridad"
                ),
                remediation=_R_OPEN_REDIRECT, grade_cap="F",
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
                            severity="INFO", category="Pruebas Activas",
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
                            severity="MEDIUM", category="Pruebas Activas",
                            name=f"Posible IDOR — parámetro '{param_name}'",
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
                    severity="HIGH", category="Pruebas Activas",
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
                    severity="INFO", category="Pruebas Activas",
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
        Sondeo activo de PHP: solo se ejecuta con --active.
        1. Intenta rutas de phpinfo() para extraer la versión exacta.
        2. Si no se encuentra phpinfo, intenta rutas de CMS PHP conocidos.
        No sobreescribe una detección pasiva ya confirmada con versión numérica.
        """
        # Si ya tenemos versión exacta (detectada pasivamente), no hace falta sondear
        if result.php_version and re.match(r"\d+\.\d+\.\d+", result.php_version):
            return

        parsed = urllib.parse.urlparse(result.final_url or result.url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Rutas de phpinfo()
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
                # Confirmar que es una página phpinfo real
                body_lower = body[:32768].lower()
                if b"phpinfo()" not in body_lower and b"php version" not in body_lower:
                    continue
                # Intentar extraer la versión
                m = phpinfo_re.search(body[:32768])
                if m:
                    version = m.group(1).decode("ascii", errors="replace")
                    result.php_version = version
                    # Evaluar CVEs con la versión encontrada
                    self._evaluar_php_cves(result, version)
                    # Si no hay CVE añade un hallazgo informativo de exposición
                    if not result.php_vulnerable:
                        result.findings.append(Finding(
                            severity="HIGH",
                            category="Vulnerabilidad PHP",
                            name=f"phpinfo() expuesto en {path}",
                            detail=(
                                f"La ruta {url_probe} devuelve phpinfo() completo (PHP {version}). "
                                "Expone versión exacta, variables de entorno, configuración, rutas del sistema "
                                "y módulos cargados — información muy valiosa para un atacante."
                            ),
                            remediation=(
                                "Eliminar o restringir el acceso a phpinfo() en producción:\n"
                                f"  rm {path}   (o equivalente en la docroot)\n"
                                "  O protegerlo con autenticación básica desde nginx/apache."
                            ),
                            grade_cap="C",
                        ))
                    else:
                        # Añadir el contexto de exposición al hallazgo CVE
                        result.findings.append(Finding(
                            severity="HIGH",
                            category="Vulnerabilidad PHP",
                            name=f"phpinfo() expuesto en {path}",
                            detail=f"La ruta {url_probe} confirma PHP {version} y expone la configuración completa.",
                            remediation=f"Eliminar {path} de la docroot inmediatamente.",
                            grade_cap="C",
                        ))
                    return
                else:
                    # phpinfo sin versión extraíble — todavía es una exposición
                    result.php_version = "detectado (phpinfo expuesto, versión no extraída)"
                    result.findings.append(Finding(
                        severity="HIGH",
                        category="Vulnerabilidad PHP",
                        name=f"phpinfo() expuesto en {path}",
                        detail=(
                            f"La ruta {url_probe} devuelve phpinfo() pero no se pudo extraer la versión exacta. "
                            "Expone configuración sensible del servidor."
                        ),
                        remediation=f"Eliminar {path} de la docroot.",
                        grade_cap="C",
                    ))
                    return
            except Exception:
                continue

        # 2. Rutas de CMS PHP conocidos (solo si no tenemos detección previa)
        if result.php_version:
            return

        for path, cms_name in self._PHP_CMS_PATHS:
            try:
                url_probe = base + path
                status, hdrs, body = self._fetch(url_probe, method="GET", follow_redirects=True)
                if status not in (200, 302, 301, 401, 403):
                    continue
                # Para wp-login y xmlrpc, confirmar contenido WordPress
                body_lower = (body[:4096].lower() if body else b"")
                if "wp-login" in path and b"wordpress" not in body_lower and b"wp-" not in body_lower:
                    continue
                if "xmlrpc" in path and b"xml" not in body_lower:
                    continue
                result.php_version = f"detectado (sondeo activo: {cms_name})"
                result.findings.append(self._php_hallazgo_oculto(
                    f"sondeo activo — {cms_name} responde en {path}",
                    f"Confirmar la versión exacta de PHP en el servidor con `php --version`.",
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
                            severity="HIGH", category="Pruebas Activas",
                            name=f"Open Redirect confirmado — parámetro '{param}'",
                            detail=(
                                f"El parámetro '{param}' redirige a una URL externa sin validación. "
                                f"Location devuelto: {location[:120]}"
                            ),
                            remediation=_R_OPEN_REDIRECT,
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
                severity="HIGH", category="GraphQL",
                name=f"Introspección GraphQL habilitada: {', '.join(introspection_on)}",
                detail=(
                    f"Los endpoints {introspection_on} responden a consultas de introspección "
                    "y exponen el schema completo de la API (tipos, campos, mutaciones). "
                    "Un atacante puede mapear la superficie de ataque de la API sin autenticación."
                ),
                remediation=_R_GRAPHQL_INTROSPECTION, grade_cap="B",
            ))
        elif endpoint_found:
            result.findings.append(Finding(
                severity="MEDIUM", category="GraphQL",
                name=f"Endpoint GraphQL detectado sin introspección: {', '.join(endpoint_found)}",
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
