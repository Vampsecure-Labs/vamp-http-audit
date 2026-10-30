# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constantes, tipos de datos y estructuras para vamp-http-audit.
Sin I/O ni interfaz de usuario: solo tipos y valores inmutables.
"""

from __future__ import annotations

from dataclasses import dataclass, field

VERSION   = "1.6.0"
TOOL_NAME = "vamp-http-audit"

LANG: str = "en"  # overridden by CLI: _models.LANG = args.lang


class _T:
    """Lazy bilingual string — resolves at str() time, not at definition time."""
    __slots__ = ("_en", "_es")

    def __init__(self, en: str, es: str) -> None:
        self._en, self._es = en, es

    def __str__(self) -> str:
        return self._es if LANG == "es" else self._en

    def __repr__(self) -> str:
        return str(self)

    def format(self, **kw: object) -> str:
        return str(self).format(**kw)

# ---------------------------------------------------------------------------
# Sistema de calificación
# ---------------------------------------------------------------------------

GRADE_ORDER_LIST = ["A+", "A", "A-", "B", "C", "D", "T", "F"]

GRADE_COLOR: dict[str, str] = {
    "A+": "bold bright_green",
    "A":  "bold green",
    "A-": "bold yellow",
    "B":  "bold yellow",
    "C":  "bold dark_orange",
    "D":  "bold red3",
    "T":  "bold magenta",
    "F":  "bold red",
}

GRADE_DESCRIPTION: dict[str, _T] = {
    "A+": _T("Exceptional HTTP configuration — all best practices met",
             "Configuración HTTP excepcional — todas las mejores prácticas cumplidas"),
    "A":  _T("Good HTTP configuration — no significant issues",
             "Buena configuración HTTP — sin problemas significativos"),
    "A-": _T("Good HTTP configuration — CSP or Referrer-Policy improvable",
             "Buena configuración HTTP — CSP o Referrer-Policy mejorables"),
    "B":  _T("Acceptable HTTP configuration — key headers absent or weakened",
             "Configuración HTTP aceptable — cabeceras clave ausentes o debilitadas"),
    "C":  _T("Poor HTTP configuration — clickjacking or downgrade possible",
             "Configuración HTTP deficiente — clickjacking o downgrade posibles"),
    "D":  _T("Very poor HTTP configuration",
             "Configuración HTTP muy deficiente"),
    "T":  _T("N/A (ssl-audit specific use)",
             "N/A (uso específico de ssl-audit)"),
    "F":  _T("Critical HTTP failure — CORS+credentials or open redirect confirmed",
             "Fallo crítico HTTP — CORS+credenciales o open redirect confirmado"),
}

HTML_GRADE_COLOR: dict[str, tuple[str, str]] = {
    "A+": ("grade-aplus",  "#00cc55"),
    "A":  ("grade-a",      "#22aa44"),
    "A-": ("grade-aminus", "#aacc00"),
    "B":  ("grade-b",      "#ffcc00"),
    "C":  ("grade-c",      "#ff8800"),
    "D":  ("grade-d",      "#ff5500"),
    "T":  ("grade-t",      "#cc44cc"),
    "F":  ("grade-f",      "#ff2222"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}

# Parámetros típicos usados en open redirects
REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "goto", "destination",
    "redir", "target", "link", "forward", "location", "rurl",
    "returl", "redirect_uri", "redirect_url", "return_url",
]

# Rutas canónicas donde suele encontrarse un endpoint GraphQL
GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphql/v1", "/api/v1/graphql",
    "/query", "/gql", "/v1/graphql", "/api/query",
]

# Valores de Referrer-Policy considerados inseguros
UNSAFE_REFERRER_POLICIES: dict[str, _T] = {
    "unsafe-url":                   _T("Sends full URL (with path and query) in all requests",
                                       "Envía URL completa (con path y query) en todas las peticiones"),
    "no-referrer-when-downgrade":   _T("Sends full URL to HTTPS; default policy in old browsers",
                                       "Envía URL completa a HTTPS; política por defecto de navegadores antiguos"),
    "origin-when-cross-origin":     _T("Sends full URL on same origin; origin only on cross-origin",
                                       "Envía URL completa en mismo origen; origen en cross-origin"),
}

# ---------------------------------------------------------------------------
# Textos de remediación
# ---------------------------------------------------------------------------

_R_CSP_ABSENT = _T(
    "Add a Content-Security-Policy header to the server:\n"
    "  nginx:  add_header Content-Security-Policy \"default-src 'self'; "
    "script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self';\";\n"
    "  apache: Header always set Content-Security-Policy \"...\"\n"
    "Validate the policy at https://csp-evaluator.withgoogle.com\n"
    "Ref: W3C CSP Level 3 · OWASP Secure Headers Project",
    "Añadir Content-Security-Policy al servidor:\n"
    "  nginx:  add_header Content-Security-Policy \"default-src 'self'; "
    "script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self';\";\n"
    "  apache: Header always set Content-Security-Policy \"...\"\n"
    "Usar https://csp-evaluator.withgoogle.com para validar la política.\n"
    "Ref: W3C CSP Level 3 · OWASP Secure Headers Project",
)
_R_CSP_UNSAFE_INLINE = _T(
    "Remove 'unsafe-inline' from script-src and style-src:\n"
    "  · Move inline scripts to external .js files referenced with 'self'\n"
    "  · If unavoidable, use nonces (nonce-<base64>) or SHA-256 hashes\n"
    "    script-src 'nonce-rAnd0m' 'strict-dynamic';\n"
    "Ref: CSP3 §4.2.2 — 'unsafe-inline' disables CSP XSS protection",
    "Eliminar 'unsafe-inline' de script-src y style-src:\n"
    "  · Mover scripts inline a ficheros .js externos referenciados con 'self'\n"
    "  · Si imprescindible, usar nonces (nonce-<base64>) o hashes SHA-256\n"
    "    script-src 'nonce-rAnd0m' 'strict-dynamic';\n"
    "Ref: CSP3 §4.2.2 — 'unsafe-inline' anula la protección XSS de CSP",
)
_R_CSP_UNSAFE_EVAL = _T(
    "Remove 'unsafe-eval' from script-src:\n"
    "  · Avoid eval(), new Function(), setTimeout(string), setInterval(string)\n"
    "  · Migrate libraries that use it (AngularJS legacy → Angular, etc.)\n"
    "Ref: CSP3 §4.2.2 — 'unsafe-eval' allows arbitrary code execution",
    "Eliminar 'unsafe-eval' de script-src:\n"
    "  · Evitar eval(), new Function(), setTimeout(string), setInterval(string)\n"
    "  · Migrar librerías que lo usan (AngularJS legacy → Angular, etc.)\n"
    "Ref: CSP3 §4.2.2 — 'unsafe-eval' permite ejecución de código arbitrario",
)
_R_CSP_WILDCARD = _T(
    "Remove wildcard (*) sources from CSP directives:\n"
    "  · Explicitly list each allowed domain\n"
    "  · Replace * with 'none' or specific domains (cdn.example.com)\n"
    "A wildcard removes the origin restriction for that directive.",
    "Eliminar fuentes comodín (*) de las directivas CSP:\n"
    "  · Especificar explícitamente cada dominio permitido\n"
    "  · Sustituir * por 'none' o dominios concretos (cdn.ejemplo.com)\n"
    "Un comodín anula la restricción de origen de esa directiva.",
)
_R_CSP_NO_FRAME_ANCESTORS = _T(
    "Add a frame-ancestors directive to prevent clickjacking:\n"
    "  frame-ancestors 'none'                         (never embeddable)\n"
    "  frame-ancestors 'self'                          (same origin only)\n"
    "  frame-ancestors https://app.example.com         (specific origin)\n"
    "Note: frame-ancestors overrides X-Frame-Options when CSP is present.",
    "Añadir directiva frame-ancestors para prevenir clickjacking:\n"
    "  frame-ancestors 'none'         (nunca embebible en iframe)\n"
    "  frame-ancestors 'self'          (solo el propio origen)\n"
    "  frame-ancestors https://app.ejemplo.com  (origen específico)\n"
    "Nota: frame-ancestors anula X-Frame-Options si CSP está presente.",
)
_R_HSTS_ABSENT = _T(
    "Add HSTS to enforce HTTPS connections:\n"
    "  nginx:   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\n"
    "  apache:  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'\n"
    "Ref: RFC 6797 · Register at hstspreload.org for browser preload",
    "Añadir HSTS para forzar conexiones HTTPS:\n"
    "  nginx:   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\n"
    "  apache:  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'\n"
    "Ref: RFC 6797 · Registrar en hstspreload.org para preload de navegadores",
)
_R_XFO_ABSENT = _T(
    "Add X-Frame-Options to protect against clickjacking:\n"
    "  nginx:   add_header X-Frame-Options DENY;\n"
    "  apache:  Header always set X-Frame-Options DENY\n"
    "Preferred: use CSP frame-ancestors (finer-grained control).\n"
    "Use SAMEORIGIN if the app embeds its own content.",
    "Añadir X-Frame-Options para proteger contra clickjacking:\n"
    "  nginx:   add_header X-Frame-Options DENY;\n"
    "  apache:  Header always set X-Frame-Options DENY\n"
    "Preferible: usar CSP frame-ancestors (mayor control granular).\n"
    "Usar SAMEORIGIN si la app embebe su propio contenido.",
)
_R_XCTO_ABSENT = _T(
    "Add X-Content-Type-Options: nosniff:\n"
    "  nginx:   add_header X-Content-Type-Options nosniff;\n"
    "  apache:  Header always set X-Content-Type-Options nosniff\n"
    "Prevents the browser from interpreting files with an incorrect MIME type.",
    "Añadir X-Content-Type-Options: nosniff:\n"
    "  nginx:   add_header X-Content-Type-Options nosniff;\n"
    "  apache:  Header always set X-Content-Type-Options nosniff\n"
    "Previene que el navegador interprete ficheros con MIME incorrecto.",
)
_R_RP_ABSENT = _T(
    "Add Referrer-Policy to control what information is sent:\n"
    "  Recommended: Referrer-Policy: strict-origin-when-cross-origin\n"
    "  Stricter:    Referrer-Policy: no-referrer\n"
    "  nginx:   add_header Referrer-Policy strict-origin-when-cross-origin;\n"
    "  apache:  Header always set Referrer-Policy strict-origin-when-cross-origin",
    "Añadir Referrer-Policy para controlar la información enviada:\n"
    "  Recomendado: Referrer-Policy: strict-origin-when-cross-origin\n"
    "  Más restrictivo: Referrer-Policy: no-referrer\n"
    "  nginx:   add_header Referrer-Policy strict-origin-when-cross-origin;\n"
    "  apache:  Header always set Referrer-Policy strict-origin-when-cross-origin",
)
_R_PP_ABSENT = _T(
    "Add Permissions-Policy to restrict browser APIs:\n"
    "  nginx:   add_header Permissions-Policy 'camera=(), microphone=(), geolocation=(), payment=()';\n"
    "  apache:  Header always set Permissions-Policy 'camera=(), microphone=(), geolocation=()'\n"
    "Ref: W3C Permissions Policy (formerly Feature-Policy)",
    "Añadir Permissions-Policy para controlar APIs del navegador:\n"
    "  nginx:   add_header Permissions-Policy 'camera=(), microphone=(), geolocation=(), payment=()';\n"
    "  apache:  Header always set Permissions-Policy 'camera=(), microphone=(), geolocation=()'\n"
    "Ref: W3C Permissions Policy (antes Feature-Policy)",
)
_R_COEP_ABSENT = _T(
    "Add Cross-Origin-Embedder-Policy to isolate the browsing context:\n"
    "  Cross-Origin-Embedder-Policy: require-corp\n"
    "Required to use SharedArrayBuffer and performance.measureUserAgentSpecificMemory().\n"
    "Embedded resources must add Cross-Origin-Resource-Policy.",
    "Añadir Cross-Origin-Embedder-Policy para aislar el contexto de navegación:\n"
    "  Cross-Origin-Embedder-Policy: require-corp\n"
    "Prerequisito para usar SharedArrayBuffer y performance.measureUserAgentSpecificMemory().\n"
    "Los recursos embebidos deben añadir Cross-Origin-Resource-Policy.",
)
_R_COOP_ABSENT = _T(
    "Add Cross-Origin-Opener-Policy to protect the browsing context group:\n"
    "  Cross-Origin-Opener-Policy: same-origin\n"
    "Prevents cross-origin Spectre attacks and isolates the window context.",
    "Añadir Cross-Origin-Opener-Policy para proteger el grupo de contexto de navegación:\n"
    "  Cross-Origin-Opener-Policy: same-origin\n"
    "Previene ataques Spectre cross-origin y aisla el contexto de la ventana.",
)
_R_CORP_ABSENT = _T(
    "Add Cross-Origin-Resource-Policy to control who can include resources:\n"
    "  Cross-Origin-Resource-Policy: same-origin   (same origin only)\n"
    "  Cross-Origin-Resource-Policy: same-site      (same site)\n"
    "  Cross-Origin-Resource-Policy: cross-origin   (anyone — risk)",
    "Añadir Cross-Origin-Resource-Policy para controlar quién puede incluir los recursos:\n"
    "  Cross-Origin-Resource-Policy: same-origin   (solo mismo origen)\n"
    "  Cross-Origin-Resource-Policy: same-site      (mismo sitio)\n"
    "  Cross-Origin-Resource-Policy: cross-origin   (cualquiera — riesgo)",
)
_R_CORS_WILDCARD_CREDS = _T(
    "CRITICAL: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true\n"
    "is an invalid configuration per spec (browsers reject it),\n"
    "but some misconfigured servers emit the attacker's origin reflected instead.\n"
    "Fix:\n"
    "  · Maintain an allowlist of permitted origins and reflect only authorised ones\n"
    "  · NEVER use * when credentials are needed\n"
    "  · nginx: add_header Access-Control-Allow-Origin $http_origin if in allowlist",
    "CRÍTICO: Access-Control-Allow-Origin: * con Access-Control-Allow-Credentials: true\n"
    "es una configuración inválida según la spec (los navegadores la rechazan),\n"
    "pero algunos servidores mal configurados la emiten con el origen del atacante reflejado.\n"
    "Solución:\n"
    "  · Mantener una lista blanca de orígenes permitidos y reflejar solo los autorizados\n"
    "  · NUNCA usar * cuando se necesitan credenciales\n"
    "  · nginx: add_header Access-Control-Allow-Origin $http_origin si está en la whitelist",
)
_R_CORS_WILDCARD = _T(
    "Access-Control-Allow-Origin: * allows any origin to read responses.\n"
    "Fix if specific CORS is needed:\n"
    "  · Define an origin allowlist and reflect only authorised origins\n"
    "  · For a public API, * may be intentional (assess the risk)",
    "Access-Control-Allow-Origin: * permite que cualquier origen lea las respuestas.\n"
    "Solución si se necesita CORS específico:\n"
    "  · Definir lista blanca de orígenes y reflejar solo los autorizados\n"
    "  · Si es una API pública, * puede ser intencional (evaluar el riesgo)",
)
_R_CORS_REFLECT = _T(
    "The server reflects the attacker's Origin in Access-Control-Allow-Origin.\n"
    "This allows cross-origin reads if credentials are present.\n"
    "Fix:\n"
    "  · Validate Origin against a strict allowlist before reflecting it\n"
    "  · Do not use permissive regex (evil.com.trusted.com)\n"
    "  · Respond without ACAO if the origin is not authorised",
    "El servidor refleja el Origin del atacante en Access-Control-Allow-Origin.\n"
    "Esto permite lectura cross-origin si hay credenciales.\n"
    "Solución:\n"
    "  · Validar Origin contra una lista blanca estricta antes de reflejarlo\n"
    "  · No usar expresiones regulares permisivas (evil.com.trusted.com)\n"
    "  · Responder sin ACAO si el origen no está autorizado",
)
_R_CORS_NULL = _T(
    "The server accepts the 'null' origin, used by sandboxed iframes and redirects.\n"
    "Fix: Do not include 'null' as an allowed origin in CORS validation.",
    "El servidor acepta el origen 'null', usado por iframes sandbox y redirecciones.\n"
    "Solución: No incluir 'null' como origen permitido en la validación CORS.",
)
_R_COOKIE_NOSECURE = _T(
    "The cookie is also transmitted over HTTP (missing Secure flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "The Secure flag ensures the cookie is only sent over HTTPS.",
    "La cookie se transmite también por HTTP (sin Secure flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "El flag Secure asegura que la cookie solo se envíe por HTTPS.",
)
_R_COOKIE_NOHTTPONLY = _T(
    "The cookie is accessible from JavaScript (missing HttpOnly flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "HttpOnly prevents cookie theft via XSS.",
    "La cookie es accesible desde JavaScript (sin HttpOnly flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "HttpOnly previene el robo de cookies mediante XSS.",
)
_R_COOKIE_NOSAMESITE = _T(
    "The cookie is sent on cross-site requests (missing SameSite flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "SameSite=Strict: same-origin requests only\n"
    "SameSite=Lax: allows top-level navigation cross-site GET\n"
    "SameSite=None: cross-site (requires Secure)",
    "La cookie se envía en peticiones cross-site (sin SameSite flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "SameSite=Strict: solo peticiones del mismo origen\n"
    "SameSite=Lax: permite GET top-level navigation cross-site\n"
    "SameSite=None: cross-site (requiere Secure)",
)
_R_SERVER_VERSION = _T(
    "Hide the server version to make fingerprinting harder:\n"
    "  nginx:   server_tokens off;  (in http block)\n"
    "  apache:  ServerTokens Prod\n"
    "           ServerSignature Off\n"
    "  haproxy: http-response del-header Server",
    "Ocultar la versión del servidor para dificultar el fingerprinting:\n"
    "  nginx:   server_tokens off;  (en http block)\n"
    "  apache:  ServerTokens Prod\n"
    "           ServerSignature Off\n"
    "  haproxy: http-response del-header Server",
)
_R_XPOWEREDBY = _T(
    "Remove the X-Powered-By header that reveals server technology:\n"
    "  PHP:     expose_php = Off  (in php.ini)\n"
    "  Express: app.disable('x-powered-by');\n"
    "  nginx:   fastcgi_hide_header X-Powered-By;\n"
    "  apache:  Header always unset X-Powered-By",
    "Eliminar cabecera X-Powered-By que revela la tecnología del servidor:\n"
    "  PHP:     expose_php = Off  (en php.ini)\n"
    "  Express: app.disable('x-powered-by');\n"
    "  nginx:   fastcgi_hide_header X-Powered-By;\n"
    "  apache:  Header always unset X-Powered-By",
)
_R_OPEN_REDIRECT = _T(
    "CRITICAL: Strictly validate redirect parameters:\n"
    "  · Use an allowlist of permitted destination URLs/domains\n"
    "  · Never redirect to an external value without validation\n"
    "  · Use relative redirects instead of absolute ones where possible\n"
    "  · Add a CSRF token to redirect parameters\n"
    "Ref: OWASP A01:2021 (Broken Access Control)",
    "CRÍTICO: Validar estrictamente los parámetros de redirección:\n"
    "  · Usar lista blanca de URLs/dominios de destino permitidos\n"
    "  · Nunca redirigir a un valor externo sin validación\n"
    "  · Usar redirecciones relativas en lugar de absolutas cuando sea posible\n"
    "  · Añadir token CSRF a los parámetros de redirección\n"
    "Ref: OWASP A01:2021 (Broken Access Control)",
)
_R_DEBUG_HEADER = _T(
    "Remove debug headers exposed in production:\n"
    "  · Configure the framework not to emit debug headers\n"
    "  · nginx:  proxy_hide_header X-Debug-Token;\n"
    "  · Review environment configuration (DEBUG=False in Django/Flask)",
    "Eliminar cabeceras de debug expuestas en producción:\n"
    "  · Configurar el framework para no emitir cabeceras de depuración\n"
    "  · nginx:  proxy_hide_header X-Debug-Token;\n"
    "  · Revisar la configuración de entorno (DEBUG=False en Django/Flask)",
)
_R_GRAPHQL_INTROSPECTION = _T(
    "Disable GraphQL introspection in production environments:\n"
    "  · Apollo Server: introspection: false (NODE_ENV=production disables it by default)\n"
    "  · GraphQL Yoga: useCSRFPrevention: true + disable introspection in prod\n"
    "  · Hasura: HASURA_GRAPHQL_ENABLE_CONSOLE=false + disable schema introspection\n"
    "  · graphene-django: GRAPHENE = {'SCHEMA': ..., 'INTROSPECTION': False}\n"
    "  · Alternative: restrict introspection by role (authenticated admin only)\n"
    "Ref: OWASP API Security Top 10 — API8:2023 (Security Misconfiguration)",
    "Deshabilitar la introspección GraphQL en entornos de producción:\n"
    "  · Apollo Server: introspection: false (NODE_ENV=production lo deshabilita por defecto)\n"
    "  · GraphQL Yoga: useCSRFPrevention: true + deshabilitar introspección en prod\n"
    "  · Hasura: HASURA_GRAPHQL_ENABLE_CONSOLE=false + deshabilitar schema introspection\n"
    "  · graphene-django: GRAPHENE = {'SCHEMA': ..., 'INTROSPECTION': False}\n"
    "  · Alternativa: limitar introspección por rol (sólo admin autenticado)\n"
    "Ref: OWASP API Security Top 10 — API8:2023 (Security Misconfiguration)",
)

# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Hallazgo de seguridad con remediación y cap de nota."""
    severity:    str
    category:    str
    name:        str
    detail:      str
    remediation: str = ""
    grade_cap:   str = ""

    @property
    def order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class CookieInfo:
    """Datos de una cookie extraída de Set-Cookie."""
    name:          str
    value_preview: str  # Solo primeros caracteres, nunca el valor completo
    secure:        bool
    httponly:      bool
    samesite:      str | None  # Strict / Lax / None / None (ausente)
    path:          str
    domain:        str
    host_prefix:   bool  # __Host-
    secure_prefix: bool  # __Secure-


@dataclass
class AuditResult:
    """Resultado completo de la auditoría HTTP de una URL."""
    url:            str
    final_url:      str   # URL tras posibles redirecciones
    timestamp:      str
    status_code:    int = 0
    # Cabeceras de la respuesta (normalizadas a minúsculas)
    headers:        dict[str, str] = field(default_factory=dict)
    # Cookies detectadas
    cookies:        list[CookieInfo] = field(default_factory=list)
    # Resultados de pruebas específicas
    cors_origin_reflected: bool = False
    cors_origin_value:     str  = ""
    cors_credentials:      bool = False
    cors_null_accepted:    bool = False
    open_redirect_params:  list[str] = field(default_factory=list)  # Parámetros vulnerables
    graphql_endpoints:     list[str] = field(default_factory=list)  # Endpoints GraphQL encontrados
    # Detección de versión PHP y vulnerabilidades conocidas
    php_version:    str  = ""    # p.ej. "8.3.12" si se detecta, "detectado (versión oculta)" si hay PHPSESSID/firmas
    php_vulnerable: bool = False # True si la versión cae en un rango CVE conocido
    php_cves:       list[str] = field(default_factory=list)  # CVEs aplicables
    # Body de la respuesta principal (uso interno, no se exporta en JSON)
    _raw_body:      bytes = field(default_factory=bytes, repr=False, compare=False)
    # Hallazgos
    findings:       list[Finding] = field(default_factory=list)
    grade:          str = ""
    error:          str | None = None

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return min(self.findings, key=lambda f: f.order).severity

    @property
    def target(self) -> str:
        return self.url
