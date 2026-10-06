# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constantes, tipos de datos y estructuras para vamp-http-audit.
Sin I/O ni interfaz de usuario: solo tipos y valores inmutables.
"""

from __future__ import annotations

from dataclasses import dataclass, field

VERSION   = "1.3.0"
TOOL_NAME = "vamp-http-audit"

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

GRADE_DESCRIPTION: dict[str, str] = {
    "A+": "Configuración HTTP excepcional — todas las mejores prácticas cumplidas",
    "A":  "Buena configuración HTTP — sin problemas significativos",
    "A-": "Buena configuración HTTP — CSP o Referrer-Policy mejorables",
    "B":  "Configuración HTTP aceptable — cabeceras clave ausentes o debilitadas",
    "C":  "Configuración HTTP deficiente — clickjacking o downgrade posibles",
    "D":  "Configuración HTTP muy deficiente",
    "T":  "N/A (uso específico de ssl-audit)",
    "F":  "Fallo crítico HTTP — CORS+credenciales o open redirect confirmado",
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
UNSAFE_REFERRER_POLICIES = {
    "unsafe-url":                   "Envía URL completa (con path y query) en todas las peticiones",
    "no-referrer-when-downgrade":   "Envía URL completa a HTTPS; política por defecto de navegadores antiguos",
    "origin-when-cross-origin":     "Envía URL completa en mismo origen; origen en cross-origin",
}

# ---------------------------------------------------------------------------
# Textos de remediación
# ---------------------------------------------------------------------------

_R_CSP_ABSENT = (
    "Añadir Content-Security-Policy al servidor:\n"
    "  nginx:  add_header Content-Security-Policy \"default-src 'self'; "
    "script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self';\";\n"
    "  apache: Header always set Content-Security-Policy \"...\"\n"
    "Usar https://csp-evaluator.withgoogle.com para validar la política.\n"
    "Ref: W3C CSP Level 3 · OWASP Secure Headers Project"
)
_R_CSP_UNSAFE_INLINE = (
    "Eliminar 'unsafe-inline' de script-src y style-src:\n"
    "  · Mover scripts inline a ficheros .js externos referenciados con 'self'\n"
    "  · Si imprescindible, usar nonces (nonce-<base64>) o hashes SHA-256\n"
    "    script-src 'nonce-rAnd0m' 'strict-dynamic';\n"
    "Ref: CSP3 §4.2.2 — 'unsafe-inline' anula la protección XSS de CSP"
)
_R_CSP_UNSAFE_EVAL = (
    "Eliminar 'unsafe-eval' de script-src:\n"
    "  · Evitar eval(), new Function(), setTimeout(string), setInterval(string)\n"
    "  · Migrar librerías que lo usan (AngularJS legacy → Angular, etc.)\n"
    "Ref: CSP3 §4.2.2 — 'unsafe-eval' permite ejecución de código arbitrario"
)
_R_CSP_WILDCARD = (
    "Eliminar fuentes comodín (*) de las directivas CSP:\n"
    "  · Especificar explícitamente cada dominio permitido\n"
    "  · Sustituir * por 'none' o dominios concretos (cdn.ejemplo.com)\n"
    "Un comodín anula la restricción de origen de esa directiva."
)
_R_CSP_NO_FRAME_ANCESTORS = (
    "Añadir directiva frame-ancestors para prevenir clickjacking:\n"
    "  frame-ancestors 'none'         (nunca embebible en iframe)\n"
    "  frame-ancestors 'self'          (solo el propio origen)\n"
    "  frame-ancestors https://app.ejemplo.com  (origen específico)\n"
    "Nota: frame-ancestors anula X-Frame-Options si CSP está presente."
)
_R_HSTS_ABSENT = (
    "Añadir HSTS para forzar conexiones HTTPS:\n"
    "  nginx:   add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\n"
    "  apache:  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'\n"
    "Ref: RFC 6797 · Registrar en hstspreload.org para preload de navegadores"
)
_R_XFO_ABSENT = (
    "Añadir X-Frame-Options para proteger contra clickjacking:\n"
    "  nginx:   add_header X-Frame-Options DENY;\n"
    "  apache:  Header always set X-Frame-Options DENY\n"
    "Preferible: usar CSP frame-ancestors (mayor control granular).\n"
    "Usar SAMEORIGIN si la app embebe su propio contenido."
)
_R_XCTO_ABSENT = (
    "Añadir X-Content-Type-Options: nosniff:\n"
    "  nginx:   add_header X-Content-Type-Options nosniff;\n"
    "  apache:  Header always set X-Content-Type-Options nosniff\n"
    "Previene que el navegador interprete ficheros con MIME incorrecto."
)
_R_RP_ABSENT = (
    "Añadir Referrer-Policy para controlar la información enviada:\n"
    "  Recomendado: Referrer-Policy: strict-origin-when-cross-origin\n"
    "  Más restrictivo: Referrer-Policy: no-referrer\n"
    "  nginx:   add_header Referrer-Policy strict-origin-when-cross-origin;\n"
    "  apache:  Header always set Referrer-Policy strict-origin-when-cross-origin"
)
_R_PP_ABSENT = (
    "Añadir Permissions-Policy para controlar APIs del navegador:\n"
    "  nginx:   add_header Permissions-Policy 'camera=(), microphone=(), geolocation=(), payment=()';\n"
    "  apache:  Header always set Permissions-Policy 'camera=(), microphone=(), geolocation=()'\n"
    "Ref: W3C Permissions Policy (antes Feature-Policy)"
)
_R_COEP_ABSENT = (
    "Añadir Cross-Origin-Embedder-Policy para aislar el contexto de navegación:\n"
    "  Cross-Origin-Embedder-Policy: require-corp\n"
    "Prerequisito para usar SharedArrayBuffer y performance.measureUserAgentSpecificMemory().\n"
    "Los recursos embebidos deben añadir Cross-Origin-Resource-Policy."
)
_R_COOP_ABSENT = (
    "Añadir Cross-Origin-Opener-Policy para proteger el grupo de contexto de navegación:\n"
    "  Cross-Origin-Opener-Policy: same-origin\n"
    "Previene ataques Spectre cross-origin y aisla el contexto de la ventana."
)
_R_CORP_ABSENT = (
    "Añadir Cross-Origin-Resource-Policy para controlar quién puede incluir los recursos:\n"
    "  Cross-Origin-Resource-Policy: same-origin   (solo mismo origen)\n"
    "  Cross-Origin-Resource-Policy: same-site      (mismo sitio)\n"
    "  Cross-Origin-Resource-Policy: cross-origin   (cualquiera — riesgo)"
)
_R_CORS_WILDCARD_CREDS = (
    "CRÍTICO: Access-Control-Allow-Origin: * con Access-Control-Allow-Credentials: true\n"
    "es una configuración inválida según la spec (los navegadores la rechazan),\n"
    "pero algunos servidores mal configurados la emiten con el origen del atacante reflejado.\n"
    "Solución:\n"
    "  · Mantener una lista blanca de orígenes permitidos y reflejar solo los autorizados\n"
    "  · NUNCA usar * cuando se necesitan credenciales\n"
    "  · nginx: add_header Access-Control-Allow-Origin $http_origin si está en la whitelist"
)
_R_CORS_WILDCARD = (
    "Access-Control-Allow-Origin: * permite que cualquier origen lea las respuestas.\n"
    "Solución si se necesita CORS específico:\n"
    "  · Definir lista blanca de orígenes y reflejar solo los autorizados\n"
    "  · Si es una API pública, * puede ser intencional (evaluar el riesgo)"
)
_R_CORS_REFLECT = (
    "El servidor refleja el Origin del atacante en Access-Control-Allow-Origin.\n"
    "Esto permite lectura cross-origin si hay credenciales.\n"
    "Solución:\n"
    "  · Validar Origin contra una lista blanca estricta antes de reflejarlo\n"
    "  · No usar expresiones regulares permisivas (evil.com.trusted.com)\n"
    "  · Responder sin ACAO si el origen no está autorizado"
)
_R_CORS_NULL = (
    "El servidor acepta el origen 'null', usado por iframes sandbox y redirecciones.\n"
    "Solución: No incluir 'null' como origen permitido en la validación CORS."
)
_R_COOKIE_NOSECURE = (
    "La cookie se transmite también por HTTP (sin Secure flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "El flag Secure asegura que la cookie solo se envíe por HTTPS."
)
_R_COOKIE_NOHTTPONLY = (
    "La cookie es accesible desde JavaScript (sin HttpOnly flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "HttpOnly previene el robo de cookies mediante XSS."
)
_R_COOKIE_NOSAMESITE = (
    "La cookie se envía en peticiones cross-site (sin SameSite flag):\n"
    "  Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict\n"
    "SameSite=Strict: solo peticiones del mismo origen\n"
    "SameSite=Lax: permite GET top-level navigation cross-site\n"
    "SameSite=None: cross-site (requiere Secure)"
)
_R_SERVER_VERSION = (
    "Ocultar la versión del servidor para dificultar el fingerprinting:\n"
    "  nginx:   server_tokens off;  (en http block)\n"
    "  apache:  ServerTokens Prod\n"
    "           ServerSignature Off\n"
    "  haproxy: http-response del-header Server"
)
_R_XPOWEREDBY = (
    "Eliminar cabecera X-Powered-By que revela la tecnología del servidor:\n"
    "  PHP:     expose_php = Off  (en php.ini)\n"
    "  Express: app.disable('x-powered-by');\n"
    "  nginx:   fastcgi_hide_header X-Powered-By;\n"
    "  apache:  Header always unset X-Powered-By"
)
_R_OPEN_REDIRECT = (
    "CRÍTICO: Validar estrictamente los parámetros de redirección:\n"
    "  · Usar lista blanca de URLs/dominios de destino permitidos\n"
    "  · Nunca redirigir a un valor externo sin validación\n"
    "  · Usar redirecciones relativas en lugar de absolutas cuando sea posible\n"
    "  · Añadir token CSRF a los parámetros de redirección\n"
    "Ref: OWASP A01:2021 (Broken Access Control)"
)
_R_DEBUG_HEADER = (
    "Eliminar cabeceras de debug expuestas en producción:\n"
    "  · Configurar el framework para no emitir cabeceras de depuración\n"
    "  · nginx:  proxy_hide_header X-Debug-Token;\n"
    "  · Revisar la configuración de entorno (DEBUG=False en Django/Flask)"
)
_R_GRAPHQL_INTROSPECTION = (
    "Deshabilitar la introspección GraphQL en entornos de producción:\n"
    "  · Apollo Server: introspection: false (NODE_ENV=production lo deshabilita por defecto)\n"
    "  · GraphQL Yoga: useCSRFPrevention: true + deshabilitar introspección en prod\n"
    "  · Hasura: HASURA_GRAPHQL_ENABLE_CONSOLE=false + deshabilitar schema introspection\n"
    "  · graphene-django: GRAPHENE = {'SCHEMA': ..., 'INTROSPECTION': False}\n"
    "  · Alternativa: limitar introspección por rol (sólo admin autenticado)\n"
    "Ref: OWASP API Security Top 10 — API8:2023 (Security Misconfiguration)"
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
