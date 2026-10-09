<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-http-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-http-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

### Overview

`vamp-http-audit` is the HTTP layer companion to `vamp-ssl-audit`. Where the TLS auditor covers the transport layer, this tool covers HTTP security headers, CORS misconfigurations, cookie flag analysis, server information disclosure, and open redirect vulnerabilities. It uses the same SSLabs-style A+–F grading system and supports the same output formats (JSON, HTML, Markdown, CSV), making it a natural fit in any automated assessment pipeline.

### Features

- SSLabs-style letter grading A+ to F based on combined HTTP security posture
- Security header analysis: CSP (directive-level deep inspection including `unsafe-inline`, `unsafe-eval`, wildcards, `frame-ancestors`), HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COEP, COOP, CORP
- CORS misconfiguration probing: attacker-origin reflection, wildcard + credentials (CRITICAL), null-origin acceptance (iframe sandbox bypass)
- Cookie security analysis: Secure, HttpOnly, SameSite flags; `__Host-` and `__Secure-` prefix enforcement
- Server information disclosure detection: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, debug headers
- Open redirect testing across 16 common parameters: `url`, `redirect`, `next`, `return`, `goto`, `destination`, `redir`, `target`, `link`, `forward`, `location`, `rurl`, `returl`, `redirect_uri`, `redirect_url`, `return_url`
- GraphQL endpoint detection and introspection availability check
- Concurrent multi-URL scanning with configurable worker pool (`--workers`, default 5)
- Zero third-party dependencies — only Python stdlib (`urllib`) and `rich`
- Export to Console, JSON, HTML (dark-theme with collapsible remediations), Markdown, and CSV

### Requirements

- Python 3.9 or later
- `rich >= 13.7.0`

### Installation

```bash
pip install vamp-http-audit
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-http-audit
```

```bash
git clone https://github.com/belky-me/vamp-http-audit.git
cd vamp-http-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Usage

```
python3 vamp_http_audit.py --help
```

```
usage: vamp_http_audit.py [-h] [-u URL] [--file FILE]
                           [--timeout TIMEOUT] [--workers WORKERS]
                           [--json FILE] [--html FILE]
                           [--markdown FILE] [--csv FILE]
                           [--no-verify-ssl]
                           [--client CLIENT] [--engagement ENGAGEMENT]
                           [--auditor AUDITOR] [--report-scope SCOPE]
                           [--report-html FILE] [--report-pdf FILE]

vamp-http-audit — HTTP Security Headers & CORS Auditor (VampSecure Labs)
```

### Try it now — public test targets

No targets of your own? These intentionally-misconfigured hosts are safe to scan:

```bash
# No HSTS → grade drops to C
python3 vamp_http_audit.py -u https://nohsts.badssl.com

# X-Frame-Options absent → clickjacking surface
python3 vamp_http_audit.py -u https://no-x-frame-options.badssl.com

# Typical modern site for comparison
python3 vamp_http_audit.py -u https://badssl.com
```

### Quick wins — going from B to A in nginx

These three directives cover the most common gap (CSP absent → HIGH):

```nginx
# nginx.conf or site vhost
server_tokens off;   # hides nginx version from Server header

add_header Content-Security-Policy
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
   img-src 'self' data: https:; frame-ancestors 'none';"
  always;

add_header Permissions-Policy
  "geolocation=(), camera=(), microphone=()"
  always;
```

For SPAs (React, Vue, Next.js, Svelte) the `script-src 'self'` will break inline scripts. Use a nonce-based CSP or add `'unsafe-inline'` temporarily while hardening:

```nginx
# Next.js: also suppress framework fingerprinting
proxy_hide_header X-Powered-By;
```

> **COEP / COOP / CORP** — vamp-http-audit flags these as LOW. They are only critical for sites using `SharedArrayBuffer` or cross-origin isolation. For most sites (blogs, dashboards, SaaS UIs without WebWorkers) these findings can be safely ignored.

### CI/CD Integration

```yaml
name: HTTP Security Audit
on:
  schedule:
    - cron: '0 7 * * 1'
  workflow_dispatch:

jobs:
  http-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install vamp-http-audit
      - run: |
          vamp-http-audit \
            -u https://yourdomain.com \
            -u https://api.yourdomain.com \
            --json http-results.json \
            --markdown http-report.md
        # Exit 1 = HIGH findings, exit 2 = CRITICAL (open redirect, CORS+creds)
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: http-audit-report
          path: http-report.md
```

### Examples

```bash
# Audit a single URL
python3 vamp_http_audit.py -u https://example.com

# Audit multiple URLs in one command
python3 vamp_http_audit.py -u https://example.com -u https://api.example.com

# Audit a list of URLs from file with 10 parallel workers
python3 vamp_http_audit.py --file urls.txt --workers 10

# Export results to all formats
python3 vamp_http_audit.py -u https://example.com \
    --json results.json --html report.html --markdown report.md --csv report.csv

# Skip TLS verification for self-signed certificates
python3 vamp_http_audit.py -u https://internal.staging.local --no-verify-ssl

# Generate client-ready engagement report
python3 vamp_http_audit.py --file urls.txt \
    --client "Acme Corp" --engagement "HTTP Headers Review Q3 2026" \
    --auditor "J. Smith" --report-html client_report.html
```

### CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-u / --url URL` | — | Target URL (repeatable for multiple targets) |
| `--file FILE` | — | Text file with one URL per line |
| `--timeout N` | 10 | Per-request timeout in seconds |
| `--workers N` | 5 | Concurrent worker threads |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report |
| `--markdown FILE` | — | Export Markdown report |
| `--csv FILE` | — | Export CSV summary (+ `FILE.findings` detail file) |
| `--no-verify-ssl` | off | Disable TLS certificate verification |
| `--client TEXT` | — | Client name for VSL engagement report |
| `--engagement TEXT` | — | Engagement title for VSL engagement report |
| `--auditor TEXT` | — | Auditor name for VSL engagement report |
| `--report-scope TEXT` | — | Scope description for VSL engagement report |
| `--report-html FILE` | — | Export unified VSL client report (HTML) |
| `--report-pdf FILE` | — | Export unified VSL client report (PDF, requires fpdf2) |

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Rich-colored graded output with per-finding remediation panels |
| JSON | `--json FILE` | Machine-readable full result set |
| HTML | `--html FILE` | Dark-theme standalone report with collapsible remediations |
| Markdown | `--markdown FILE` | Portable report for inclusion in audit repositories |
| CSV | `--csv FILE` | Summary row per host + `FILE.findings` with one row per finding |
| Client HTML | `--report-html FILE` | Unified VampSecure Labs engagement report |
| Client PDF | `--report-pdf FILE` | PDF version of the VSL client report |

### Grading Scale

| Grade | Criteria |
|-------|----------|
| A+ | All headers present, solid CSP, secure cookies, no CORS issues |
| A | Good configuration; missing COOP/COEP/CORP or SameSite on some cookies |
| A- | CSP with `unsafe-inline`/`eval`/wildcard; suboptimal Referrer-Policy |
| B | CSP absent · X-Content-Type-Options absent · server version exposed · insecure cookie · CORS wildcard without credentials |
| C | X-Frame-Options absent without `frame-ancestors` · HSTS absent |
| F | CORS wildcard + credentials · confirmed open redirect |

### Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | No critical or high findings | Pipeline passes |
| `1` | High-severity findings detected | Pipeline fails — review required |
| `2` | Critical-severity findings detected | Pipeline fails — immediate action required |

### Sample Output

```text
vamp-http-audit v1.2.1 · 2 targets
─────────────────────────────────────────────────────────────────────────
Target: https://example.com
  Grade: C
  [HIGH]     HEADER-001  Content-Security-Policy absent
  [HIGH]     HEADER-002  X-Frame-Options absent — no frame-ancestors in CSP
  [MEDIUM]   HEADER-003  Server header exposes version: nginx/1.24.0
  [MEDIUM]   CORS-001    CORS: Access-Control-Allow-Origin reflects request origin
             Tested origin: https://attacker.example.com → reflected ✗
  [LOW]      HEADER-004  Referrer-Policy absent — defaults to no-referrer-when-downgrade
  [LOW]      HEADER-005  Permissions-Policy absent
  [LOW]      COOKIE-001  Session cookie missing SameSite attribute: SESSIONID

Target: https://api.example.com
  Grade: F
  [CRITICAL] CORS-002    CORS wildcard + credentials: Access-Control-Allow-Origin: *
             with Access-Control-Allow-Credentials: true — CRITICAL misconfiguration
  [HIGH]     HEADER-006  HSTS absent — site accessible over plain HTTP
  [HIGH]     REDIRECT-001 Open redirect confirmed: ?next=https://evil.example.com
             redirect_uri=https://evil.example.com → 302 Location: https://evil.example.com
  [MEDIUM]   HEADER-007  X-Content-Type-Options absent — MIME sniffing enabled
  [MEDIUM]   HEADER-008  X-Powered-By exposes framework: Express 4.18.2

┌─────────────────────────────────────┬──────────────┬──────────────┐
│ Target                              │ Grade        │ Findings     │
├─────────────────────────────────────┼──────────────┼──────────────┤
│ https://example.com                 │ C            │ 1H 2M 3L     │
│ https://api.example.com             │ F            │ 1C 2H 2M     │
└─────────────────────────────────────┴──────────────┴──────────────┘
1 CRITICAL · 3 HIGH · 4 MEDIUM · 3 LOW   exit 2
```

---

### Why vamp-http-audit vs. SecurityHeaders.com · OWASP ZAP · Nikto

| Feature | vamp-http-audit | SecurityHeaders.com | OWASP ZAP | Nikto |
|---------|-----------------|---------------------|-----------|-------|
| CORS misconfiguration (origin reflection, wildcard+creds) | ✅ | ❌ | ⚠️ partial | ❌ |
| Open redirect testing (16 params) | ✅ | ❌ | ✅ | ✅ |
| CSP deep inspection (directives, wildcards, unsafe-eval) | ✅ | ✅ | ⚠️ shallow | ❌ |
| COEP / COOP / CORP | ✅ | ✅ | ❌ | ❌ |
| Multi-URL in parallel with workers | ✅ `--workers` | ❌ one URL | ❌ | ❌ |
| Export JSON + HTML + Markdown + CSV | ✅ | ❌ web only | ✅ | ⚠️ text |
| No external traffic — stdlib only | ✅ | ❌ external SaaS | ❌ Java+proxy | ❌ |
| Client engagement report (VSL) | ✅ | ❌ | ❌ | ❌ |

- **Active CORS with credentials detection**: not just checking the header, but probing reflection with a controlled origin and the wildcard+credentials combination — the most critical finding that neither SecurityHeaders.com nor Nikto detect.
- **No external dependencies**: only `urllib` stdlib + `rich`; no Java proxy (ZAP), no external SaaS call (SecurityHeaders.com), no Perl (Nikto) — runs on any CI runner from scratch.
- **A+–F grading with multi-header logic**: the grade accounts for header interactions (CSP `frame-ancestors` replaces X-Frame-Options; COEP/COOP are evaluated jointly) instead of adding points per individual header.
- **Designed for pipelines**: exit code 2 on CRITICAL (CORS+creds, confirmed open redirect) blocks the deploy; exit code 1 on HIGH; other tools have no CI/CD exit code semantics.

---

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| HEADER-001 | Content-Security-Policy absent | OWASP ASVS v4.0 §14.4.6 / CSP Level 3 (W3C) | HIGH |
| HEADER-002 | CSP uses `unsafe-inline` or `unsafe-eval` | OWASP ASVS v4.0 §14.4.6 / CSP Level 3 §4.2 | MEDIUM |
| HEADER-003 | CSP uses wildcard source (`*`) in script-src or default-src | OWASP ASVS v4.0 §14.4.6 | MEDIUM |
| HEADER-004 | X-Frame-Options absent without frame-ancestors in CSP | OWASP ASVS v4.0 §14.4.7 | HIGH |
| HEADER-005 | HSTS absent or max-age < 1 year | OWASP ASVS v4.0 §9.3.1 / RFC 6797 | HIGH |
| HEADER-006 | X-Content-Type-Options absent — MIME sniffing enabled | OWASP ASVS v4.0 §14.4.2 | MEDIUM |
| HEADER-007 | Server or X-Powered-By exposes version information | OWASP ASVS v4.0 §14.3.3 | MEDIUM |
| HEADER-008 | Referrer-Policy absent or unsafe (unsafe-url, no-referrer-when-downgrade) | OWASP ASVS v4.0 §14.4.4 | LOW |
| HEADER-009 | Permissions-Policy absent | OWASP ASVS v4.0 §14.4.5 | LOW |
| CORS-001 | CORS reflects arbitrary request origin (active probe) | RFC 6454 / OWASP ASVS v4.0 §14.5.3 | HIGH |
| CORS-002 | CORS wildcard + Access-Control-Allow-Credentials: true | RFC 6454 §7 / OWASP ASVS v4.0 §14.5.3 | CRITICAL |
| CORS-003 | CORS accepts null origin (iframe sandbox bypass) | RFC 6454 §7.3 | HIGH |
| COOKIE-001 | Session cookie missing Secure flag | OWASP ASVS v4.0 §3.4.1 | HIGH |
| COOKIE-002 | Session cookie missing HttpOnly flag | OWASP ASVS v4.0 §3.4.2 | HIGH |
| COOKIE-003 | Session cookie missing SameSite attribute | OWASP ASVS v4.0 §3.4.3 | MEDIUM |
| REDIRECT-001 | Open redirect confirmed via 16 common redirect parameters | OWASP ASVS v4.0 §5.1.5 | HIGH |

---

### Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

### Part of VampSecure Labs Toolkit

`vamp-http-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

### Version History

| Version | Main changes |
|---------|-------------|
| v1.2.1 | Bilingual README (EN/ES) |
| v1.2.0 | Initial public release — HTTP security headers, CORS, cookies, open redirect, GraphQL detection |

---

© VampSecure Studios — VampSecure Labs Security Research Division

---
---

<a name="español"></a>
## 🇪🇸 Español

### Descripción general

`vamp-http-audit` es el complemento de capa HTTP de `vamp-ssl-audit`. Mientras el auditor TLS cubre la capa de transporte, esta herramienta cubre cabeceras de seguridad HTTP, configuraciones incorrectas de CORS, análisis de flags de cookies, divulgación de información del servidor y vulnerabilidades de redirección abierta. Utiliza el mismo sistema de calificación por letras estilo SSLabs (A+–F) y soporta los mismos formatos de salida (JSON, HTML, Markdown, CSV), lo que la hace ideal para cualquier pipeline de evaluación automatizado.

### Características

- Calificación por letras estilo SSLabs de A+ a F basada en la postura de seguridad HTTP combinada
- Análisis de cabeceras de seguridad: CSP (inspección profunda a nivel de directiva incluyendo `unsafe-inline`, `unsafe-eval`, comodines, `frame-ancestors`), HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COEP, COOP, CORP
- Sondeo de configuraciones incorrectas de CORS: reflexión de origen de atacante, comodín + credenciales (CRITICAL), aceptación de null-origin (bypass de iframe sandbox)
- Análisis de seguridad de cookies: flags Secure, HttpOnly, SameSite; aplicación de prefijos `__Host-` y `__Secure-`
- Detección de divulgación de información del servidor: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, cabeceras de depuración
- Pruebas de redirección abierta en 16 parámetros comunes: `url`, `redirect`, `next`, `return`, `goto`, `destination`, `redir`, `target`, `link`, `forward`, `location`, `rurl`, `returl`, `redirect_uri`, `redirect_url`, `return_url`
- Detección de endpoints GraphQL y comprobación de disponibilidad de introspección
- Escaneo multi-URL concurrente con pool de workers configurable (`--workers`, por defecto 5)
- Cero dependencias de terceros — solo Python stdlib (`urllib`) y `rich`
- Exportación a Consola, JSON, HTML (dark-theme con correcciones desplegables), Markdown y CSV

### Requisitos

- Python 3.9 o posterior
- `rich >= 13.7.0`

### Instalación

```bash
pip install vamp-http-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-http-audit
```

```bash
git clone https://github.com/belky-me/vamp-http-audit.git
cd vamp-http-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Uso

```
python3 vamp_http_audit.py --help
```

### Pruébalo ahora — objetivos de prueba públicos

¿No tienes objetivos propios? Estos hosts intencionalmente mal configurados son seguros para escanear:

```bash
# Sin HSTS → la calificación baja a C
python3 vamp_http_audit.py -u https://nohsts.badssl.com

# X-Frame-Options ausente → superficie de clickjacking
python3 vamp_http_audit.py -u https://no-x-frame-options.badssl.com

# Sitio moderno típico para comparación
python3 vamp_http_audit.py -u https://badssl.com
```

### Ganancias rápidas — pasar de B a A en nginx

Estas tres directivas cubren el hueco más común (CSP ausente → HIGH):

```nginx
# nginx.conf o vhost del sitio
server_tokens off;   # oculta la versión de nginx de la cabecera Server

add_header Content-Security-Policy
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
   img-src 'self' data: https:; frame-ancestors 'none';"
  always;

add_header Permissions-Policy
  "geolocation=(), camera=(), microphone=()"
  always;
```

> **COEP / COOP / CORP** — vamp-http-audit los marca como LOW. Solo son críticos para sitios que usan `SharedArrayBuffer` o aislamiento cross-origin. Para la mayoría de sitios (blogs, dashboards, UIs SaaS sin WebWorkers) estos hallazgos pueden ignorarse con seguridad.

### Integración CI/CD

```yaml
name: HTTP Security Audit
on:
  schedule:
    - cron: '0 7 * * 1'
  workflow_dispatch:

jobs:
  http-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install vamp-http-audit
      - run: |
          vamp-http-audit \
            -u https://tudominio.com \
            -u https://api.tudominio.com \
            --json resultados-http.json \
            --markdown informe-http.md
        # Exit 1 = hallazgos HIGH, exit 2 = CRITICAL (redirección abierta, CORS+creds)
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: http-audit-report
          path: informe-http.md
```

### Ejemplos

```bash
# Auditar una sola URL
python3 vamp_http_audit.py -u https://ejemplo.com

# Auditar múltiples URLs en un comando
python3 vamp_http_audit.py -u https://ejemplo.com -u https://api.ejemplo.com

# Auditar una lista de URLs desde fichero con 10 workers en paralelo
python3 vamp_http_audit.py --file urls.txt --workers 10

# Exportar resultados a todos los formatos
python3 vamp_http_audit.py -u https://ejemplo.com \
    --json resultados.json --html informe.html --markdown informe.md --csv informe.csv

# Omitir verificación TLS para certificados auto-firmados
python3 vamp_http_audit.py -u https://interno.staging.local --no-verify-ssl

# Generar informe de engagement listo para el cliente
python3 vamp_http_audit.py --file urls.txt \
    --client "Acme Corp" --engagement "Revisión HTTP Headers Q3 2026" \
    --auditor "J. García" --report-html informe_cliente.html
```

### Referencia CLI

| Flag | Por defecto | Descripción |
|------|-------------|-------------|
| `-u / --url URL` | — | URL objetivo (repetible para múltiples objetivos) |
| `--file FILE` | — | Fichero de texto con una URL por línea |
| `--timeout N` | 10 | Timeout por petición en segundos |
| `--workers N` | 5 | Hilos de trabajo concurrentes |
| `--json FILE` | — | Exportar resultados a JSON |
| `--html FILE` | — | Exportar informe HTML dark-theme |
| `--markdown FILE` | — | Exportar informe Markdown |
| `--csv FILE` | — | Exportar resumen CSV (+ fichero `FILE.findings` con detalle) |
| `--no-verify-ssl` | off | Deshabilitar verificación de certificado TLS |
| `--client TEXT` | — | Nombre del cliente para el informe de engagement VSL |
| `--engagement TEXT` | — | Título del engagement para el informe VSL |
| `--auditor TEXT` | — | Nombre del auditor para el informe VSL |
| `--report-scope TEXT` | — | Descripción del alcance para el informe VSL |
| `--report-html FILE` | — | Exportar informe unificado VSL del cliente (HTML) |
| `--report-pdf FILE` | — | Exportar informe unificado VSL del cliente (PDF, requiere fpdf2) |

### Formatos de salida

| Formato | Flag | Descripción |
|---------|------|-------------|
| Consola | (por defecto) | Salida Rich con colores y calificación, paneles de corrección por hallazgo |
| JSON | `--json FILE` | Conjunto completo de resultados legible por máquina |
| HTML | `--html FILE` | Informe dark-theme standalone con correcciones desplegables |
| Markdown | `--markdown FILE` | Informe portable para incluir en repositorios de auditoría |
| CSV | `--csv FILE` | Fila resumen por host + `FILE.findings` con una fila por hallazgo |
| HTML cliente | `--report-html FILE` | Informe de engagement unificado VampSecure Labs |
| PDF cliente | `--report-pdf FILE` | Versión PDF del informe VSL del cliente |

### Escala de calificación

| Nota | Criterios |
|------|-----------|
| A+ | Todas las cabeceras presentes, CSP sólida, cookies seguras, sin problemas de CORS |
| A | Buena configuración; falta COOP/COEP/CORP o SameSite en algunas cookies |
| A- | CSP con `unsafe-inline`/`eval`/comodín; Referrer-Policy subóptima |
| B | CSP ausente · X-Content-Type-Options ausente · versión del servidor expuesta · cookie insegura · CORS comodín sin credenciales |
| C | X-Frame-Options ausente sin `frame-ancestors` · HSTS ausente |
| F | CORS comodín + credenciales · redirección abierta confirmada |

### Códigos de salida

| Código | Significado | Comportamiento CI/CD |
|--------|-------------|---------------------|
| `0` | Sin hallazgos críticos ni altos | El pipeline pasa |
| `1` | Hallazgos de severidad alta detectados | El pipeline falla — revisión requerida |
| `2` | Hallazgos de severidad crítica detectados | El pipeline falla — acción inmediata requerida |

---

### Why vamp-http-audit vs. SecurityHeaders.com · OWASP ZAP · Nikto

| Característica | vamp-http-audit | SecurityHeaders.com | OWASP ZAP | Nikto |
|---|---|---|---|---|
| CORS misconfiguration (origin reflection, wildcard+creds) | ✅ | ❌ | ⚠️ parcial | ❌ |
| Open redirect testing (16 params) | ✅ | ❌ | ✅ | ✅ |
| CSP deep inspection (directivas, wildcards, unsafe-eval) | ✅ | ✅ | ⚠️ superficial | ❌ |
| COEP / COOP / CORP | ✅ | ✅ | ❌ | ❌ |
| Multi-URL en paralelo con workers | ✅ `--workers` | ❌ una URL | ❌ | ❌ |
| Export JSON + HTML + Markdown + CSV | ✅ | ❌ solo web | ✅ | ⚠️ texto |
| Sin tráfico externo — solo stdlib | ✅ | ❌ SaaS externo | ❌ Java+proxy | ❌ |
| Informe de engagement cliente (VSL) | ✅ | ❌ | ❌ | ❌ |

- **CORS con credenciales detectado de forma activa**: no solo comprueba la cabecera, sino que prueba la reflexión con un origen controlado y la combinación wildcard+credentials — el hallazgo más crítico que ni SecurityHeaders.com ni Nikto detectan.
- **Sin dependencias externas**: solo `urllib` stdlib + `rich`; sin proxy Java (ZAP), sin llamada a SaaS externo (SecurityHeaders.com), sin Perl (Nikto) — corre en cualquier runner CI desde cero.
- **Grading A+–F con lógica multi-cabecera**: el grade tiene en cuenta la interacción entre cabeceras (CSP `frame-ancestors` reemplaza X-Frame-Options; COEP/COOP se valoran conjuntamente) en lugar de sumar puntos por cabecera individual.
- **Diseñado para pipelines**: exit code 2 en CRITICAL (CORS+creds, open redirect confirmado) bloquea el deploy; exit code 1 en HIGH; los otros tools no tienen semántica de exit code para CI/CD.

---

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|----------|-------------|----------|-----------|
| HEADER-001 | Content-Security-Policy ausente | OWASP ASVS v4.0 §14.4.6 / CSP Level 3 (W3C) | HIGH |
| HEADER-002 | CSP usa `unsafe-inline` o `unsafe-eval` | OWASP ASVS v4.0 §14.4.6 / CSP Level 3 §4.2 | MEDIUM |
| HEADER-003 | CSP usa comodín (`*`) en script-src o default-src | OWASP ASVS v4.0 §14.4.6 | MEDIUM |
| HEADER-004 | X-Frame-Options ausente sin frame-ancestors en CSP | OWASP ASVS v4.0 §14.4.7 | HIGH |
| HEADER-005 | HSTS ausente o max-age < 1 año | OWASP ASVS v4.0 §9.3.1 / RFC 6797 | HIGH |
| HEADER-006 | X-Content-Type-Options ausente — MIME sniffing habilitado | OWASP ASVS v4.0 §14.4.2 | MEDIUM |
| HEADER-007 | Server o X-Powered-By expone información de versión | OWASP ASVS v4.0 §14.3.3 | MEDIUM |
| HEADER-008 | Referrer-Policy ausente o insegura (unsafe-url, no-referrer-when-downgrade) | OWASP ASVS v4.0 §14.4.4 | LOW |
| HEADER-009 | Permissions-Policy ausente | OWASP ASVS v4.0 §14.4.5 | LOW |
| CORS-001 | CORS refleja el origen de la petición arbitraria (sondeo activo) | RFC 6454 / OWASP ASVS v4.0 §14.5.3 | HIGH |
| CORS-002 | CORS comodín + Access-Control-Allow-Credentials: true | RFC 6454 §7 / OWASP ASVS v4.0 §14.5.3 | CRITICAL |
| CORS-003 | CORS acepta null origin (bypass de iframe sandbox) | RFC 6454 §7.3 | HIGH |
| COOKIE-001 | Cookie de sesión sin flag Secure | OWASP ASVS v4.0 §3.4.1 | HIGH |
| COOKIE-002 | Cookie de sesión sin flag HttpOnly | OWASP ASVS v4.0 §3.4.2 | HIGH |
| COOKIE-003 | Cookie de sesión sin atributo SameSite | OWASP ASVS v4.0 §3.4.3 | MEDIUM |
| REDIRECT-001 | Redirección abierta confirmada en 16 parámetros comunes | OWASP ASVS v4.0 §5.1.5 | HIGH |

---

### Aviso legal

Uso exclusivo en sistemas de tu propiedad o para los que dispongas de autorización escrita explícita del propietario. VampSecure Studios no asume responsabilidad por el uso no autorizado.

### Parte del toolkit VampSecure Labs

`vamp-http-audit` es una herramienta del toolkit de investigación de seguridad de VampSecure Labs. Para el toolkit completo incluyendo el orquestador que ejecuta todas las herramientas en secuencia y agrega los hallazgos en un único informe de engagement, consulta:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orquestador: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.2.1 | README bilingüe (EN/ES) |
| v1.2.0 | Lanzamiento público inicial — cabeceras de seguridad HTTP, CORS, cookies, redirección abierta, detección GraphQL |

---

© VampSecure Studios — VampSecure Labs Security Research Division
