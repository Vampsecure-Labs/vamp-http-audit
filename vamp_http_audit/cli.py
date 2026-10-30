# © VampSecure Studios — VampSecure Labs Security Research Division
"""
cli.py — Interfaz de línea de comandos para vamp-http-audit.
Presentación en consola (Rich), parsing de argumentos y punto de entrada principal.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import vamp_http_audit._models as _models
from ._models import (
    VERSION,
    TOOL_NAME,
    GRADE_COLOR,
    GRADE_DESCRIPTION,
    SEVERITY_ORDER,
    SEVERITY_COLOR,
    AuditResult,
    _T,
)
from ._core import HTTPAuditor
from ._report import to_json, to_html, to_markdown, to_csv, _findings_vsl

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-http-audit v1.6.0 · HTTP Security Headers & CORS Auditor
  ────────────────────────────────────────────────────────────────────────
  FOR AUTHORIZED AUDITS ONLY · Unauthorized use is illegal
"""

# ---------------------------------------------------------------------------
# Presentación en consola
# ---------------------------------------------------------------------------

class Reporter:
    """Genera la presentación en consola de los resultados de auditoría."""

    def __init__(self, con: Console) -> None:
        self._c = con

    def print_result(self, result: AuditResult) -> None:
        if result.error:
            self._c.print(f"[bold red]✗[/] [bold]{result.url}[/] — {result.error}")
            return

        grade     = result.grade
        grade_col = GRADE_COLOR.get(grade, "white")
        grade_desc= str(GRADE_DESCRIPTION.get(grade, ""))
        sev_col   = SEVERITY_COLOR.get(result.max_severity, "white")

        self._c.print(f"\n[bold cyan]{'─'*65}[/]")
        self._c.print(
            f"  {_T("Grade","Nota")}: [{grade_col}]{grade:>2}[/{grade_col}]  "
            f"[bold]{result.url}[/]  "
            f"[{sev_col}]{result.max_severity}[/{sev_col}]"
        )
        self._c.print(f"  [dim]{grade_desc}[/]")
        self._c.print(f"[bold cyan]{'─'*65}[/]")

        self._c.print(f"  [bold]{_T("HTTP Status","Estado HTTP")}:[/]     {result.status_code}")

        # Cabeceras clave
        csp   = result.headers.get("content-security-policy", f"[red]{_T('ABSENT','AUSENTE')}[/]")
        hsts  = result.headers.get("strict-transport-security", f"[red]{_T('ABSENT','AUSENTE')}[/]")
        xfo   = result.headers.get("x-frame-options", f"[red]{_T('ABSENT','AUSENTE')}[/]")
        xcto  = result.headers.get("x-content-type-options", f"[red]{_T('ABSENT','AUSENTE')}[/]")
        rp    = result.headers.get("referrer-policy", f"[red]{_T('ABSENT','AUSENTE')}[/]")
        pp    = result.headers.get("permissions-policy", f"[red]{_T('ABSENT','AUSENTE')}[/]")

        self._c.print(f"  [bold]CSP:[/]             {csp[:80] + '…' if len(str(csp)) > 80 else csp}")
        self._c.print(f"  [bold]HSTS:[/]            {hsts}")
        self._c.print(f"  [bold]X-Frame-Options:[/] {xfo}")
        self._c.print(f"  [bold]X-Content-Type:[/]  {xcto}")
        self._c.print(f"  [bold]Referrer-Policy:[/] {rp}")
        self._c.print(f"  [bold]Permissions-Policy:[/] {pp[:60] + '…' if len(str(pp)) > 60 else pp}")

        if result.cookies:
            self._c.print(f"\n  [bold]{_T("Cookies detected","Cookies detectadas")}:[/] {len(result.cookies)}")
            for ck in result.cookies:
                flags = []
                flags.append("[green]S[/]"  if ck.secure   else "[red]S[/]")
                flags.append("[green]H[/]"  if ck.httponly  else "[red]H[/]")
                flags.append("[green]SS[/]" if ck.samesite  else "[red]SS[/]")
                self._c.print(f"    {ck.name:<30} {''.join(flags)} SameSite={ck.samesite or '—'}")

        if result.open_redirect_params:
            self._c.print(f"\n  [bold red]{_T("Open redirect: vulnerable parameters","Open redirect: parámetros vulnerables")}:[/] {', '.join(result.open_redirect_params)}")

        # Tabla de hallazgos
        if result.findings:
            self._c.print()
            tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
            tbl.add_column("SEV",       width=10)
            tbl.add_column(str(_T("Category","Categoría")), width=20)
            tbl.add_column(str(_T("Finding","Hallazgo")),  min_width=38)
            tbl.add_column("Cap",       width=4)
            for f in result.findings:
                color = SEVERITY_COLOR.get(f.severity, "white")
                tbl.add_row(
                    Text(f.severity, style=color),
                    Text(f.category),
                    Text(f.name),
                    Text(f.grade_cap or ""),
                )
            self._c.print(tbl)

            criticos = [f for f in result.findings if f.severity in ("CRITICAL", "HIGH") and f.remediation]
            if criticos:
                self._c.print(f"\n  [bold cyan]{_T("Priority remediation steps","Pasos de remediación prioritarios")}:[/]")
                for f in criticos:
                    self._c.print(Panel(
                        f.remediation,
                        title=f"[{SEVERITY_COLOR[f.severity]}]{f.severity}[/] — {f.name}",
                        border_style="cyan", expand=False,
                    ))
        else:
            self._c.print(f"\n  [bold green]✔ {_T("No security findings","Sin hallazgos de seguridad")}[/]")

    def print_php_summary(self, results: list[AuditResult]) -> None:
        """Tabla de resumen de hosts con PHP vulnerable."""
        vulnerables = [r for r in results if r.php_vulnerable]
        detectados  = [r for r in results if r.php_version and not r.php_vulnerable]

        if not vulnerables and not detectados:
            return

        self._c.print("\n[bold red]━━━ PHP VULNERABILITY SUMMARY ━━━[/]")

        if vulnerables:
            tbl = Table(
                title=f"[bold red]⚠ {len(vulnerables)} host(s) PHP VULNERABLE(S)[/]",
                header_style="bold red", show_lines=True,
            )
            tbl.add_column("URL",           min_width=35)
            tbl.add_column(str(_T("PHP version","Versión PHP")), width=14)
            tbl.add_column("CVEs",          min_width=22)
            for r in vulnerables:
                tbl.add_row(
                    r.url[:50] + ("…" if len(r.url) > 50 else ""),
                    f"[bold red]{r.php_version}[/]",
                    ", ".join(r.php_cves),
                )
            self._c.print(tbl)

        if detectados:
            tbl2 = Table(
                title=f"[green]{len(detectados)} host(s) PHP detectado (versión no vulnerable)[/]",
                header_style="bold green", show_lines=False,
            )
            tbl2.add_column("URL",          min_width=35)
            tbl2.add_column(str(_T("PHP version","Versión PHP")), width=14)
            for r in detectados:
                tbl2.add_row(
                    r.url[:50] + ("…" if len(r.url) > 50 else ""),
                    f"[green]{r.php_version}[/]",
                )
            self._c.print(tbl2)

    def print_summary(self, results: list[AuditResult]) -> None:
        self._c.print("\n")
        tbl = Table(title=str(_T("HTTP Audit Summary","Resumen de auditoría HTTP")),
                    header_style="bold cyan", show_lines=True)
        tbl.add_column("URL",             min_width=30)
        tbl.add_column(str(_T("Grade","Nota")),            width=5)
        tbl.add_column(str(_T("Status","Estado")),          width=7)
        tbl.add_column("CSP",             width=5)
        tbl.add_column("HSTS",            width=6)
        tbl.add_column("Cookies",         width=8)
        tbl.add_column(str(_T("Findings C/H","Hallazgos C/H")),   width=12)
        tbl.add_column(str(_T("Max severity","Severidad máx.")),  width=12)

        for r in results:
            if r.error:
                tbl.add_row(r.url[:40], "[red]F[/]", "[red]ERR[/]", "—", "—", "—", "—", "[red]ERROR[/]")
                continue
            grade_col = GRADE_COLOR.get(r.grade, "white")
            sev_col   = SEVERITY_COLOR.get(r.max_severity, "white")
            csp_s     = "[green]✔[/]" if r.headers.get("content-security-policy") else "[red]✗[/]"
            hsts_s    = "[green]✔[/]" if r.headers.get("strict-transport-security") else "[red]✗[/]"
            crhi      = sum(1 for f in r.findings if f.severity in ("CRITICAL", "HIGH"))
            tbl.add_row(
                r.url[:40] + ("…" if len(r.url) > 40 else ""),
                f"[{grade_col}]{r.grade}[/{grade_col}]",
                str(r.status_code),
                csp_s,
                hsts_s,
                str(len(r.cookies)),
                str(crhi),
                f"[{sev_col}]{r.max_severity}[/{sev_col}]",
            )
        self._c.print(tbl)


# ---------------------------------------------------------------------------
# CLI — parsing de argumentos y función principal
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"VampSecure Labs HTTP Audit v{VERSION} — Auditor de seguridad HTTP con calificación A+→F",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  vamp-http-audit -u https://ejemplo.com
  vamp-http-audit -u https://ejemplo.com -u https://api.ejemplo.com/v2/
  vamp-http-audit --file urls.txt --html informe.html --markdown informe.md
  vamp-http-audit -u https://ejemplo.com --json salida.json --csv resultados.csv
  vamp-http-audit --network 192.168.1.0/24 --json red_interna.json
  vamp-http-audit --network 10.0.0.0/16 --network 172.16.0.0/24 --php-only --json php_vuln.json
  vamp-http-audit --network 192.168.0.0/24 --scan-ports 80,443,8080 --scan-timeout 2.0
        """,
    )
    p.add_argument("-u", "--url", dest="urls", metavar="URL",
                   action="append", default=[],
                   help="URL a auditar (se puede repetir)")
    p.add_argument("--network", dest="networks", metavar="CIDR",
                   action="append", default=[],
                   help="Rango CIDR a descubrir y auditar (ej. 192.168.1.0/24, se puede repetir)")
    p.add_argument("--scan-ports", metavar="PORTS",
                   help="Puertos TCP a probar en --network (coma: 80,443,8080). Default: puertos web comunes")
    p.add_argument("--scan-timeout", type=float, default=1.5, metavar="SEG",
                   help="Timeout TCP por host en el escaneo de red (default: 1.5 s)")
    p.add_argument("--scan-concurrency", type=int, default=200, metavar="N",
                   help="Conexiones TCP simultáneas en el escaneo de red (default: 200)")
    p.add_argument("--file", metavar="FILE",
                   help="Fichero con URLs, una por línea")
    p.add_argument("--timeout", type=int, default=10,
                   help="Timeout de conexión en segundos (default: 10)")
    p.add_argument("--workers", type=int, default=5,
                   help="Hilos paralelos para múltiples URLs (default: 5)")
    p.add_argument("--json",     metavar="FILE", help="Exportar JSON")
    p.add_argument("--html",     metavar="FILE", help="Exportar HTML dark-theme")
    p.add_argument("--markdown", metavar="FILE", help="Exportar Markdown")
    p.add_argument("--csv",      metavar="FILE", help="Exportar CSV (+ FILE.findings)")
    p.add_argument("--no-verify-ssl", dest="no_verify_ssl", action="store_true",
                   help="No verificar certificado TLS al hacer peticiones (útil para endpoints internos)")
    p.add_argument("--active", action="store_true",
                   help=(
                       "Activar pruebas activas (IDOR, Host Header Injection, Open Redirect). "
                       "Solo usar en entornos autorizados — pueden generar peticiones adicionales."
                   ))
    p.add_argument("--php-only", action="store_true",
                   help="Mostrar en consola solo los hosts con PHP vulnerable (útil con --network)")
    p.add_argument("--lang", choices=["en", "es"], default="en",
                   help="Output language / Idioma de salida (default: en)")
    from vampsec_report import add_report_args
    add_report_args(p)
    return p.parse_args()


def _resolve_urls(args: argparse.Namespace) -> list[str]:
    raw: list[str] = list(args.urls)
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            console.print(f"[bold red]ERROR:[/] {_T("File not found","Fichero no encontrado")}: {args.file}")
            sys.exit(1)
        raw.extend(line.strip() for line in path.read_text().splitlines()
                   if line.strip() and not line.startswith("#"))

    # Descubrimiento de hosts en rangos CIDR
    if args.networks:
        from ._net_scan import escanear_redes, WEB_PORTS
        puertos = WEB_PORTS
        if args.scan_ports:
            try:
                puertos = [int(p.strip()) for p in args.scan_ports.split(",") if p.strip()]
            except ValueError:
                console.print(f"[bold red]ERROR:[/] {_T('--scan-ports must be a comma-separated list of integers','--scan-ports debe ser una lista de enteros separados por coma')}")
                sys.exit(1)
        with console.status(
            f"[cyan]{_T('Scanning','Escaneando')} {len(args.networks)} CIDR range(s) {_T('on ports','en puertos')} {puertos}…[/]",
            spinner="dots",
        ):
            descubiertas = escanear_redes(
                args.networks,
                puertos=puertos,
                timeout=args.scan_timeout,
                max_concurrencia=args.scan_concurrency,
            )
        console.print(
            f"[bold green]✔[/] {_T('Discovered','Descubiertas')} [bold]{len(descubiertas)}[/] {_T('active URL(s) in','URL(s) activas en')} {', '.join(args.networks)}"
        )
        raw.extend(descubiertas)

    if not raw:
        if args.networks:
            console.print(
                f"[bold red]ERROR:[/] {_T('No active hosts discovered in the specified CIDR ranges.','No se descubrieron hosts activos en los rangos CIDR especificados.')}\n"
                f"  · {_T('Verify connectivity with the target network','Verifica conectividad con la red objetivo')}\n"
                f"  · {_T('Try a higher --scan-timeout (e.g. --scan-timeout 3.0)','Prueba con --scan-timeout mayor (ej. --scan-timeout 3.0)')}\n"
                f"  · {_T('Specify ports manually with --scan-ports 80,443,8080','Especifica puertos manualmente con --scan-ports 80,443,8080')}"
            )
        else:
            console.print(f"[bold red]ERROR:[/] {_T('Specify at least one URL with -u, --file or --network','Indica al menos una URL con -u, --file o --network')}")
        sys.exit(1)

    urls = []
    for u in raw:
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        urls.append(u)
    return list(dict.fromkeys(urls))  # dedup preservando orden


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER, style="bold magenta")

    args     = _parse_args()
    _models.LANG = args.lang
    urls     = _resolve_urls(args)

    if not args.active:
        console.print(
            f"[dim yellow]⚠  {_T('Active tests disabled','Pruebas activas desactivadas')} (IDOR · Host Header Injection · Open Redirect).[/]\n"
            f"[dim]   {_T('Use','Usa')} [bold]--active[/] {_T('to enable them. Authorized environments only.','para activarlas. Solo en entornos autorizados.')}[/]\n"
        )

    auditor  = HTTPAuditor(timeout=args.timeout, verify_ssl=not args.no_verify_ssl, active=args.active)
    reporter = Reporter(console)

    console.print(f"[bold cyan]{_T("Auditing","Auditando")} {len(urls)} URL(s)…[/]\n")

    results: list[AuditResult] = []

    if len(urls) == 1:
        with console.status(f"[cyan]{_T("Auditing","Auditando")} {urls[0]}…[/]", spinner="dots"):
            results.append(auditor.audit(urls[0]))
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(auditor.audit, u): u for u in urls}
            with console.status(f"[cyan]{_T("Auditing URLs in parallel","Auditando URLs en paralelo")}…[/]", spinner="dots"):
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())

    results.sort(key=lambda r: r.url)

    # Con --php-only solo se muestran los hosts con PHP vulnerable
    mostrar = [r for r in results if r.php_vulnerable] if args.php_only else results
    for r in mostrar:
        reporter.print_result(r)

    reporter.print_summary(results)
    reporter.print_php_summary(results)

    if args.json:
        Path(args.json).write_text(to_json(results), encoding="utf-8")
        console.print(f"\n[green]✔[/] JSON {_T("saved to","guardado en")} [bold]{args.json}[/]")
    if args.html:
        Path(args.html).write_text(to_html(results), encoding="utf-8")
        console.print(f"[green]✔[/] HTML {_T("saved to","guardado en")} [bold]{args.html}[/]")
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(results), encoding="utf-8")
        console.print(f"[green]✔[/] Markdown {_T("saved to","guardado en")} [bold]{args.markdown}[/]")
    if args.csv:
        ph, pf = to_csv(results, args.csv)
        console.print(f"[green]✔[/] CSV {_T("summary","resumen")}: [bold]{ph}[/]")
        console.print(f"[green]✔[/] CSV {_T("findings","hallazgos")}: [bold]{pf}[/]")

    # Informes de cliente (formato unificado VSL)
    if args.report_html or args.report_pdf:
        from vampsec_report import VampSecReport, meta_from_args
        meta    = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        vsl_rep = VampSecReport(meta, _findings_vsl(results))
        if args.report_html:
            vsl_rep.to_html_client(args.report_html)
            console.print(f"[green]✔[/] {_T("Client HTML report","Informe cliente HTML")}: [bold]{args.report_html}[/]")
        if args.report_pdf:
            try:
                vsl_rep.to_pdf(args.report_pdf)
                console.print(f"[green]✔[/] {_T("Client PDF report","Informe cliente PDF")}: [bold]{args.report_pdf}[/]")
            except RuntimeError as e:
                console.print(f"[yellow]⚠ {_T("PDF not generated","PDF no generado")}: {e}[/yellow]")

    max_sev = "INFO"
    for r in results:
        if SEVERITY_ORDER.get(r.max_severity, 99) < SEVERITY_ORDER.get(max_sev, 99):
            max_sev = r.max_severity
    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)
