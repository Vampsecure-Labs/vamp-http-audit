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

from ._models import (
    VERSION,
    TOOL_NAME,
    GRADE_COLOR,
    GRADE_DESCRIPTION,
    SEVERITY_ORDER,
    SEVERITY_COLOR,
    AuditResult,
    Finding,
)
from ._core import HTTPAuditor, compute_grade
from ._report import to_json, to_html, to_markdown, to_csv, _findings_vsl

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-http-audit v1.3.0 · HTTP Security Headers & CORS Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
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
        grade_desc= GRADE_DESCRIPTION.get(grade, "")
        sev_col   = SEVERITY_COLOR.get(result.max_severity, "white")

        self._c.print(f"\n[bold cyan]{'─'*65}[/]")
        self._c.print(
            f"  Nota: [{grade_col}]{grade:>2}[/{grade_col}]  "
            f"[bold]{result.url}[/]  "
            f"[{sev_col}]{result.max_severity}[/{sev_col}]"
        )
        self._c.print(f"  [dim]{grade_desc}[/]")
        self._c.print(f"[bold cyan]{'─'*65}[/]")

        self._c.print(f"  [bold]Estado HTTP:[/]     {result.status_code}")

        # Cabeceras clave
        csp   = result.headers.get("content-security-policy", "[red]AUSENTE[/]")
        hsts  = result.headers.get("strict-transport-security", "[red]AUSENTE[/]")
        xfo   = result.headers.get("x-frame-options", "[red]AUSENTE[/]")
        xcto  = result.headers.get("x-content-type-options", "[red]AUSENTE[/]")
        rp    = result.headers.get("referrer-policy", "[red]AUSENTE[/]")
        pp    = result.headers.get("permissions-policy", "[red]AUSENTE[/]")

        self._c.print(f"  [bold]CSP:[/]             {csp[:80] + '…' if len(str(csp)) > 80 else csp}")
        self._c.print(f"  [bold]HSTS:[/]            {hsts}")
        self._c.print(f"  [bold]X-Frame-Options:[/] {xfo}")
        self._c.print(f"  [bold]X-Content-Type:[/]  {xcto}")
        self._c.print(f"  [bold]Referrer-Policy:[/] {rp}")
        self._c.print(f"  [bold]Permissions-Policy:[/] {pp[:60] + '…' if len(str(pp)) > 60 else pp}")

        if result.cookies:
            self._c.print(f"\n  [bold]Cookies detectadas:[/] {len(result.cookies)}")
            for ck in result.cookies:
                flags = []
                flags.append("[green]S[/]"  if ck.secure   else "[red]S[/]")
                flags.append("[green]H[/]"  if ck.httponly  else "[red]H[/]")
                flags.append("[green]SS[/]" if ck.samesite  else "[red]SS[/]")
                self._c.print(f"    {ck.name:<30} {''.join(flags)} SameSite={ck.samesite or '—'}")

        if result.open_redirect_params:
            self._c.print(f"\n  [bold red]Open redirect: parámetros vulnerables:[/] {', '.join(result.open_redirect_params)}")

        # Tabla de hallazgos
        if result.findings:
            self._c.print()
            tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
            tbl.add_column("SEV",       width=10)
            tbl.add_column("Categoría", width=20)
            tbl.add_column("Hallazgo",  min_width=38)
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
                self._c.print("\n  [bold cyan]Pasos de remediación prioritarios:[/]")
                for f in criticos:
                    self._c.print(Panel(
                        f.remediation,
                        title=f"[{SEVERITY_COLOR[f.severity]}]{f.severity}[/] — {f.name}",
                        border_style="cyan", expand=False,
                    ))
        else:
            self._c.print("\n  [bold green]✔ Sin hallazgos de seguridad[/]")

    def print_summary(self, results: list[AuditResult]) -> None:
        self._c.print("\n")
        tbl = Table(title="Resumen de auditoría HTTP",
                    header_style="bold cyan", show_lines=True)
        tbl.add_column("URL",             min_width=30)
        tbl.add_column("Nota",            width=5)
        tbl.add_column("Estado",          width=7)
        tbl.add_column("CSP",             width=5)
        tbl.add_column("HSTS",            width=6)
        tbl.add_column("Cookies",         width=8)
        tbl.add_column("Hallazgos C/H",   width=12)
        tbl.add_column("Severidad máx.",  width=12)

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
        """,
    )
    p.add_argument("-u", "--url", dest="urls", metavar="URL",
                   action="append", default=[],
                   help="URL a auditar (se puede repetir)")
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
    from vampsec_report import add_report_args
    add_report_args(p)
    return p.parse_args()


def _resolve_urls(args: argparse.Namespace) -> list[str]:
    raw: list[str] = list(args.urls)
    if args.file:
        path = Path(args.file)
        if not path.is_file():
            console.print(f"[bold red]ERROR:[/] Fichero no encontrado: {args.file}")
            sys.exit(1)
        raw.extend(line.strip() for line in path.read_text().splitlines()
                   if line.strip() and not line.startswith("#"))
    if not raw:
        console.print("[bold red]ERROR:[/] Indica al menos una URL con -u o --file")
        sys.exit(1)

    urls = []
    for u in raw:
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        urls.append(u)
    return urls


def main() -> None:
    """Punto de entrada principal."""
    console.print(BANNER, style="bold magenta")

    args     = _parse_args()
    urls     = _resolve_urls(args)

    if not args.active:
        console.print(
            "[dim yellow]⚠  Pruebas activas desactivadas (IDOR · Host Header Injection · Open Redirect).[/]\n"
            "[dim]   Usa [bold]--active[/] para activarlas. Solo en entornos autorizados.[/]\n"
        )

    auditor  = HTTPAuditor(timeout=args.timeout, verify_ssl=not args.no_verify_ssl, active=args.active)
    reporter = Reporter(console)

    console.print(f"[bold cyan]Auditando {len(urls)} URL(s)…[/]\n")

    results: list[AuditResult] = []

    if len(urls) == 1:
        with console.status(f"[cyan]Auditando {urls[0]}…[/]", spinner="dots"):
            results.append(auditor.audit(urls[0]))
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(auditor.audit, u): u for u in urls}
            with console.status("[cyan]Auditando URLs en paralelo…[/]", spinner="dots"):
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())

    results.sort(key=lambda r: r.url)

    for r in results:
        reporter.print_result(r)

    reporter.print_summary(results)

    if args.json:
        Path(args.json).write_text(to_json(results), encoding="utf-8")
        console.print(f"\n[green]✔[/] JSON guardado en [bold]{args.json}[/]")
    if args.html:
        Path(args.html).write_text(to_html(results), encoding="utf-8")
        console.print(f"[green]✔[/] HTML guardado en [bold]{args.html}[/]")
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(results), encoding="utf-8")
        console.print(f"[green]✔[/] Markdown guardado en [bold]{args.markdown}[/]")
    if args.csv:
        ph, pf = to_csv(results, args.csv)
        console.print(f"[green]✔[/] CSV resumen: [bold]{ph}[/]")
        console.print(f"[green]✔[/] CSV hallazgos: [bold]{pf}[/]")

    # Informes de cliente (formato unificado VSL)
    if args.report_html or args.report_pdf:
        from vampsec_report import VampSecReport, meta_from_args
        meta    = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        vsl_rep = VampSecReport(meta, _findings_vsl(results))
        if args.report_html:
            vsl_rep.to_html_client(args.report_html)
            console.print(f"[green]✔[/] Informe cliente HTML: [bold]{args.report_html}[/]")
        if args.report_pdf:
            try:
                vsl_rep.to_pdf(args.report_pdf)
                console.print(f"[green]✔[/] Informe cliente PDF: [bold]{args.report_pdf}[/]")
            except RuntimeError as e:
                console.print(f"[yellow]⚠ PDF no generado: {e}[/yellow]")

    max_sev = "INFO"
    for r in results:
        if SEVERITY_ORDER.get(r.max_severity, 99) < SEVERITY_ORDER.get(max_sev, 99):
            max_sev = r.max_severity
    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)
