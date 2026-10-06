# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_report.py — Generación de informes en múltiples formatos (JSON, HTML, Markdown, CSV).
Sin interfaz de usuario ni dependencias de presentación.
"""

from __future__ import annotations

import csv as csv_module
import io
import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from ._models import (
    VERSION,
    TOOL_NAME,
    GRADE_DESCRIPTION,
    HTML_GRADE_COLOR,
    SEVERITY_COLOR,
    AuditResult,
    CookieInfo,
)

# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def to_json(results: list[AuditResult]) -> str:
    """Serializa los resultados al formato JSON estructurado VSL."""
    def _ck(c: CookieInfo) -> dict:
        return {
            "name": c.name, "secure": c.secure, "httponly": c.httponly,
            "samesite": c.samesite, "path": c.path, "domain": c.domain,
            "host_prefix": c.host_prefix, "secure_prefix": c.secure_prefix,
        }
    def _r(r: AuditResult) -> dict:
        return {
            "url": r.url, "final_url": r.final_url, "timestamp": r.timestamp,
            "status_code": r.status_code, "grade": r.grade,
            "grade_description": GRADE_DESCRIPTION.get(r.grade, ""),
            "error": r.error, "max_severity": r.max_severity,
            "cors_origin_reflected": r.cors_origin_reflected,
            "cors_credentials": r.cors_credentials,
            "cors_null_accepted": r.cors_null_accepted,
            "open_redirect_params": r.open_redirect_params,
            "cookies": [_ck(c) for c in r.cookies],
            "headers_present": {k: v for k, v in r.headers.items()
                                if not k.startswith("_") and k in (
                                    "content-security-policy", "strict-transport-security",
                                    "x-frame-options", "x-content-type-options",
                                    "referrer-policy", "permissions-policy",
                                    "cross-origin-embedder-policy",
                                    "cross-origin-opener-policy",
                                    "cross-origin-resource-policy",
                                    "server", "x-powered-by",
                                )},
            "findings": [
                {"severity": f.severity, "category": f.category,
                 "name": f.name, "detail": f.detail,
                 "grade_cap": f.grade_cap, "remediation": f.remediation}
                for f in r.findings
            ],
        }
    return json.dumps(
        {"tool": TOOL_NAME, "version": VERSION,
         "generated": datetime.now(timezone.utc).isoformat(),
         "results": [_r(r) for r in results]},
        indent=2, ensure_ascii=False,
    )


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def to_html(results: list[AuditResult]) -> str:
    """Genera un informe HTML dark-theme con remediaciones colapsables."""
    SEV_CSS = {"CRITICAL": "sev-crit", "HIGH": "sev-high",
               "MEDIUM": "sev-med", "LOW": "sev-low", "INFO": "sev-info"}

    rows_html: list[str] = []
    for r in results:
        if r.error:
            rows_html.append(f'<div class="result-block"><h2>{escape(r.url)}</h2>'
                             f'<p class="sev-crit">ERROR: {escape(r.error)}</p></div>')
            continue

        grade        = r.grade
        _, grade_hex = HTML_GRADE_COLOR.get(grade, ("", "#ff2222"))
        grade_desc_h = escape(GRADE_DESCRIPTION.get(grade, ""))

        h = r.headers
        def _hval(key: str) -> str:
            v = h.get(key)
            return f'<span class="hdr-present">{escape(v[:80])}…</span>' if v and len(v) > 80 \
                else f'<span class="hdr-present">{escape(v)}</span>' if v \
                else '<span class="hdr-absent">AUSENTE</span>'

        headers_table = "".join(
            f"<tr><td>{name}</td><td>{_hval(key)}</td></tr>"
            for name, key in [
                ("Content-Security-Policy",      "content-security-policy"),
                ("Strict-Transport-Security",    "strict-transport-security"),
                ("X-Frame-Options",              "x-frame-options"),
                ("X-Content-Type-Options",       "x-content-type-options"),
                ("Referrer-Policy",              "referrer-policy"),
                ("Permissions-Policy",           "permissions-policy"),
                ("COEP",                         "cross-origin-embedder-policy"),
                ("COOP",                         "cross-origin-opener-policy"),
                ("CORP",                         "cross-origin-resource-policy"),
            ]
        )

        ck_rows = ""
        for ck in r.cookies:
            s_cls  = "good" if ck.secure   else "sev-high"
            h_cls  = "good" if ck.httponly  else "sev-high"
            ss_cls = "good" if ck.samesite  else "sev-med"
            ck_rows += (
                f"<tr><td>{escape(ck.name)}</td>"
                f'<td class="{s_cls}">{"✔" if ck.secure   else "✗"}</td>'
                f'<td class="{h_cls}">{"✔" if ck.httponly  else "✗"}</td>'
                f'<td class="{ss_cls}">{escape(ck.samesite or "—")}</td></tr>'
            )

        cookies_html = ""
        if r.cookies:
            cookies_html = f"""
            <h3>Cookies ({len(r.cookies)})</h3>
            <table class="findings-table">
              <thead><tr><th>Nombre</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead>
              <tbody>{ck_rows}</tbody>
            </table>"""

        f_rows = "".join(
            f'<tr><td class="{SEV_CSS.get(f.severity,"")}">{escape(f.severity)}</td>'
            f'<td>{escape(f.category)}</td>'
            f'<td>{escape(f.name)}</td>'
            f'<td>{escape(f.detail)}'
            f'{"<details class=remed><summary>Ver remediación</summary><pre>" + escape(f.remediation) + "</pre></details>" if f.remediation else ""}'
            f'</td></tr>'
            for f in r.findings
        )
        findings_html = (
            f'<table class="findings-table"><thead><tr>'
            f'<th>Severidad</th><th>Categoría</th><th>Hallazgo</th><th>Detalle</th>'
            f'</tr></thead><tbody>{f_rows}</tbody></table>'
        ) if r.findings else '<p class="good">✔ Sin hallazgos</p>'

        rows_html.append(f"""
        <div class="result-block">
          <div class="host-header">
            <div class="grade-circle" style="background:{grade_hex}">{escape(grade)}</div>
            <div class="host-info">
              <h2>{escape(r.url)}</h2>
              <p class="grade-desc">{grade_desc_h}</p>
            </div>
          </div>
          <h3>Cabeceras de seguridad</h3>
          <table class="info-table"><tbody>{headers_table}</tbody></table>
          {cookies_html}
          <h3>Hallazgos ({len(r.findings)})</h3>
          {findings_html}
        </div>""")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VampSecure Labs — HTTP Audit Report</title>
<style>
:root{{--bg:#0d0d0d;--surface:#141414;--border:#1e1e1e;--text:#e0e0e0;
  --text-dim:#888;--accent:#9b59b6;--crit:#ff4444;--high:#ff8800;
  --med:#ffcc00;--low:#4488ff;--good:#44cc88}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Consolas','Courier New',monospace;
  font-size:14px;padding:24px}}
header{{border-bottom:1px solid var(--accent);padding-bottom:16px;margin-bottom:24px}}
header h1{{color:var(--accent);font-size:22px;letter-spacing:.1em}}
header p{{color:var(--text-dim);font-size:12px;margin-top:4px}}
.result-block{{background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:20px;margin-bottom:20px}}
.host-header{{display:flex;align-items:center;gap:16px;margin-bottom:14px}}
.grade-circle{{width:56px;height:56px;border-radius:50%;display:flex;align-items:center;
  justify-content:center;font-size:18px;font-weight:bold;color:#fff;flex-shrink:0}}
.host-info h2{{font-size:16px;margin-bottom:4px}}
.grade-desc{{color:var(--text-dim);font-size:12px}}
h3{{font-size:13px;color:var(--text-dim);margin:14px 0 6px;text-transform:uppercase;letter-spacing:.07em}}
.info-table td{{padding:4px 12px 4px 0;vertical-align:top}}
.info-table td:first-child{{color:var(--text-dim);width:240px}}
.hdr-present{{color:var(--good)}}
.hdr-absent{{color:var(--crit);font-style:italic}}
.findings-table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}}
.findings-table th{{text-align:left;padding:6px 10px;color:var(--text-dim);
  border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase}}
.findings-table td{{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
.findings-table tr:last-child td{{border-bottom:none}}
.sev-crit{{color:var(--crit)}}.sev-high{{color:var(--high)}}
.sev-med{{color:var(--med)}}.sev-low{{color:var(--low)}}
.sev-info{{color:var(--text-dim)}}.good{{color:var(--good)}}
details.remed summary{{cursor:pointer;color:var(--accent);font-size:11px;margin-top:4px}}
details.remed pre{{background:#0a0a0a;border:1px solid var(--border);
  border-radius:4px;padding:8px;font-size:11px;margin-top:4px;overflow-x:auto;white-space:pre-wrap}}
footer{{margin-top:32px;text-align:center;color:var(--text-dim);font-size:11px}}
</style></head><body>
<header>
  <h1>VampSecure Labs — HTTP Security Audit Report</h1>
  <p>{TOOL_NAME} v{VERSION} · {generated} · VampSecure Studios · Uso exclusivo en auditorías autorizadas</p>
</header>
{"".join(rows_html)}
<footer>© VampSecure Studios — VampSecure Labs Security Research Division</footer>
</body></html>"""


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def to_markdown(results: list[AuditResult]) -> str:
    """Genera un informe Markdown para repositorios de informes."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    lines += [
        "# VampSecure Labs — Informe de Auditoría HTTP",
        "",
        f"**Herramienta:** {TOOL_NAME} v{VERSION}  ",
        f"**Generado:** {generated}  ",
        f"**URLs analizadas:** {len(results)}  ",
        "", "---", "",
        "## Resumen Ejecutivo",
        "",
        "| URL | Nota | Estado | CSP | HSTS | Cookies | C/H | Sev. Máx. |",
        "|-----|------|--------|-----|------|---------|-----|-----------|",
    ]
    for r in results:
        if r.error:
            lines.append(f"| `{r.url[:40]}` | **F** | ERR | — | — | — | — | ERROR |")
            continue
        csp  = "✔" if r.headers.get("content-security-policy") else "✗"
        hsts = "✔" if r.headers.get("strict-transport-security") else "✗"
        crhi = sum(1 for f in r.findings if f.severity in ("CRITICAL","HIGH"))
        lines.append(f"| `{r.url[:40]}` | **{r.grade}** | {r.status_code} | {csp} | {hsts} | {len(r.cookies)} | {crhi} | {r.max_severity} |")

    lines += ["", "---", ""]

    for r in results:
        lines.append(f"## URL: `{r.url}`")
        lines.append("")
        if r.error:
            lines.append(f"> ❌ **ERROR:** {r.error}")
            lines.append("")
            continue

        lines.append(f"### 📊 Calificación: **{r.grade}** — {GRADE_DESCRIPTION.get(r.grade,'')}")
        lines.append("")
        lines.append("### Cabeceras de seguridad")
        lines.append("")
        lines.append("| Cabecera | Valor |")
        lines.append("|----------|-------|")
        for hname, hkey in [
            ("Content-Security-Policy", "content-security-policy"),
            ("Strict-Transport-Security","strict-transport-security"),
            ("X-Frame-Options","x-frame-options"),
            ("X-Content-Type-Options","x-content-type-options"),
            ("Referrer-Policy","referrer-policy"),
            ("Permissions-Policy","permissions-policy"),
            ("COEP","cross-origin-embedder-policy"),
            ("COOP","cross-origin-opener-policy"),
            ("CORP","cross-origin-resource-policy"),
        ]:
            val = r.headers.get(hkey)
            val_md = f"`{val[:70]}…`" if val and len(val) > 70 else f"`{val}`" if val else "**AUSENTE**"
            lines.append(f"| {hname} | {val_md} |")
        lines.append("")

        if r.cookies:
            lines.append("### Cookies")
            lines.append("")
            lines.append("| Nombre | Secure | HttpOnly | SameSite |")
            lines.append("|--------|--------|----------|----------|")
            for ck in r.cookies:
                lines.append(f"| `{ck.name}` | {'✔' if ck.secure else '✗'} | {'✔' if ck.httponly else '✗'} | {ck.samesite or '—'} |")
            lines.append("")

        if r.findings:
            lines.append("### 🔍 Hallazgos")
            lines.append("")
            for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
                grp = [f for f in r.findings if f.severity == sev]
                if not grp:
                    continue
                icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}.get(sev,"")
                lines.append(f"#### {icon} {sev}")
                lines.append("")
                for f in grp:
                    lines.append(f"**{f.name}**")
                    lines.append(f"> {f.detail}")
                    if f.remediation:
                        lines += ["> ", "> **Remediación:**", "> ", "> ```"]
                        for ln in f.remediation.splitlines():
                            lines.append(f"> {ln}")
                        lines.append("> ```")
                    lines.append("")

            pri = [f for f in r.findings if f.severity in ("CRITICAL","HIGH") and f.remediation]
            if pri:
                lines.append("### ✅ Acciones inmediatas")
                lines.append("")
                for i, f in enumerate(pri, 1):
                    lines.append(f"{i}. **[{f.severity}]** {f.name}")
                lines.append("")
        else:
            lines.append("### ✅ Sin hallazgos de seguridad")
            lines.append("")
        lines += ["---", ""]

    lines += [
        f"*Generado por {TOOL_NAME} v{VERSION} · VampSecure Studios · VampSecure Labs Security Research Division*  ",
        "*Uso exclusivo en entornos autorizados. El uso no autorizado es ilegal.*",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def to_csv(results: list[AuditResult], base_path: str) -> tuple[str, str]:
    """Genera dos ficheros CSV: resumen por URL y detalle de hallazgos."""
    buf_h = io.StringIO()
    w_h   = csv_module.writer(buf_h)
    w_h.writerow([
        "url","nota","estado","csp","hsts","xfo","xcto","rp","pp",
        "coep","coop","corp","server","x_powered_by",
        "cookies","cors_reflejado","cors_creds","open_redirect",
        "num_hallazgos","hallazgos_critical","hallazgos_high",
        "severidad_maxima","error","timestamp",
    ])
    for r in results:
        hg = r.headers.get
        w_h.writerow([
            r.url, r.grade, r.status_code,
            "SI" if hg("content-security-policy")      else "NO",
            "SI" if hg("strict-transport-security")    else "NO",
            hg("x-frame-options",""),
            hg("x-content-type-options",""),
            hg("referrer-policy",""),
            hg("permissions-policy",""),
            hg("cross-origin-embedder-policy",""),
            hg("cross-origin-opener-policy",""),
            hg("cross-origin-resource-policy",""),
            hg("server",""),
            hg("x-powered-by",""),
            len(r.cookies),
            "SI" if r.cors_origin_reflected else "NO",
            "SI" if r.cors_credentials else "NO",
            "|".join(r.open_redirect_params),
            len(r.findings),
            sum(1 for f in r.findings if f.severity=="CRITICAL"),
            sum(1 for f in r.findings if f.severity=="HIGH"),
            r.max_severity, r.error or "", r.timestamp,
        ])

    buf_f = io.StringIO()
    w_f   = csv_module.writer(buf_f)
    w_f.writerow(["url","nota","severidad","categoria","hallazgo","detalle","cap_nota","remediacion"])
    for r in results:
        for f in r.findings:
            w_f.writerow([
                r.url, r.grade, f.severity, f.category, f.name,
                f.detail, f.grade_cap, f.remediation.replace("\n"," | "),
            ])

    Path(base_path).write_text(buf_h.getvalue(), encoding="utf-8")
    Path(base_path + ".findings").write_text(buf_f.getvalue(), encoding="utf-8")
    return base_path, base_path + ".findings"


# ---------------------------------------------------------------------------
# Conversión al formato de informe unificado VSL
# ---------------------------------------------------------------------------

def _findings_vsl(results: list[AuditResult]) -> list:
    """
    Convierte los AuditResult de vamp-http-audit al formato Finding de vampsec_report.

    Solo se incluyen hallazgos de severidad MEDIUM o superior. Los hallazgos INFO
    quedan disponibles en los informes técnicos dark-theme y CSV, no en el informe
    ejecutivo de cliente (exceso de ruido para el destinatario).
    """
    from vampsec_report import Finding as VSLFinding

    VSL_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}
    findings = []
    n = 0
    for r in results:
        for f in r.findings:
            if f.severity not in VSL_SEVERITIES:
                continue
            n += 1
            # Construir evidencia contextual
            ev_parts = [f"URL objetivo: {r.final_url or r.url}"]
            if r.status_code:
                ev_parts.append(f"HTTP {r.status_code}")
            if f.detail:
                ev_parts.append(f"Detalle: {f.detail}")
            if f.grade_cap:
                ev_parts.append(f"Cap de nota: {f.grade_cap} (nota final: {r.grade})")

            findings.append(VSLFinding(
                id          = f"HTTP-{n:03d}",
                title       = f.name[:80],
                severity    = f.severity,
                description = (
                    f"[{f.category}] {f.name}. "
                    + (f.detail or "Hallazgo de seguridad en cabeceras/configuración HTTP.")
                ),
                evidence    = "\n".join(ev_parts),
                affected    = r.final_url or r.url,
                remediation = (
                    f.remediation or
                    "Revisar la configuración del servidor web y aplicar las cabeceras de seguridad recomendadas."
                ),
                tags        = ["http", "headers", f.category.lower().replace(" ", "-")],
            ))
    return findings
