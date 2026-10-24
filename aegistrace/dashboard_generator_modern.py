
"""Modern dark SOC dashboard generator for AegisTrace."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px


def _json_records(records: list[dict[str, Any]]) -> str:
    """Serialize records safely for embedding in HTML."""
    return json.dumps(records, default=str).replace("</", "<\\/")


def generate_modern_dashboard(
    threats: list[dict[str, Any]],
    predictions: pd.DataFrame | None = None,
    iocs_enriched: list[dict[str, Any]] | None = None,
    output_file: str = "dashboard_modern.html",
) -> str:
    """Generate a responsive SOC dashboard from pipeline results."""
    threats = threats or []
    iocs = iocs_enriched or []
    predictions = predictions if predictions is not None else pd.DataFrame()

    threat_df = pd.DataFrame(threats)
    ioc_df = pd.DataFrame(iocs)

    def count_values(df: pd.DataFrame, column: str) -> dict[str, int]:
        if column not in df.columns:
            return {}
        return {
            str(key): int(value)
            for key, value in df[column].fillna("Unknown").value_counts().items()
        }

    threat_types = count_values(threat_df, "threat_type")
    sectors = count_values(threat_df, "sector")
    ioc_types = count_values(ioc_df, "type")

    ip_count = sum(
        1 for item in iocs
        if str(item.get("type", "")).lower() in {"ip", "ipv4", "ipv6", "ip address"}
    )
    domain_count = sum(
        1 for item in iocs
        if "domain" in str(item.get("type", "")).lower()
    )

    high_risk = sum(
        1 for item in iocs
        if any(
            word in str(item.get("reputation", "")).lower()
            for word in ("malicious", "high risk", "high-risk", "critical")
        )
    )

    def chart_html(fig: Any) -> str:
        return fig.to_html(
            full_html=False,
            include_plotlyjs="cdn",
            config={"responsive": True, "displaylogo": False},
        )

    if threat_types:
        type_fig = px.bar(
            x=list(threat_types.keys()),
            y=list(threat_types.values()),
            labels={"x": "Threat type", "y": "Records"},
            title="Threats by type",
        )
    else:
        type_fig = px.bar(title="Threats by type — no data")

    if sectors:
        sector_fig = px.pie(
            names=list(sectors.keys()),
            values=list(sectors.values()),
            hole=0.62,
            title="Threat distribution by sector",
        )
    else:
        sector_fig = px.pie(title="Threat distribution — no data")

    if ioc_types:
        ioc_fig = px.bar(
            x=list(ioc_types.keys()),
            y=list(ioc_types.values()),
            labels={"x": "Indicator type", "y": "Count"},
            title="Indicators by type",
        )
    else:
        ioc_fig = px.bar(title="Indicators by type — no data")

    if not predictions.empty and {
        "date", "predicted_threats"
    }.issubset(predictions.columns):
        forecast_fig = px.line(
            predictions,
            x="date",
            y="predicted_threats",
            color="risk_level" if "risk_level" in predictions.columns else None,
            markers=True,
            title="Threat forecast",
        )
        forecast_html = chart_html(forecast_fig)
    else:
        forecast_html = (
            '<div class="empty">No forecast data available for this run.</div>'
        )

    for fig in (type_fig, sector_fig, ioc_fig):
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#dbe7f5",
            margin=dict(l=20, r=20, t=55, b=20),
            height=320,
        )

    # Build tables using escaped text so source content cannot inject HTML.
    threat_columns = [
        col for col in
        ("title", "sector", "threat_type", "source", "summary_nlp")
        if col in threat_df.columns
    ]
    ioc_columns = [
        col for col in
        ("indicator", "type", "reputation", "country", "active", "source")
        if col in ioc_df.columns
    ]

    def table_html(df: pd.DataFrame, columns: list[str], limit: int) -> str:
        if df.empty or not columns:
            return '<tr><td colspan="6">No records available for this run.</td></tr>'
        rows = []
        for _, row in df[columns].head(limit).iterrows():
            cells = "".join(
                f"<td>{escape(str(row[col]))}</td>"
                for col in columns
            )
            rows.append(f"<tr>{cells}</tr>")
        return "".join(rows)

    threat_headers = "".join(
        f"<th>{escape(col.replace('_', ' ').title())}</th>"
        for col in threat_columns
    ) or "<th>Threat records</th>"

    ioc_headers = "".join(
        f"<th>{escape(col.replace('_', ' ').title())}</th>"
        for col in ioc_columns
    ) or "<th>Indicators</th>"

    now = datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    threat_data = _json_records(threats)
    ioc_data = _json_records(iocs)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisTrace | Threat Intelligence</title>
<style>
:root {{
  color-scheme: dark;
  --bg:#080d18; --panel:#111a2b; --line:#24334b;
  --text:#edf4ff; --muted:#8fa3bd; --cyan:#48d8e8;
  --green:#45d6a0; --red:#ff657a;
}}
* {{ box-sizing:border-box; }}
body {{
  margin:0; background:var(--bg); color:var(--text);
  font:14px/1.5 Inter,Segoe UI,Arial,sans-serif;
}}
header {{
  padding:24px clamp(16px,4vw,48px); border-bottom:1px solid var(--line);
  display:flex; align-items:center; justify-content:space-between; gap:18px;
  flex-wrap:wrap;
}}
.brand {{ font-size:23px; font-weight:800; letter-spacing:.4px; }}
.brand span {{ color:var(--cyan); }}
.muted {{ color:var(--muted); }}
.status {{ color:var(--green); font-size:12px; }}
main {{ max-width:1500px; margin:auto; padding:28px clamp(14px,3vw,40px); }}
.heading {{ display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; }}
h1 {{ font-size:clamp(24px,3vw,34px); margin:0 0 6px; }}
h2 {{ font-size:17px; margin:0 0 14px; }}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin:24px 0; }}
.card,.panel {{
  background:var(--panel); border:1px solid var(--line);
  border-radius:14px; padding:19px; min-width:0;
}}
.kpi-label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
.kpi-value {{ font-size:30px; font-weight:750; margin-top:8px; overflow-wrap:anywhere; }}
.accent {{ color:var(--cyan); }} .danger {{ color:var(--red); }}
.charts {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }}
.chart {{ min-width:0; overflow:hidden; }}
.wide {{ grid-column:1/-1; }}
.table-wrap {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; min-width:650px; font-size:13px; }}
th,td {{ text-align:left; padding:12px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--cyan); font-weight:650; }}
td {{ overflow-wrap:anywhere; max-width:420px; }}
input {{
  background:#0a1220; color:var(--text); border:1px solid var(--line);
  border-radius:8px; padding:10px 12px; width:min(100%,320px);
}}
button {{
  border:1px solid var(--line); background:#15243a; color:var(--text);
  border-radius:8px; padding:10px 13px; cursor:pointer;
}}
button:hover {{ border-color:var(--cyan); }}
.toolbar {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:12px; }}
.empty {{ color:var(--muted); padding:30px 8px; text-align:center; }}
footer {{ color:var(--muted); text-align:center; padding:26px; font-size:12px; }}
@media(max-width:760px) {{
  .charts {{ grid-template-columns:1fr; }}
  .wide {{ grid-column:auto; }}
  header {{ align-items:flex-start; }}
}}
</style>
</head>
<body>
<header>
  <div>
    <div class="brand">AEGIS<span>TRACE</span></div>
    <div class="muted">Cyber Threat Intelligence Operations</div>
  </div>
  <div><div class="status">● LOCAL REPORT GENERATED</div><div class="muted">{now}</div></div>
</header>
<main>
  <div class="heading">
    <div><h1>Threat Intelligence Overview</h1>
    <div class="muted">Analysis of records collected by the current pipeline run.</div></div>
    <div class="toolbar">
      <button onclick="downloadCSV('threats')">Export threats CSV</button>
      <button onclick="downloadCSV('iocs')">Export IOC CSV</button>
    </div>
  </div>

  <section class="kpis">
    <div class="card"><div class="kpi-label">Threat records</div><div class="kpi-value accent">{len(threats)}</div></div>
    <div class="card"><div class="kpi-label">Indicators</div><div class="kpi-value">{len(iocs)}</div></div>
    <div class="card"><div class="kpi-label">IP indicators</div><div class="kpi-value">{ip_count}</div></div>
    <div class="card"><div class="kpi-label">Domain indicators</div><div class="kpi-value">{domain_count}</div></div>
    <div class="card"><div class="kpi-label">High-risk labels</div><div class="kpi-value danger">{high_risk}</div></div>
  </section>

  <section class="charts">
    <div class="panel chart">{chart_html(type_fig)}</div>
    <div class="panel chart">{chart_html(sector_fig)}</div>
    <div class="panel chart">{chart_html(ioc_fig)}</div>
    <div class="panel chart"><h2>Forecast</h2>{forecast_html}</div>

    <div class="panel wide">
      <h2>Recent Threat Records</h2>
      <div class="toolbar"><input id="threatSearch" placeholder="Search threat records..." oninput="filterTable('threatSearch','threatTable')"></div>
      <div class="table-wrap"><table id="threatTable"><thead><tr>{threat_headers}</tr></thead><tbody>{table_html(threat_df, threat_columns, 50)}</tbody></table></div>
    </div>

    <div class="panel wide">
      <h2>Indicators of Compromise</h2>
      <div class="toolbar"><input id="iocSearch" placeholder="Search indicators..." oninput="filterTable('iocSearch','iocTable')"></div>
      <div class="table-wrap"><table id="iocTable"><thead><tr>{ioc_headers}</tr></thead><tbody>{table_html(ioc_df, ioc_columns, 100)}</tbody></table></div>
    </div>
  </section>
</main>
<footer>AegisTrace dashboard · Generated report, not a continuous live feed. Original project attribution and license are retained.</footer>
<script>
const threatData = {threat_data};
const iocData = {ioc_data};
function filterTable(inputId, tableId) {{
  const query = document.getElementById(inputId).value.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tbody tr').forEach(row => {{
    row.style.display = row.innerText.toLowerCase().includes(query) ? '' : 'none';
  }});
}}
function downloadCSV(kind) {{
  const data = kind === 'threats' ? threatData : iocData;
  if (!data.length) {{ alert('No records available to export.'); return; }}
  const columns = [...new Set(data.flatMap(row => Object.keys(row)))];
  const quote = value => '"' + String(Array.isArray(value) ? value.join(', ') : (value ?? '')).replaceAll('"','""') + '"';
  const csv = [columns.map(quote).join(','), ...data.map(row => columns.map(key => quote(row[key])).join(','))].join('\\r\\n');
  const blob = new Blob([csv], {{type:'text/csv;charset=utf-8;'}});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = kind + '_aegistrace.csv';
  link.click();
  URL.revokeObjectURL(link.href);
}}
</script>
</body>
</html>"""

    output = Path(output_file)
    output.write_text(html, encoding="utf-8")
    return str(output.resolve())
