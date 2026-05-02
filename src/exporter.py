from __future__ import annotations
import csv
import json
from pathlib import Path
from models import LogEntry

_SEVERITY_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#aaaaaa",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Simulator — Session Log</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #0d1117;
    color: #c9d1d9;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    padding: 24px;
  }}

  /* ── Alert box ── */
  .alert-box {{
    border: 1px solid {sev_color};
    border-left: 4px solid {sev_color};
    background: #161b22;
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 24px;
    max-width: 900px;
  }}
  .alert-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
  }}
  .alert-badge {{
    background: {sev_color};
    color: #0d1117;
    font-weight: bold;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 3px;
    letter-spacing: 1px;
  }}
  .alert-rule {{
    color: #8b949e;
    font-size: 12px;
  }}
  .alert-rule span {{
    color: #e6edf3;
    font-weight: bold;
  }}
  .alert-triggered {{
    color: #8b949e;
    font-size: 11px;
    margin-bottom: 10px;
  }}
  .alert-summary {{
    color: #e6edf3;
    font-size: 14px;
    margin-bottom: 8px;
    line-height: 1.5;
  }}
  .alert-description {{
    color: #8b949e;
    font-size: 12px;
    line-height: 1.6;
    border-top: 1px solid #21262d;
    padding-top: 10px;
    margin-top: 8px;
  }}

  /* ── Stats bar ── */
  .stats {{
    display: flex;
    gap: 24px;
    margin-bottom: 16px;
    color: #8b949e;
    font-size: 12px;
  }}
  .stats span {{ color: #e6edf3; font-weight: bold; }}

  /* ── Filter ── */
  .filter-bar {{
    margin-bottom: 12px;
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
  }}
  .filter-bar input {{
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 6px 12px;
    border-radius: 4px;
    font-family: inherit;
    font-size: 12px;
    width: 260px;
  }}
  .filter-bar input:focus {{ outline: none; border-color: #58a6ff; }}
  .filter-bar select {{
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 6px 10px;
    border-radius: 4px;
    font-family: inherit;
    font-size: 12px;
  }}
  .filter-label {{ color: #8b949e; font-size: 12px; }}

  /* ── Table ── */
  .table-wrap {{
    overflow-x: auto;
    border: 1px solid #21262d;
    border-radius: 6px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    min-width: 900px;
  }}
  thead th {{
    background: #161b22;
    color: #8b949e;
    font-weight: bold;
    font-size: 11px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 2px solid #21262d;
    position: sticky;
    top: 0;
  }}
  tbody tr {{
    border-bottom: 1px solid #161b22;
    transition: background 0.1s;
  }}
  tbody tr:hover {{ background: #1c2128; }}
  tbody tr.hidden {{ display: none; }}
  td {{ padding: 7px 12px; vertical-align: top; white-space: nowrap; }}
  td.details-cell {{
    white-space: normal;
    word-break: break-word;
    max-width: 340px;
    color: #8b949e;
    font-size: 11px;
  }}

  /* ── Source type badges ── */
  .src-badge {{
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
  }}
  .src-Windows-Security {{ background: #1f3a5f; color: #58a6ff; }}
  .src-Sysmon           {{ background: #1f3f2a; color: #3fb950; }}
  .src-Proxy            {{ background: #3f2a1f; color: #d29922; }}
  .src-DNS              {{ background: #3a1f3f; color: #bc8cff; }}

  /* ── EID pill ── */
  .eid {{ color: #8b949e; }}

  /* ── Row count ── */
  #row-count {{ color: #8b949e; font-size: 12px; }}
</style>
</head>
<body>

<!-- Alert -->
<div class="alert-box">
  <div class="alert-header">
    <span class="alert-badge">{severity}</span>
    <span class="alert-rule">Rule: <span>{rule_id}</span></span>
  </div>
  <div class="alert-triggered">Triggered: {triggered}</div>
  <div class="alert-summary">{summary}</div>
  {description_html}
</div>

<!-- Stats -->
<div class="stats">
  Total events: <span>{total}</span>
  &nbsp;|&nbsp; Session window: <span>{window}</span>
</div>

<!-- Filter bar -->
<div class="filter-bar">
  <span class="filter-label">Filter:</span>
  <input type="text" id="search" placeholder="user, IP, host, command..." oninput="applyFilter()">
  <select id="src-filter" onchange="applyFilter()">
    <option value="">All sources</option>
    <option>Windows-Security</option>
    <option>Sysmon</option>
    <option>Proxy</option>
    <option>DNS</option>
  </select>
  <span id="row-count"></span>
</div>

<!-- Log table -->
<div class="table-wrap">
<table id="log-table">
  <thead>
    <tr>
      <th>Time</th>
      <th>Source</th>
      <th>EID</th>
      <th>User</th>
      <th>Src IP</th>
      <th>Dest Host</th>
      <th>Details</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
</div>

<script>
  function applyFilter() {{
    const q = document.getElementById('search').value.toLowerCase();
    const src = document.getElementById('src-filter').value;
    const rows = document.querySelectorAll('#log-table tbody tr');
    let visible = 0;
    rows.forEach(r => {{
      const text = r.dataset.search || '';
      const rowSrc = r.dataset.src || '';
      const match = (!q || text.includes(q)) && (!src || rowSrc === src);
      r.classList.toggle('hidden', !match);
      if (match) visible++;
    }});
    document.getElementById('row-count').textContent = visible + ' / ' + rows.length + ' events';
  }}
  applyFilter();
</script>
</body>
</html>
"""

_ROW_TEMPLATE = (
    '<tr data-search="{search}" data-src="{src_type}">'
    '<td>{time}</td>'
    '<td><span class="src-badge src-{src_cls}">{src_type}</span></td>'
    '<td class="eid">{eid}</td>'
    '<td>{user}</td>'
    '<td>{src_ip}</td>'
    '<td>{dest_host}</td>'
    '<td class="details-cell">{details}</td>'
    '</tr>'
)


class Exporter:
    def to_csv(self, logs: list[LogEntry], filepath: Path) -> None:
        filepath = Path(filepath)
        fieldnames = ["timestamp", "source_type", "event_id", "user", "source_ip", "dest_host", "details_json"]
        with filepath.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in logs:
                writer.writerow(entry.to_csv_row())

    def to_ndjson(self, logs: list[LogEntry], filepath: Path) -> None:
        filepath = Path(filepath)
        with filepath.open("w", encoding="utf-8") as f:
            for entry in logs:
                f.write(json.dumps(entry.to_json()) + "\n")

    def to_html(
        self,
        logs: list[LogEntry],
        filepath: Path,
        alert_rule: str = "",
        alert_severity: str = "MEDIUM",
        alert_summary: str = "",
        alert_description: str = "",
        alert_triggered: str = "",
    ) -> None:
        filepath = Path(filepath)
        sev_color = _SEVERITY_COLOR.get(alert_severity.upper(), "#aaaaaa")

        desc_html = ""
        if alert_description:
            desc_html = f'<div class="alert-description">{_esc(alert_description)}</div>'

        rows_html = []
        for entry in logs:
            ts = entry.timestamp.strftime("%H:%M:%S")
            details_str = "; ".join(f"{k}: {v}" for k, v in entry.details.items())
            search_str = " ".join([
                ts, entry.source_type, str(entry.event_id),
                entry.user, entry.source_ip, entry.dest_host, details_str
            ]).lower()
            src_cls = entry.source_type.replace(" ", "-").replace("_", "-")
            rows_html.append(_ROW_TEMPLATE.format(
                search=_esc(search_str),
                src_type=_esc(entry.source_type),
                src_cls=_esc(src_cls),
                time=ts,
                eid=entry.event_id,
                user=_esc(entry.user),
                src_ip=_esc(entry.source_ip),
                dest_host=_esc(entry.dest_host),
                details=_esc(details_str[:200]),
            ))

        if logs:
            t0 = min(e.timestamp for e in logs).strftime("%H:%M")
            t1 = max(e.timestamp for e in logs).strftime("%H:%M")
            window = f"{t0} – {t1}"
        else:
            window = "—"

        html = _HTML_TEMPLATE.format(
            sev_color=sev_color,
            severity=_esc(alert_severity.upper()),
            rule_id=_esc(alert_rule),
            triggered=_esc(alert_triggered),
            summary=_esc(alert_summary),
            description_html=desc_html,
            total=len(logs),
            window=window,
            rows="\n".join(rows_html),
        )

        filepath.write_text(html, encoding="utf-8")

    def to_terminal(self, logs: list[LogEntry], head: int = 20) -> None:
        header = f"{'TIMESTAMP':10s} {'SOURCE':14s} {'EID':5s} {'USER':22s} {'SRC IP':16s} {'DEST HOST'}"
        sep = "-" * 95
        print(sep)
        print(header)
        print(sep)
        for entry in logs[:head]:
            ts = entry.timestamp.strftime("%H:%M:%S")
            print(
                f"{ts:10s} {entry.source_type:14s} {entry.event_id:<5d} "
                f"{entry.user:22s} {entry.source_ip:16s} {entry.dest_host}"
            )
        if len(logs) > head:
            print(f"  ... and {len(logs) - head} more events")
        print(sep)


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
