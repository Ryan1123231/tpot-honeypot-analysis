# /reports

This folder is written to automatically by `scripts/analyze_logs.py` and
`scripts/generate_dashboard.py` (and by the daily GitHub Actions workflow).
Nothing in here is hand-edited - it's regenerated from whatever logs were
most recently pulled from the honeypot.

| File | What it is |
|---|---|
| `LATEST.md` | Always a copy of the most recent report - link here if you want a stable URL. |
| `report_<date>.md` | One dated snapshot report per analysis run. Kept as history. |
| `data/metrics_<date>.json` | The machine-readable numbers behind each report. `generate_dashboard.py` reads *all* of these to build trend charts, so don't delete old ones if you want history to keep working. |
| `dashboard.html` | Chart view (attack volume over time, top IPs/countries/ports/malware families). Open directly in a browser, or serve via GitHub Pages. |

See `docs/METHODOLOGY.md` in the repo root for how each metric is computed and its limitations.
