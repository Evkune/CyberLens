# CyberLens

[![Python](https://img.shields.io/badge/Python-3.10%2B-09090B?logo=python&logoColor=white)](https://www.python.org/)
[![Shiny for Python](https://img.shields.io/badge/Shiny-for%20Python-09090B)](https://shiny.posit.co/py/)
[![Plotly](https://img.shields.io/badge/Plotly-WebGL%20%26%20SVG-09090B)](https://plotly.com/python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-09090B)](LICENSE)

**CyberLens** is a threat-informed visual analytics platform for **Risk-Based Vulnerability Management (RBVM)**. It fuses NVD CVSS v3.1 severity, FIRST EPSS v3 30-day exploitation probabilities (including 30-day velocity surges), and CISA KEV ground truth into a coordinated multi-view triage environment that compresses alert fatigue while preserving **100% KEV recall**.

---

## Key Capabilities

- **Unified Real-World Snapshot:** Built-in ETL pipeline and normalized Parquet/CSV snapshot covering **3,092 enterprise CVEs**, **521 confirmed CISA KEVs** (**114 ransomware-linked**), **27 EPSS 30-day velocity surges**, and **13 enterprise software vendors** across 4 architectural tiers.
- **Deterministic RBVM SLA Engine (`P0–P4`):** Classifies vulnerabilities dynamically against interactive CVSS and EPSS cutoffs into `P0 (<24h)`, `P1 (<72h)`, `P2 (<14d)`, `P3 (Paper Tiger — Defer 60d)`, and `P4 (Dormant Backlog)`, computing actuarial expected risk (`CVSS × P_eff`) and low-CVSS blind-spot scores.
- **Three Coordinated Analytical Views (`anywidget` + Plotly):**
  1. **Threat Prioritization Scatter (`go.Scattergl`):** WebGL bivariate plot (CVSS vs. EPSS, Linear or Log10 scale) with Stevens' Power Law area scaling (`a = 0.7`), ransomware/surge glyph encoding, plot-area-scoped mouse-wheel zoom, lasso brushing, and single-click CVE pinning.
  2. **Attack Surface Hierarchy (Squarified Treemap):** `Layer → CWE Family → Vendor` drill-down sized by Expected Risk, Actionable Queue (`P0–P2`), or Confirmed KEVs, shaded by network exposure ratio, with click-to-cross-filter synchronization.
  3. **Exploitation Velocity Ridgeline (Reflected Gaussian KDE):** Boundary-corrected disclosure-to-KEV lag density on `[0, +∞)` sorted by ascending cohort median (`P50`) with `24h (P0)`, `0–7d Flash`, and `14d Legacy SLA` markers.
- **On-Demand 5D Logit K-Means (`K ∈ [3, 6]`):** Standardized clustering over CVSS, logit-EPSS, compressed 30-day EPSS velocity, impact, and CVSS exploitability access ease, with live Silhouette and Davies-Bouldin diagnostics.
- **Operational Patch Queue & CVE Inspector:** Filterable, sortable `DataGrid` with CSV export and synchronized CVE inspection drawer linking directly to NVD and CISA KEV advisories.

---

## Architecture

```text
CyberLens/
├── cyberlens/
│   ├── app.py                   # Reactive Shiny app & persistent FigureWidget sync
│   ├── config.py                # Thresholds, vendor inventory, CWE taxonomy, schema
│   ├── domain/
│   │   ├── prioritization.py    # Vectorized RBVM P0–P4 engine, presets & queue ranking
│   │   ├── metrics.py           # Single-pass triage KPIs & queue compression metrics
│   │   └── clustering.py        # 5D Logit K-Means++ threat archetype discovery
│   ├── ingestion/
│   │   ├── feeds_client.py      # NVD, FIRST EPSS v3 (current + 30d), CISA KEV clients
│   │   ├── etl_pipeline.py      # Normalization, join & Parquet/CSV snapshot builder
│   │   └── loader.py            # Cached dataset & metadata loader with ordinal typing
│   ├── ui/
│   │   ├── mod_sidebar.py       # Progressive-disclosure controls & ML diagnostics
│   │   ├── mod_kpi_header.py    # Policy telemetry strip, cross-filter bus & 4 KPIs
│   │   ├── mod_triage_queue.py  # Actionable Patch Queue DataGrid, inspector & CSV export
│   │   └── styles.py            # Swiss Editorial Light CSS & plot-scoped wheel zoom JS
│   └── viz/
│       ├── theme.py             # Colorblind-safe Swiss Light palettes & layout helpers
│       ├── idiom_bubble.py      # WebGL Prioritization Bubble Plot (Idiom 1)
│       ├── idiom_treemap.py     # Architectural Weakness Treemap (Idiom 2)
│       └── idiom_ridgeline.py   # Exploitation Velocity Ridgeline Plot (Idiom 3)
├── data/
│   ├── cve_unified_dataset.parquet
│   ├── cve_unified_dataset.csv
│   └── dataset_metadata.json
├── tests/                       # Automated pytest suite
├── pytest.ini
├── requirements.txt
└── README.md
```

---

## Quickstart

### Prerequisites
- Python **3.10+** (verified on Python 3.12)

### Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Launching CyberLens

```bash
PYTHONPATH=. .venv/bin/shiny run cyberlens/app.py --port 8000
```

Open `http://127.0.0.1:8000` in your browser.

### Running the Test Suite

```bash
PYTHONPATH=. .venv/bin/pytest -v
```

### Refreshing the Threat Intelligence Snapshot (Optional)

The repository ships with a pre-built snapshot in `data/`. To re-fetch live NVD, FIRST EPSS v3, and CISA KEV feeds:

```bash
PYTHONPATH=. .venv/bin/python -m cyberlens.ingestion.etl_pipeline
```

---

## Authors & License

- **Evan Gendrot** — [@Evkune](https://github.com/Evkune)
- **Minerva Nayeli Rosas Sanchez**

Licensed under the [MIT License](LICENSE).
