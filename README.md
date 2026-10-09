# CyberLens: Threat-Informed Vulnerability Prioritization

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Shiny for Python](https://img.shields.io/badge/Shiny-for%20Python-38bdf8?logo=rstudio&logoColor=white)](https://shiny.posit.co/py/)
[![Plotly](https://img.shields.io/badge/Plotly-Interactive%20Visuals-3f4f75?logo=plotly&logoColor=white)](https://plotly.com/python/)
[![Pandas](https://img.shields.io/badge/Pandas-Data%20Engine-150458?logo=pandas&logoColor=white)](https://pandas.pydata.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-amber.svg)]()
[![Academic Context](https://img.shields.io/badge/Academic-UPM%20%7C%20INSA%20Rennes-0284c7)]()

> **Threat-Informed Visual Analytics Platform for Enterprise Risk-Based Vulnerability Management (RBVM)**  
> Developed as part of the *Data Visualization / Visual Analytics* curriculum at **Universidad Politécnica de Madrid (ETSIINF / UPM)** in partnership with **INSA Rennes** (M2 Cybersecurity).

---

## 1. Executive Summary & Problem Characterization

Enterprise Security Operations Centers (SOC) and Vulnerability Management teams face acute alert fatigue, with more than **28,000 Common Vulnerabilities and Exposures (CVEs)** published each year. Traditional compliance frameworks require patching all vulnerabilities scoring High or Critical ($\text{CVSS} \ge 7.0$).

However, empirical threat intelligence indicates that **less than 4.5% of published CVEs are ever weaponized in the wild**. Simultaneously, several vulnerabilities rated as Moderate ($4.0 \le \text{CVSS} \le 6.9$) due to local execution prerequisites are actively leveraged in targeted intrusion chains for privilege escalation and lateral movement.

Static database queries (`SELECT * WHERE cvss >= 7.0`) cannot solve this triage dilemma because organizational risk boundaries are continuous and multi-dimensional. **CyberLens** bridges theoretical severity, empirical weaponization probability, and observed real-world exploitation into a unified visual analytics environment following the **Tamara Munzner Four-Level Nested Framework**.

---

## 2. Architecture & Data Flow

```mermaid
flowchart TD
    subgraph Data_Sources [Threat Intelligence Feeds]
        NVD["NIST NVD\n(CVSS v3.1, CWE, Metrics)"]
        EPSS["FIRST.org EPSS v3\n(30-day Exploit Probabilities)"]
        KEV["CISA KEV\n(Confirmed Weaponized Exploits)"]
    end

    subgraph ETL_Pipeline [Normalization & Data Engine]
        Ingest["ETL Pipeline (cyberlens.etl_pipeline)\nSchema Alignment & Join"]
        Parquet["Data Store\n(Parquet / CSV Standardized Feeds)"]
        Engine["Data Engine (cyberlens.data_engine)\nEnterprise Stack Filtering & Triage Quadrants"]
    end

    subgraph Analytics_Core [Analytical & Machine Learning Core]
        KMeans["Unsupervised 4D K-Means\nThreat Archetypes Discovery"]
        KDE["Gaussian Kernel Density Estimation\nVelocity & Survival Modeling"]
    end

    subgraph Visual_Interface [Interactive Decision Support (Shiny & Plotly)]
        Idiom1["Idiom 1: Bivariate Risk Bubble Plot\n(CVSS vs EPSS, Stevens' Law Scaled)"]
        Idiom2["Idiom 2: Hierarchical Weakness Treemap\n(Space-Filling Architecture Layers)"]
        Idiom3["Idiom 3: Multi-Cohort Ridgeline Plot\n(Continuous Weaponization Velocity)"]
    end

    NVD --> Ingest
    EPSS --> Ingest
    KEV --> Ingest
    Ingest --> Parquet
    Parquet --> Engine
    Engine --> KMeans
    Engine --> KDE
    KMeans --> Idiom1
    Engine --> Idiom2
    KDE --> Idiom3
```

---

## 3. Data & Task Abstraction (Munzner Framework)

### Data Abstraction (WHAT)
The normalized dataset merges four key dimensions into 4,500+ structured items:
* **Identification Keys:** `cve_id`, `vendor`, `product`, `layer` (Architectural tier: OS/Firmware, Network, Web/App, Database), `cwe_family`.
* **Quantitative Risk Scores (Sequential):** `cvss_base` ($0.0 - 10.0$), `cvss_impact` ($0.0 - 6.0$), `epss_score` ($0.000 - 1.000$, heavy-tailed log-normal).
* **Observed Exploitation (Categorical):** `is_kev` (Boolean, CISA KEV ground truth).
* **Attack Primitives (Ordinal):** `attack_vector` ($\text{Network} > \text{Adjacent} > \text{Local} > \text{Physical}$), `privileges_required` ($\text{None} < \text{Low} < \text{High}$).
* **Longitudinal Metric (Quantitative):** `days_to_exploit` (Elapsed days between disclosure and confirmed weaponization).

### Task Abstraction (WHY) & Visual Idioms (HOW)

| Task | Munzner Action & Target | Idiom Implementation | Visual Encoding Rationale |
|---|---|---|---|
| **Task 1: Bivariate Risk Profiling** | `Consume → Discover`<br>`{Explore, Identify, Outliers & Correlation}` | **Multi-Channel Bubble Plot** (Plotly) | Spatial Position (X = CVSS, Y = EPSS) dominates cognitive accuracy (*Stevens' Law*). Mark size encodes CVSS Impact. Color hue isolates active CISA KEV threats in pre-attentive pop-out. |
| **Task 2: Structural Weakness Decomposition** | `Consume → Discover`<br>`{Browse, Compare, Hierarchical Distribution}` | **Architectural Treemap** (Space-Filling) | Spatial containment (Layer → CWE Family → Vendor). Area encodes aggregate corporate threat weight ($\text{CVSS} \times \text{EPSS}$). Luminance encodes network exposure. |
| **Task 3: Weaponization Velocity Modeling** | `Consume → Discover`<br>`{Locate, Compare, Continuous Distribution}` | **Multi-Cohort Ridgeline Density** (SciPy KDE) | Continuous Gaussian KDE on separate baselines replaces simplistic SQL min/max queries, highlighting zero-day weaponization spikes ($t < 7\text{ days}$) vs long decay. |

---

## 4. Academic Milestones & Project Roadmap

| Phase | Description | Academic Schedule | Status |
|:---:|---|:---:|:---:|
| **Phase 1** | **Problem Characterization & Methodological Framing**<br>• Formal Munzner 4-level taxonomy and analytical questions<br>• Unified ETL pipeline synthesizing NVD, EPSS v3, and CISA KEV<br>• Proposal defense and formal faculty approval | October 5, 2026 | Completed |
| **Phase 2** | **Statistical Modeling & Visual Idiom Refinement**<br>• In-depth exploratory data analysis (EDA) across vulnerability cohorts<br>• Unsupervised 4D K-Means clustering (`[CVSS, EPSS, Impact, Complexity]`)<br>• Unit test coverage and dynamic cross-filtering optimization | October – November 2026 | In Progress |
| **Phase 3** | **Coordinated Dashboard & Cloud Deployment**<br>• Reactive multi-view application (Shiny for Python + Plotly)<br>• Public cloud hosting on Posit Connect Cloud / Shinyapps.io<br>• Comprehensive final research report & oral defense | December – January 11, 2027 | Planned |

---

## 5. Repository Structure

```text
CyberLens/
├── cyberlens/              # Core Python package
│   ├── __init__.py         # Package initialization & version metadata
│   ├── etl_pipeline.py     # Ingestion & synthesis of NVD, EPSS v3, and KEV
│   ├── data_engine.py      # Stack filtering, KPI computation, risk quadrants
│   ├── ml_clustering.py    # Unsupervised K-Means 4D threat archetypes
│   ├── idiom_bubble.py     # Bivariate Prioritization Bubble Plot (Idiom 1)
│   ├── idiom_treemap.py    # Architectural Weakness Treemap (Idiom 2)
│   ├── idiom_ridgeline.py  # Weaponization Velocity Ridgeline Plot (Idiom 3)
│   └── app.py              # Interactive Shiny for Python application
├── data/                   # Data directory (tracked with .gitkeep)
│   └── .gitkeep
├── docs/                   # Methodological documentation
│   ├── METHODOLOGY.md      # Detailed Munzner framework & metric formulation
│   ├── PROJECT_PROPOSAL_CYBERLENS.md # Formal proposal document
│   └── PROJECT_PROPOSAL_CYBERLENS.pdf # Approved 2-page proposal PDF
├── tests/                  # Automated test suite
│   ├── __init__.py
│   └── test_data_engine.py # Unit tests for data engine, schema & clustering
├── .gitignore              # Python, virtual environments, datasets & caches
├── LICENSE                 # MIT License
├── pytest.ini              # Pytest configuration
├── requirements.txt        # Production dependencies
└── README.md               # Project documentation
```

---

## 6. Quickstart Guide

### Prerequisites
* Python 3.10+ (tested on Python 3.12)
* Virtual environment recommended (`venv` or `conda`)

### Installation

```bash
# Clone the repository
git clone https://github.com/Evkune/CyberLens.git
cd CyberLens

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the ETL Pipeline

To generate and normalize the unified dataset (stored in `data/`):

```bash
python -m cyberlens.etl_pipeline
```

### Running the Test Suite

```bash
pytest
```

### Launching the Dashboard Prototype

```bash
shiny run cyberlens/app.py --reload --port 8000
```

Open `http://127.0.0.1:8000` in your browser.

---

## 7. Authors & Academic Credits

* **Evan Gendrot** — *Cybersecurity Engineering Student* ([INSA Rennes](https://www.insa-rennes.fr/) / Erasmus Exchange at [ETSI de Ingenieros Informáticos, UPM](https://www.fi.upm.es/))  
  *GitHub:* [@Evkune](https://github.com/Evkune)
* **Academic Supervisor:** Prof. Pablo Toharia Rabasco — *Department of Computer Architecture and Technology, UPM*

---

## 8. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
