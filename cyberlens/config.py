from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
PARQUET_FILENAME = "cve_unified_dataset.parquet"
CSV_FILENAME = "cve_unified_dataset.csv"
METADATA_FILENAME = "dataset_metadata.json"

DEFAULT_CVSS_CUTOFF = 7.0
DEFAULT_EPSS_CUTOFF = 0.30
EPSS_SURGE_DELTA = 0.10
EPSS_SURGE_RATIO = 3.0
EPSS_SURGE_FLOOR = 0.15

LAYER_ORDER: List[str] = [
    "OS & Firmware",
    "Network Infrastructure",
    "Web & Application",
    "Database & Storage",
]

ATTACK_VECTOR_ORDER: List[str] = ["Physical", "Local", "Adjacent", "Network"]
PRIVILEGES_REQUIRED_ORDER: List[str] = ["High", "Low", "None"]
ATTACK_COMPLEXITY_ORDER: List[str] = ["High", "Low"]

CVSS_AV_WEIGHTS: Dict[str, float] = {
    "Network": 0.85,
    "Adjacent": 0.62,
    "Local": 0.55,
    "Physical": 0.20,
}

CVSS_AC_WEIGHTS: Dict[str, float] = {
    "Low": 0.77,
    "High": 0.44,
}

CVSS_PR_WEIGHTS: Dict[str, float] = {
    "None": 0.85,
    "Low": 0.62,
    "High": 0.27,
}

SLA_TIER_ORDER: List[str] = [
    "P0: Emergency (<24h)",
    "P1: Urgent (<72h)",
    "P2: Elevated (<14d)",
    "P3: Paper Tiger (Defer 60d)",
    "P4: Dormant Backlog",
]

SLA_TARGET_HOURS: Dict[str, int] = {
    "P0: Emergency (<24h)": 24,
    "P1: Urgent (<72h)": 72,
    "P2: Elevated (<14d)": 336,
    "P3: Paper Tiger (Defer 60d)": 1440,
    "P4: Dormant Backlog": 2160,
}

QUADRANT_LABELS: Dict[str, str] = {
    "Q1": "Q1: Critical Weapons (High CVSS + Active/High EPSS)",
    "Q2": "Q2: Silent Threats (Moderate CVSS + Active/High EPSS)",
    "Q3": "Q3: Paper Tigers (High CVSS + Low Exploit)",
    "Q4": "Q4: Dormant Backlog (Low Priority)",
}

# Canonical enterprise vendors mapped to architectural layer and CPE/KEV aliases
ENTERPRISE_VENDORS: Dict[str, Dict[str, object]] = {
    "Microsoft": {
        "layer": "OS & Firmware",
        "aliases": ["microsoft", "windows", "exchange", "sharepoint", "azure", "msrc"],
        "default_selected": True,
    },
    "Linux": {
        "layer": "OS & Firmware",
        "aliases": ["linux", "redhat", "red_hat", "red hat", "canonical", "ubuntu", "debian", "suse", "kernel"],
        "default_selected": True,
    },
    "VMware": {
        "layer": "OS & Firmware",
        "aliases": ["vmware", "broadcom"],
        "default_selected": True,
    },
    "Apple": {
        "layer": "OS & Firmware",
        "aliases": ["apple"],
        "default_selected": True,
    },
    "Cisco": {
        "layer": "Network Infrastructure",
        "aliases": ["cisco"],
        "default_selected": True,
    },
    "Fortinet": {
        "layer": "Network Infrastructure",
        "aliases": ["fortinet", "fortios", "fortigate"],
        "default_selected": True,
    },
    "Ivanti": {
        "layer": "Network Infrastructure",
        "aliases": ["ivanti", "pulse_secure", "mobileiron"],
        "default_selected": True,
    },
    "Palo Alto Networks": {
        "layer": "Network Infrastructure",
        "aliases": ["paloaltonetworks", "palo alto", "palo_alto", "pan-os"],
        "default_selected": True,
    },
    "Apache": {
        "layer": "Web & Application",
        "aliases": ["apache", "tomcat", "struts", "log4j"],
        "default_selected": True,
    },
    "Atlassian": {
        "layer": "Web & Application",
        "aliases": ["atlassian", "confluence", "jira", "bitbucket"],
        "default_selected": True,
    },
    "Nginx": {
        "layer": "Web & Application",
        "aliases": ["nginx", "f5"],
        "default_selected": True,
    },
    "Oracle": {
        "layer": "Database & Storage",
        "aliases": ["oracle", "mysql", "weblogic", "sun"],
        "default_selected": True,
    },
    "PostgreSQL": {
        "layer": "Database & Storage",
        "aliases": ["postgresql", "postgres", "pgadmin"],
        "default_selected": True,
    },
}

DEFAULT_SELECTED_VENDORS: List[str] = [
    vendor for vendor, meta in ENTERPRISE_VENDORS.items() if meta.get("default_selected")
]

CORE_STACK_VENDORS: List[str] = [
    vendor for vendor in ENTERPRISE_VENDORS if vendor not in {"Apple", "Atlassian"}
]

# MITRE CWE ID -> analytical weakness family
CWE_FAMILY_RULES: Dict[str, List[str]] = {
    "Memory Corruption (CWE-119)": [
        "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-190",
        "CWE-415", "CWE-416", "CWE-476", "CWE-787", "CWE-843", "CWE-129",
    ],
    "Injection (CWE-89/78)": [
        "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
        "CWE-94", "CWE-95", "CWE-917", "CWE-918",
    ],
    "Authentication Bypass (CWE-287)": [
        "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-306", "CWE-307",
        "CWE-798", "CWE-863",
    ],
    "Improper Access Control (CWE-284)": [
        "CWE-22", "CWE-23", "CWE-36", "CWE-269", "CWE-276", "CWE-284",
        "CWE-285", "CWE-434", "CWE-639", "CWE-732", "CWE-862",
    ],
    "Untrusted Deserialization (CWE-502)": [
        "CWE-502", "CWE-611", "CWE-915",
    ],
    "Cryptographic Flaws (CWE-310)": [
        "CWE-295", "CWE-310", "CWE-311", "CWE-312", "CWE-319", "CWE-326",
        "CWE-327", "CWE-328", "CWE-330", "CWE-345", "CWE-347",
    ],
    "Input Validation & Logic (CWE-20)": [
        "CWE-20", "CWE-200", "CWE-352", "CWE-362", "CWE-400", "CWE-601",
        "CWE-770",
    ],
}

CWE_ID_TO_FAMILY: Dict[str, str] = {
    cwe_id: family
    for family, cwe_ids in CWE_FAMILY_RULES.items()
    for cwe_id in cwe_ids
}

DEFAULT_CWE_FAMILY = "Input Validation & Logic (CWE-20)"

REQUIRED_SCHEMA_COLUMNS: List[str] = [
    "cve_id",
    "vendor",
    "product",
    "layer",
    "cwe_id",
    "cwe_family",
    "cvss_base",
    "cvss_impact",
    "cvss_exploitability",
    "epss_score",
    "epss_percentile",
    "epss_score_30d",
    "epss_delta_30d",
    "epss_velocity_ratio",
    "is_epss_surge",
    "is_kev",
    "is_ransomware",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "disclosure_date",
    "kev_date_added",
    "kev_due_date",
    "days_to_exploit",
    "kev_required_action",
    "description",
]
