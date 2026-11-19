from __future__ import annotations

import time

import numpy as np
import pandas as pd
import pytest

from cyberlens.config import QUADRANT_LABELS, SLA_TIER_ORDER
from cyberlens.domain.metrics import calculate_triage_metrics
from cyberlens.domain.prioritization import (
    enrich_prioritization,
    filter_by_scope,
    rank_action_queue,
)
from cyberlens.ingestion.loader import load_dataset


@pytest.fixture
def synthetic_edge_cases() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "cve_id": "CVE-2024-0001",
                "vendor": "Palo Alto Networks",
                "product": "PAN-OS",
                "layer": "Network Infrastructure",
                "cwe_family": "Injection (CWE-89/78)",
                "cvss_base": 9.8,
                "cvss_impact": 5.9,
                "epss_score": 0.95,
                "epss_delta_30d": 0.02,
                "is_epss_surge": False,
                "is_kev": True,
                "is_ransomware": True,
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "disclosure_year": 2024,
                "days_to_exploit": 2.0,
            },
            {
                # Critical SOC edge case: low CVSS + low EPSS, but confirmed local KEV!
                "cve_id": "CVE-2024-0002",
                "vendor": "Microsoft",
                "product": "Windows Kernel",
                "layer": "OS & Firmware",
                "cwe_family": "Improper Access Control (CWE-284)",
                "cvss_base": 5.5,
                "cvss_impact": 3.6,
                "epss_score": 0.08,
                "epss_delta_30d": 0.01,
                "is_epss_surge": False,
                "is_kev": True,
                "is_ransomware": False,
                "attack_vector": "Local",
                "attack_complexity": "Low",
                "privileges_required": "Low",
                "disclosure_year": 2024,
                "days_to_exploit": 14.0,
            },
            {
                # EPSS Surge edge case: moderate CVSS, EPSS below 0.30, rapid 30d surge
                "cve_id": "CVE-2025-0003",
                "vendor": "Cisco",
                "product": "IOS XE",
                "layer": "Network Infrastructure",
                "cwe_family": "Authentication Bypass (CWE-287)",
                "cvss_base": 6.4,
                "cvss_impact": 3.9,
                "epss_score": 0.22,
                "epss_delta_30d": 0.18,
                "is_epss_surge": True,
                "is_kev": False,
                "is_ransomware": False,
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "disclosure_year": 2025,
                "days_to_exploit": np.nan,
            },
            {
                # Paper Tiger: high CVSS, negligible EPSS, non-KEV
                "cve_id": "CVE-2025-0004",
                "vendor": "Apache",
                "product": "HTTP Server",
                "layer": "Web & Application",
                "cwe_family": "Memory Corruption (CWE-119)",
                "cvss_base": 8.8,
                "cvss_impact": 5.2,
                "epss_score": 0.002,
                "epss_delta_30d": 0.0,
                "is_epss_surge": False,
                "is_kev": False,
                "is_ransomware": False,
                "attack_vector": "Local",
                "attack_complexity": "High",
                "privileges_required": "High",
                "disclosure_year": 2025,
                "days_to_exploit": np.nan,
            },
            {
                # Dormant Backlog
                "cve_id": "CVE-2025-0005",
                "vendor": "PostgreSQL",
                "product": "PostgreSQL",
                "layer": "Database & Storage",
                "cwe_family": "Cryptographic Flaws (CWE-310)",
                "cvss_base": 4.3,
                "cvss_impact": 2.5,
                "epss_score": 0.001,
                "epss_delta_30d": 0.0,
                "is_epss_surge": False,
                "is_kev": False,
                "is_ransomware": False,
                "attack_vector": "Local",
                "attack_complexity": "High",
                "privileges_required": "High",
                "disclosure_year": 2025,
                "days_to_exploit": np.nan,
            },
        ]
    )


def test_kev_never_drops_into_paper_tiger_or_backlog(synthetic_edge_cases: pd.DataFrame) -> None:
    enriched = enrich_prioritization(synthetic_edge_cases, cvss_cutoff=7.0, epss_cutoff=0.30)
    by_id = enriched.set_index("cve_id")

    # Ransomware perimeter KEV -> P0, Q1
    assert by_id.loc["CVE-2024-0001", "sla_tier"] == SLA_TIER_ORDER[0]
    assert by_id.loc["CVE-2024-0001", "risk_quadrant"] == QUADRANT_LABELS["Q1"]

    # Low-CVSS, low-EPSS local KEV -> MUST be P1 Urgent + Q2 Silent Threat (never Q4!)
    assert by_id.loc["CVE-2024-0002", "sla_tier"] == SLA_TIER_ORDER[1]
    assert by_id.loc["CVE-2024-0002", "risk_quadrant"] == QUADRANT_LABELS["Q2"]
    assert bool(by_id.loc["CVE-2024-0002", "is_silent_threat"]) is True

    # Rising EPSS surge -> P1 Urgent + Q2 Silent Threat
    assert by_id.loc["CVE-2025-0003", "sla_tier"] == SLA_TIER_ORDER[1]
    assert by_id.loc["CVE-2025-0003", "risk_quadrant"] == QUADRANT_LABELS["Q2"]

    # Paper Tiger -> P3 + Q3
    assert by_id.loc["CVE-2025-0004", "sla_tier"] == SLA_TIER_ORDER[3]
    assert by_id.loc["CVE-2025-0004", "risk_quadrant"] == QUADRANT_LABELS["Q3"]

    # Dormant -> P4 + Q4
    assert by_id.loc["CVE-2025-0005", "sla_tier"] == SLA_TIER_ORDER[4]
    assert by_id.loc["CVE-2025-0005", "risk_quadrant"] == QUADRANT_LABELS["Q4"]


def test_blindspot_score_and_days_display(synthetic_edge_cases: pd.DataFrame) -> None:
    enriched = enrich_prioritization(synthetic_edge_cases, cvss_cutoff=7.0, epss_cutoff=0.30)
    by_id = enriched.set_index("cve_id")

    # Low-CVSS KEV has much larger blindspot than High-CVSS KEV or Paper Tiger
    assert by_id.loc["CVE-2024-0002", "blindspot_score"] > by_id.loc["CVE-2024-0001", "blindspot_score"]
    assert by_id.loc["CVE-2025-0004", "blindspot_score"] == 0.0

    # No "NaN" strings anywhere in display column
    assert by_id.loc["CVE-2024-0001", "days_to_exploit_display"] == "2d"
    assert by_id.loc["CVE-2025-0004", "days_to_exploit_display"] == "N/A"
    assert not enriched["days_to_exploit_display"].str.contains("nan", case=False).any()


def test_triage_metrics_respect_dynamic_cutoffs(synthetic_edge_cases: pd.DataFrame) -> None:
    m_strict = calculate_triage_metrics(synthetic_edge_cases, cvss_cutoff=7.0, epss_cutoff=0.30)
    m_loose = calculate_triage_metrics(synthetic_edge_cases, cvss_cutoff=8.0, epss_cutoff=0.10)

    assert m_strict.kev_count == 2
    assert m_strict.ransomware_kev_count == 1
    assert m_strict.cyberlens_kev_capture_pct == 100.0
    assert m_strict.compliance_kev_capture_pct == 50.0  # Compliance misses CVE-2024-0002
    assert m_strict.silent_threats_count == 2
    assert m_strict.p3_paper_tigers_count == 1

    # Changing epss_cutoff must dynamically alter actionable metrics
    assert m_loose.total_count == 5
    assert m_loose.compliance_tickets == 2


def test_rank_action_queue_and_scope_presets(synthetic_edge_cases: pd.DataFrame) -> None:
    enriched = enrich_prioritization(synthetic_edge_cases)
    ranked = rank_action_queue(enriched)
    assert ranked.iloc[0]["cve_id"] == "CVE-2024-0001"
    assert ranked.iloc[-1]["cve_id"] == "CVE-2025-0005"

    ransom = filter_by_scope(enriched, preset="ransomware_kev")
    assert list(ransom["cve_id"]) == ["CVE-2024-0001"]

    silent = filter_by_scope(enriched, preset="silent_threats")
    assert set(silent["cve_id"]) == {"CVE-2024-0002", "CVE-2025-0003"}

    surges = filter_by_scope(enriched, preset="epss_surge")
    assert list(surges["cve_id"]) == ["CVE-2025-0003"]


def test_real_dataset_invariants_and_speed() -> None:
    df = load_dataset()
    t0 = time.perf_counter()
    enriched = enrich_prioritization(df, cvss_cutoff=7.0, epss_cutoff=0.30)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # Vectorized enrichment on full dataset must run well under 100ms
    assert elapsed_ms < 100.0

    kev_tiers = set(enriched.loc[enriched["is_kev"], "sla_tier"].unique())
    assert kev_tiers.issubset({SLA_TIER_ORDER[0], SLA_TIER_ORDER[1]})

    metrics = calculate_triage_metrics(enriched, pre_enriched=True)
    assert metrics.cyberlens_kev_capture_pct == 100.0
