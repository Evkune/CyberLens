from __future__ import annotations

from typing import Iterable, Optional

import numpy as np
import pandas as pd

from cyberlens.config import (
    DEFAULT_CVSS_CUTOFF,
    DEFAULT_EPSS_CUTOFF,
    QUADRANT_LABELS,
    SLA_TARGET_HOURS,
    SLA_TIER_ORDER,
)


def enrich_prioritization(
    df: pd.DataFrame,
    cvss_cutoff: float = DEFAULT_CVSS_CUTOFF,
    epss_cutoff: float = DEFAULT_EPSS_CUTOFF,
) -> pd.DataFrame:
    """Vectorized RBVM enrichment: quadrants, SLA tiers P0-P4, actuarial risk, and blind-spot score."""
    enriched = df.copy()
    if len(enriched) == 0:
        enriched["effective_prob"] = pd.Series(dtype=float)
        enriched["expected_risk"] = pd.Series(dtype=float)
        enriched["risk_quadrant"] = pd.Series(dtype=object)
        enriched["sla_tier"] = pd.Categorical([], categories=SLA_TIER_ORDER, ordered=True)
        enriched["sla_target_hours"] = pd.Series(dtype=int)
        enriched["is_silent_threat"] = pd.Series(dtype=bool)
        enriched["is_actionable"] = pd.Series(dtype=bool)
        enriched["blindspot_score"] = pd.Series(dtype=float)
        enriched["days_to_exploit_display"] = pd.Series(dtype=object)
        return enriched

    cvss = enriched["cvss_base"].to_numpy(dtype=float, na_value=0.0)
    epss = enriched["epss_score"].to_numpy(dtype=float, na_value=0.0)
    is_kev = enriched["is_kev"].to_numpy(dtype=bool, na_value=False)

    is_ransomware = (
        enriched["is_ransomware"].to_numpy(dtype=bool, na_value=False)
        if "is_ransomware" in enriched.columns
        else np.zeros(len(enriched), dtype=bool)
    )
    is_surge = (
        enriched["is_epss_surge"].to_numpy(dtype=bool, na_value=False)
        if "is_epss_surge" in enriched.columns
        else np.zeros(len(enriched), dtype=bool)
    )
    attack_vector = enriched["attack_vector"].astype(str).to_numpy()

    # Confirmed KEV anchors empirical exploitation probability to 1.0
    effective_prob = np.where(is_kev, 1.0, epss)
    expected_risk = np.round(cvss * effective_prob, 4)

    high_cvss = cvss >= cvss_cutoff
    elevated_exploit = is_kev | (epss >= epss_cutoff) | is_surge
    is_silent = (~high_cvss) & elevated_exploit

    quadrant_conds = [
        high_cvss & elevated_exploit,
        (~high_cvss) & elevated_exploit,
        high_cvss & (~elevated_exploit),
    ]
    quadrant_choices = [
        QUADRANT_LABELS["Q1"],
        QUADRANT_LABELS["Q2"],
        QUADRANT_LABELS["Q3"],
    ]
    risk_quadrant = np.select(quadrant_conds, quadrant_choices, default=QUADRANT_LABELS["Q4"])

    # Operational SLA tiers: 100% of KEVs land in P0 or P1 regardless of CVSS cutoff
    is_p0 = is_kev & (is_ransomware | (attack_vector == "Network") | (cvss >= 8.5))
    is_p1 = (~is_p0) & (is_kev | is_silent | is_surge)
    is_p2 = (~is_p0) & (~is_p1) & (epss >= epss_cutoff)
    is_p3 = (~is_p0) & (~is_p1) & (~is_p2) & high_cvss

    sla_conds = [is_p0, is_p1, is_p2, is_p3]
    sla_choices = SLA_TIER_ORDER[:4]
    sla_raw = np.select(sla_conds, sla_choices, default=SLA_TIER_ORDER[4])
    sla_tier = pd.Categorical(sla_raw, categories=SLA_TIER_ORDER, ordered=True)

    sla_hours = np.select(
        sla_conds,
        [SLA_TARGET_HOURS[tier] for tier in sla_choices],
        default=SLA_TARGET_HOURS[SLA_TIER_ORDER[4]],
    )

    # Discrepancy score isolating low-CVSS / high-real-world-risk blind spots
    gap = np.clip(effective_prob - (cvss / 10.0), 0.0, 1.0)
    boost = np.where(is_kev & (~high_cvss), 0.25, 0.0) + np.where(is_surge & (~high_cvss), 0.15, 0.0)
    blindspot_score = np.round(np.clip(gap + boost, 0.0, 1.0), 4)

    is_actionable = is_p0 | is_p1 | is_p2

    if "days_to_exploit" in enriched.columns:
        days_series = pd.to_numeric(enriched["days_to_exploit"], errors="coerce")
        valid_days = days_series.notna()
        days_display = np.full(len(enriched), "N/A", dtype=object)
        if valid_days.any():
            days_display[valid_days.to_numpy()] = (
                days_series[valid_days].round().astype(int).astype(str) + "d"
            ).to_numpy()
    else:
        days_display = np.full(len(enriched), "N/A", dtype=object)

    enriched["effective_prob"] = effective_prob
    enriched["expected_risk"] = expected_risk
    enriched["risk_quadrant"] = risk_quadrant
    enriched["sla_tier"] = sla_tier
    enriched["sla_target_hours"] = sla_hours.astype(int)
    enriched["is_silent_threat"] = is_silent
    enriched["is_actionable"] = is_actionable
    enriched["blindspot_score"] = blindspot_score
    enriched["days_to_exploit_display"] = days_display
    return enriched


def filter_by_scope(
    df: pd.DataFrame,
    vendors: Optional[Iterable[str]] = None,
    layers: Optional[Iterable[str]] = None,
    cwe_families: Optional[Iterable[str]] = None,
    years: Optional[Iterable[int]] = None,
    cve_ids: Optional[Iterable[str]] = None,
    preset: str = "all",
) -> pd.DataFrame:
    if len(df) == 0:
        return df.copy()

    mask = np.ones(len(df), dtype=bool)

    if vendors is not None:
        vendor_set = set(vendors)
        if vendor_set:
            mask &= df["vendor"].isin(vendor_set).to_numpy()
        else:
            return df.iloc[0:0].copy()

    if layers is not None:
        layer_set = set(layers)
        if layer_set:
            mask &= df["layer"].isin(layer_set).to_numpy()

    if cwe_families is not None:
        cwe_set = set(cwe_families)
        if cwe_set:
            mask &= df["cwe_family"].isin(cwe_set).to_numpy()

    if years is not None and "disclosure_year" in df.columns:
        year_set = set(years)
        if year_set:
            mask &= df["disclosure_year"].isin(year_set).to_numpy()

    if cve_ids is not None:
        cve_set = set(cve_ids)
        if cve_set:
            mask &= df["cve_id"].isin(cve_set).to_numpy()

    if preset == "emergency_24h" and "sla_tier" in df.columns:
        mask &= (df["sla_tier"] == SLA_TIER_ORDER[0]).to_numpy()
    elif preset == "silent_threats" and "is_silent_threat" in df.columns:
        mask &= df["is_silent_threat"].to_numpy(dtype=bool)
    elif preset == "ransomware_kev" and "is_ransomware" in df.columns:
        mask &= df["is_ransomware"].to_numpy(dtype=bool)
    elif preset == "epss_surge" and "is_epss_surge" in df.columns:
        mask &= df["is_epss_surge"].to_numpy(dtype=bool)
    elif preset == "kev_only":
        mask &= df["is_kev"].to_numpy(dtype=bool)

    return df.loc[mask].copy()


def rank_action_queue(df: pd.DataFrame) -> pd.DataFrame:
    if len(df) == 0:
        return df.copy()
    work = df if "sla_tier" in df.columns else enrich_prioritization(df)
    sort_cols = ["sla_tier", "is_ransomware", "is_kev", "effective_prob", "blindspot_score", "cvss_base"]
    existing_cols = [c for c in sort_cols if c in work.columns]
    ascending = [True if c == "sla_tier" else False for c in existing_cols]
    return work.sort_values(existing_cols, ascending=ascending, kind="mergesort").reset_index(drop=True)
