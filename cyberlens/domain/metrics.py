from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np
import pandas as pd

from cyberlens.config import DEFAULT_CVSS_CUTOFF, DEFAULT_EPSS_CUTOFF, SLA_TIER_ORDER
from cyberlens.domain.prioritization import enrich_prioritization


@dataclass(frozen=True)
class TriageMetrics:
    total_count: int
    compliance_tickets: int
    actionable_tickets: int
    urgent_24_72h_count: int
    p0_emergency_count: int
    p1_urgent_count: int
    p2_elevated_count: int
    p3_paper_tigers_count: int
    p4_backlog_count: int
    kev_count: int
    ransomware_kev_count: int
    silent_threats_count: int
    epss_surge_count: int
    alert_reduction_pct: float
    urgent_reduction_pct: float
    compliance_kev_capture_pct: float
    cyberlens_kev_capture_pct: float
    median_cvss: float
    median_epss: float
    median_days_to_exploit: Optional[float]


def calculate_triage_metrics(
    df: pd.DataFrame,
    cvss_cutoff: float = DEFAULT_CVSS_CUTOFF,
    epss_cutoff: float = DEFAULT_EPSS_CUTOFF,
    pre_enriched: bool = False,
) -> TriageMetrics:
    total = len(df)
    if total == 0:
        return TriageMetrics(
            total_count=0,
            compliance_tickets=0,
            actionable_tickets=0,
            urgent_24_72h_count=0,
            p0_emergency_count=0,
            p1_urgent_count=0,
            p2_elevated_count=0,
            p3_paper_tigers_count=0,
            p4_backlog_count=0,
            kev_count=0,
            ransomware_kev_count=0,
            silent_threats_count=0,
            epss_surge_count=0,
            alert_reduction_pct=0.0,
            urgent_reduction_pct=0.0,
            compliance_kev_capture_pct=0.0,
            cyberlens_kev_capture_pct=0.0,
            median_cvss=0.0,
            median_epss=0.0,
            median_days_to_exploit=None,
        )

    work = df if (pre_enriched and "sla_tier" in df.columns) else enrich_prioritization(
        df, cvss_cutoff=cvss_cutoff, epss_cutoff=epss_cutoff
    )

    cvss = work["cvss_base"].to_numpy(dtype=float, na_value=0.0)
    epss = work["epss_score"].to_numpy(dtype=float, na_value=0.0)
    is_kev = work["is_kev"].to_numpy(dtype=bool, na_value=False)
    is_ransomware = (
        work["is_ransomware"].to_numpy(dtype=bool, na_value=False)
        if "is_ransomware" in work.columns
        else np.zeros(total, dtype=bool)
    )
    is_surge = (
        work["is_epss_surge"].to_numpy(dtype=bool, na_value=False)
        if "is_epss_surge" in work.columns
        else np.zeros(total, dtype=bool)
    )

    tier_counts = work["sla_tier"].value_counts()
    p0 = int(tier_counts.get(SLA_TIER_ORDER[0], 0))
    p1 = int(tier_counts.get(SLA_TIER_ORDER[1], 0))
    p2 = int(tier_counts.get(SLA_TIER_ORDER[2], 0))
    p3 = int(tier_counts.get(SLA_TIER_ORDER[3], 0))
    p4 = int(tier_counts.get(SLA_TIER_ORDER[4], 0))

    compliance_mask = cvss >= cvss_cutoff
    compliance_tickets = int(compliance_mask.sum())
    actionable_tickets = p0 + p1 + p2
    urgent_24_72h = p0 + p1

    kev_count = int(is_kev.sum())
    ransomware_count = int((is_kev & is_ransomware).sum())
    silent_count = int(work["is_silent_threat"].sum())
    surge_count = int(is_surge.sum())

    if compliance_tickets > 0:
        alert_reduction = max(0.0, (1.0 - (actionable_tickets / compliance_tickets)) * 100.0)
        urgent_reduction = max(0.0, (1.0 - (urgent_24_72h / compliance_tickets)) * 100.0)
    else:
        alert_reduction = 0.0
        urgent_reduction = 0.0

    if kev_count > 0:
        comp_kev_capture = float((is_kev & compliance_mask).sum() / kev_count * 100.0)
        cl_kev_capture = float(
            (is_kev & work["is_actionable"].to_numpy(dtype=bool)).sum() / kev_count * 100.0
        )
    else:
        comp_kev_capture = 100.0
        cl_kev_capture = 100.0

    median_days: Optional[float] = None
    if "days_to_exploit" in work.columns:
        valid_days = pd.to_numeric(work.loc[is_kev, "days_to_exploit"], errors="coerce").dropna()
        if len(valid_days) > 0:
            median_days = round(float(valid_days.median()), 1)

    return TriageMetrics(
        total_count=total,
        compliance_tickets=compliance_tickets,
        actionable_tickets=actionable_tickets,
        urgent_24_72h_count=urgent_24_72h,
        p0_emergency_count=p0,
        p1_urgent_count=p1,
        p2_elevated_count=p2,
        p3_paper_tigers_count=p3,
        p4_backlog_count=p4,
        kev_count=kev_count,
        ransomware_kev_count=ransomware_count,
        silent_threats_count=silent_count,
        epss_surge_count=surge_count,
        alert_reduction_pct=round(alert_reduction, 1),
        urgent_reduction_pct=round(urgent_reduction, 1),
        compliance_kev_capture_pct=round(comp_kev_capture, 1),
        cyberlens_kev_capture_pct=round(cl_kev_capture, 1),
        median_cvss=round(float(np.median(cvss)), 1),
        median_epss=round(float(np.median(epss)), 4),
        median_days_to_exploit=median_days,
    )
