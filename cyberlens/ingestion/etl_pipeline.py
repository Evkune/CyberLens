from __future__ import annotations

import json
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from cyberlens.config import (
    CSV_FILENAME,
    CWE_FAMILY_RULES,
    CWE_ID_TO_FAMILY,
    DEFAULT_CWE_FAMILY,
    DEFAULT_DATA_DIR,
    ENTERPRISE_VENDORS,
    EPSS_SURGE_DELTA,
    EPSS_SURGE_FLOOR,
    EPSS_SURGE_RATIO,
    METADATA_FILENAME,
    PARQUET_FILENAME,
    REQUIRED_SCHEMA_COLUMNS,
)
from cyberlens.ingestion.feeds_client import (
    FeedConfig,
    fetch_cisa_kev,
    fetch_epss_snapshot,
    fetch_nvd_kev_cves,
    fetch_nvd_published_window,
)

# Priority order for matching raw CPE/vendor tokens to canonical enterprise vendors
_ALIAS_LOOKUP: List[Tuple[str, str, str]] = [
    (alias.lower(), vendor, str(meta["layer"]))
    for vendor, meta in ENTERPRISE_VENDORS.items()
    for alias in meta["aliases"]  # type: ignore[index]
]
# Match longer aliases first to avoid partial collisions
_ALIAS_LOOKUP.sort(key=lambda item: len(item[0]), reverse=True)


def map_vendor_and_layer(
    raw_vendor: str,
    raw_product: str = "",
    description: str = "",
) -> Optional[Tuple[str, str]]:
    haystack = f"{raw_vendor} {raw_product}".lower()
    for alias, canonical, layer in _ALIAS_LOOKUP:
        if alias in haystack:
            return canonical, layer

    # Secondary check on description only for unambiguous flagship vendor names
    desc_lower = description.lower()[:280]
    for canonical, meta in ENTERPRISE_VENDORS.items():
        if canonical.lower() in desc_lower:
            return canonical, str(meta["layer"])

    return None


def map_cwe_family(cwe_ids: Iterable[str]) -> Tuple[str, str]:
    for raw_id in cwe_ids:
        clean = str(raw_id).strip().upper()
        if clean in CWE_ID_TO_FAMILY:
            return clean, CWE_ID_TO_FAMILY[clean]
    first_valid = next(
        (str(c).strip().upper() for c in cwe_ids if str(c).strip().upper().startswith("CWE-")),
        "CWE-20",
    )
    return first_valid, DEFAULT_CWE_FAMILY


def _extract_cpe_vendor_product(cve_obj: Dict[str, Any]) -> Tuple[str, str]:
    configs = cve_obj.get("configurations") or []
    for cfg in configs:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                    vendor = parts[3].replace("_", " ").strip()
                    product = parts[4].replace("_", " ").strip()
                    if vendor and vendor != "*":
                        return vendor, product.title() if product != "*" else "Core Platform"
    return "", ""


def _extract_cvss_v3(cve_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    metrics = cve_obj.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss_data = primary.get("cvssData") or {}
        base_score = cvss_data.get("baseScore")
        if base_score is None:
            continue

        av_raw = str(cvss_data.get("attackVector", "NETWORK")).upper()
        av_map = {
            "NETWORK": "Network",
            "ADJACENT_NETWORK": "Adjacent",
            "ADJACENT": "Adjacent",
            "LOCAL": "Local",
            "PHYSICAL": "Physical",
        }
        ac_raw = str(cvss_data.get("attackComplexity", "LOW")).title()
        pr_raw = str(cvss_data.get("privilegesRequired", "NONE")).title()
        ui_raw = str(cvss_data.get("userInteraction", "NONE")).title()

        impact_sub = primary.get("impactScore")
        exploit_sub = primary.get("exploitabilityScore")
        base_f = float(base_score)
        return {
            "cvss_base": round(base_f, 1),
            "cvss_impact": round(float(impact_sub), 1) if impact_sub is not None else round(min(base_f * 0.58, 6.0), 1),
            "cvss_exploitability": round(float(exploit_sub), 1) if exploit_sub is not None else round(min(base_f * 0.39, 3.9), 1),
            "attack_vector": av_map.get(av_raw, "Network"),
            "attack_complexity": ac_raw if ac_raw in ("Low", "High") else "Low",
            "privileges_required": pr_raw if pr_raw in ("None", "Low", "High") else "None",
            "user_interaction": ui_raw if ui_raw in ("None", "Required") else "None",
        }
    return None


def _extract_cwes(cve_obj: Dict[str, Any]) -> List[str]:
    cwes: List[str] = []
    for weakness in cve_obj.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            val = str(desc.get("value", ""))
            if val.startswith("CWE-"):
                cwes.append(val)
    return cwes


def _extract_description(cve_obj: Dict[str, Any]) -> str:
    for item in cve_obj.get("descriptions") or []:
        if item.get("lang") == "en":
            return str(item.get("value", "")).strip()
    return ""


def _parse_iso_date(raw_ts: Optional[str]) -> Optional[date]:
    if not raw_ts:
        return None
    try:
        return date.fromisoformat(str(raw_ts)[:10])
    except ValueError:
        return None


def _build_record(
    vuln_wrapper: Dict[str, Any],
    kev_map: Dict[str, Dict[str, Any]],
    epss_now: Dict[str, Tuple[float, float]],
    epss_prev: Dict[str, Tuple[float, float]],
) -> Optional[Dict[str, Any]]:
    cve_obj = vuln_wrapper.get("cve") or {}
    cve_id = cve_obj.get("id")
    if not cve_id or cve_obj.get("vulnStatus") == "Rejected":
        return None

    cvss = _extract_cvss_v3(cve_obj)
    if cvss is None:
        return None

    description = _extract_description(cve_obj)
    kev_info = kev_map.get(cve_id)
    cpe_vendor, cpe_product = _extract_cpe_vendor_product(cve_obj)

    raw_vendor = (kev_info["vendor_project"] if kev_info else "") or cpe_vendor
    raw_product = (kev_info["product"] if kev_info else "") or cpe_product

    mapped = map_vendor_and_layer(raw_vendor, raw_product, description)
    if mapped is None:
        return None
    vendor, layer = mapped
    product = raw_product.strip() if raw_product.strip() else f"{vendor} Platform"

    cwes = _extract_cwes(cve_obj)
    if kev_info and kev_info.get("cwes"):
        cwes = list(kev_info["cwes"]) + cwes
    cwe_id, cwe_family = map_cwe_family(cwes)

    pub_date = _parse_iso_date(cve_obj.get("published"))
    if pub_date is None:
        return None

    epss_score, epss_pct = epss_now.get(cve_id, (0.001, 0.05))
    epss_30d, _ = epss_prev.get(cve_id, (epss_score, epss_pct))
    epss_delta = round(float(epss_score - epss_30d), 5)
    velocity_ratio = round(float(epss_score / max(epss_30d, 0.005)), 2)
    is_surge = bool(
        (epss_delta >= EPSS_SURGE_DELTA)
        or (epss_score >= EPSS_SURGE_FLOOR and velocity_ratio >= EPSS_SURGE_RATIO)
    )

    is_kev = kev_info is not None
    kev_date_added = kev_info["date_added"] if kev_info else None
    kev_due_date = kev_info["due_date"] if kev_info else None
    kev_dt = _parse_iso_date(kev_date_added)
    days_to_exploit: Optional[float] = None
    if is_kev and kev_dt is not None:
        days_to_exploit = float(max(0, (kev_dt - pub_date).days))

    return {
        "cve_id": cve_id,
        "vendor": vendor,
        "product": product[:80],
        "layer": layer,
        "cwe_id": cwe_id,
        "cwe_family": cwe_family,
        "cvss_base": cvss["cvss_base"],
        "cvss_impact": cvss["cvss_impact"],
        "cvss_exploitability": cvss["cvss_exploitability"],
        "epss_score": round(float(np.clip(epss_score, 0.0, 1.0)), 5),
        "epss_percentile": round(float(np.clip(epss_pct, 0.0, 1.0)), 5),
        "epss_score_30d": round(float(np.clip(epss_30d, 0.0, 1.0)), 5),
        "epss_delta_30d": epss_delta,
        "epss_velocity_ratio": velocity_ratio,
        "is_epss_surge": is_surge,
        "is_kev": is_kev,
        "is_ransomware": bool(kev_info["is_ransomware"]) if kev_info else False,
        "attack_vector": cvss["attack_vector"],
        "attack_complexity": cvss["attack_complexity"],
        "privileges_required": cvss["privileges_required"],
        "user_interaction": cvss["user_interaction"],
        "disclosure_date": pub_date.isoformat(),
        "kev_date_added": kev_date_added,
        "kev_due_date": kev_due_date,
        "days_to_exploit": days_to_exploit,
        "kev_required_action": (kev_info["required_action"][:220] if kev_info else ""),
        "description": description[:360],
    }


def _build_live_dataset(
    config: FeedConfig,
    target_non_kev: int = 4200,
    min_kev_year: int = 2021,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    catalog_version, kev_map = fetch_cisa_kev(config)
    epss_date_now, epss_now = fetch_epss_snapshot(config, target_date=None)
    epss_date_prev, epss_prev = fetch_epss_snapshot(
        config, target_date=epss_date_now - timedelta(days=30)
    )

    records_by_cve: Dict[str, Dict[str, Any]] = {}

    # 1. Fetch all NVD records linked to CISA KEV (1 request)
    nvd_kev_raw = fetch_nvd_kev_cves(config)
    for wrapper in nvd_kev_raw:
        rec = _build_record(wrapper, kev_map, epss_now, epss_prev)
        if rec is None:
            continue
        pub_year = int(rec["disclosure_date"][:4])
        if pub_year >= min_kev_year:
            records_by_cve[rec["cve_id"]] = rec

    kev_retained = len(records_by_cve)

    # 2. Fetch stratified 115-day NVD windows backwards from latest EPSS date
    anchor_dt = datetime(epss_date_now.year, epss_date_now.month, epss_date_now.day)
    non_kev_count = 0
    windows_fetched = 0
    max_windows = 8

    for step in range(max_windows):
        if non_kev_count >= target_non_kev:
            break
        end_dt = anchor_dt - timedelta(days=step * 115)
        start_dt = end_dt - timedelta(days=114)
        time.sleep(config.nvd_delay_seconds)
        window_vulns = fetch_nvd_published_window(start_dt, end_dt, config, results_per_page=2000)
        windows_fetched += 1

        for wrapper in window_vulns:
            cve_id = (wrapper.get("cve") or {}).get("id")
            if not cve_id or cve_id in records_by_cve:
                continue
            rec = _build_record(wrapper, kev_map, epss_now, epss_prev)
            if rec is None:
                continue
            records_by_cve[cve_id] = rec
            if not rec["is_kev"]:
                non_kev_count += 1

    # Ensure landmark CVE-2024-38063 is present if missed by window boundaries
    if "CVE-2024-38063" not in records_by_cve:
        try:
            time.sleep(config.nvd_delay_seconds)
            lm_vulns = fetch_nvd_published_window(
                datetime(2024, 8, 13), datetime(2024, 8, 14), config, results_per_page=200
            )
            for wrapper in lm_vulns:
                rec = _build_record(wrapper, kev_map, epss_now, epss_prev)
                if rec and rec["cve_id"] not in records_by_cve:
                    records_by_cve[rec["cve_id"]] = rec
        except Exception:
            pass

    df = pd.DataFrame(list(records_by_cve.values()))
    df = df[REQUIRED_SCHEMA_COLUMNS].sort_values(
        ["is_kev", "epss_score", "cvss_base"], ascending=[False, False, False]
    ).reset_index(drop=True)

    metadata: Dict[str, Any] = {
        "source_mode": "live_feeds",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cisa_kev_catalog_version": catalog_version,
        "cisa_kev_total_catalog": len(kev_map),
        "epss_date_current": epss_date_now.isoformat(),
        "epss_date_baseline_30d": epss_date_prev.isoformat(),
        "nvd_windows_fetched": windows_fetched,
        "kev_records_in_dataset": int(df["is_kev"].sum()),
        "ransomware_kev_records": int(df["is_ransomware"].sum()),
        "epss_surge_records": int(df["is_epss_surge"].sum()),
        "total_records": int(len(df)),
        "kev_retained_initial": kev_retained,
        "vendors": sorted(df["vendor"].unique().tolist()),
    }
    return df, metadata


def generate_offline_fallback_dataset(n_samples: int = 4500, seed: int = 2026) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Deterministic fallback reproducing the exact live schema for airgapped runs."""
    rng = np.random.default_rng(seed)
    vendors = list(ENTERPRISE_VENDORS.keys())
    cwe_families = list(CWE_FAMILY_RULES.keys())
    probs = np.array([0.20, 0.16, 0.08, 0.08, 0.11, 0.08, 0.05, 0.05, 0.07, 0.03, 0.03, 0.04, 0.02])
    probs = probs / probs.sum()

    selected_vendors = rng.choice(vendors, size=n_samples, p=probs)
    base_date = date(2023, 1, 1)
    records: List[Dict[str, Any]] = []

    for i, vendor in enumerate(selected_vendors):
        layer = str(ENTERPRISE_VENDORS[vendor]["layer"])
        cwe_family = str(rng.choice(cwe_families))
        cwe_id = CWE_FAMILY_RULES[cwe_family][0]

        cvss_base = float(np.clip(np.round(rng.normal(7.1, 1.6), 1), 2.0, 10.0))
        cvss_impact = float(np.clip(np.round(cvss_base * rng.uniform(0.45, 0.62), 1), 1.0, 6.0))
        cvss_exploit = float(np.clip(np.round(cvss_base - cvss_impact, 1), 0.5, 3.9))

        raw_epss = rng.lognormal(mean=-4.2, sigma=1.7)
        epss_score = float(np.clip(np.round(raw_epss / (raw_epss + 1.5), 5), 0.0004, 0.985))
        if cvss_base >= 8.5 and rng.random() < 0.18:
            epss_score = float(np.clip(epss_score + rng.uniform(0.30, 0.65), 0.01, 0.99))

        delta_noise = float(rng.normal(0.0, 0.015))
        if rng.random() < 0.035:
            delta_noise = float(rng.uniform(0.11, 0.45))
        epss_30d = float(np.clip(np.round(epss_score - delta_noise, 5), 0.0002, 0.99))
        epss_delta = round(epss_score - epss_30d, 5)
        vel_ratio = round(epss_score / max(epss_30d, 0.005), 2)
        is_surge = bool((epss_delta >= EPSS_SURGE_DELTA) or (epss_score >= EPSS_SURGE_FLOOR and vel_ratio >= EPSS_SURGE_RATIO))

        kev_prob = 0.015 + 0.45 * (epss_score ** 1.3) + (0.03 if cvss_base >= 9.0 else 0.0)
        is_kev = bool(rng.random() < np.clip(kev_prob, 0.01, 0.85))
        is_ransomware = bool(is_kev and rng.random() < 0.30)

        av = str(rng.choice(["Network", "Adjacent", "Local", "Physical"], p=[0.68, 0.08, 0.22, 0.02]))
        ac = str(rng.choice(["Low", "High"], p=[0.82, 0.18]))
        pr = str(rng.choice(["None", "Low", "High"], p=[0.55, 0.30, 0.15]))
        ui = str(rng.choice(["None", "Required"], p=[0.65, 0.35]))

        pub_date = base_date + timedelta(days=int(rng.integers(0, 1200)))
        days_lag: Optional[float] = None
        kev_added: Optional[str] = None
        kev_due: Optional[str] = None
        if is_kev:
            scale = 9.0 if layer == "Network Infrastructure" else 24.0
            lag = int(np.clip(np.round(rng.exponential(scale)), 0, 180))
            days_lag = float(lag)
            kev_dt = pub_date + timedelta(days=lag)
            kev_added = kev_dt.isoformat()
            kev_due = (kev_dt + timedelta(days=21)).isoformat()

        records.append(
            {
                "cve_id": f"CVE-{pub_date.year}-{10000 + i}",
                "vendor": vendor,
                "product": f"{vendor} Core",
                "layer": layer,
                "cwe_id": cwe_id,
                "cwe_family": cwe_family,
                "cvss_base": cvss_base,
                "cvss_impact": cvss_impact,
                "cvss_exploitability": cvss_exploit,
                "epss_score": epss_score,
                "epss_percentile": round(float(np.clip(epss_score ** 0.35, 0.01, 0.999)), 5),
                "epss_score_30d": epss_30d,
                "epss_delta_30d": epss_delta,
                "epss_velocity_ratio": vel_ratio,
                "is_epss_surge": is_surge,
                "is_kev": is_kev,
                "is_ransomware": is_ransomware,
                "attack_vector": av,
                "attack_complexity": ac,
                "privileges_required": pr,
                "user_interaction": ui,
                "disclosure_date": pub_date.isoformat(),
                "kev_date_added": kev_added,
                "kev_due_date": kev_due,
                "days_to_exploit": days_lag,
                "kev_required_action": "Apply mitigations per vendor instructions." if is_kev else "",
                "description": f"Offline fallback record for {vendor} ({cwe_family}).",
            }
        )

    df = pd.DataFrame(records)[REQUIRED_SCHEMA_COLUMNS]
    metadata: Dict[str, Any] = {
        "source_mode": "offline_fallback",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_records": int(len(df)),
        "kev_records_in_dataset": int(df["is_kev"].sum()),
        "ransomware_kev_records": int(df["is_ransomware"].sum()),
        "epss_surge_records": int(df["is_epss_surge"].sum()),
        "vendors": sorted(df["vendor"].unique().tolist()),
    }
    return df, metadata


def run_etl_pipeline(
    output_dir: Optional[str | Path] = None,
    prefer_live: bool = True,
    target_non_kev: int = 4200,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    target_dir = Path(output_dir) if output_dir else DEFAULT_DATA_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    df: pd.DataFrame
    metadata: Dict[str, Any]

    if prefer_live:
        try:
            config = FeedConfig.from_env()
            df, metadata = _build_live_dataset(config, target_non_kev=target_non_kev)
        except Exception as exc:
            print(f"[CyberLens ETL] Live fetch failed ({exc}); falling back to deterministic offline dataset.")
            df, metadata = generate_offline_fallback_dataset()
            metadata["fallback_reason"] = str(exc)
    else:
        df, metadata = generate_offline_fallback_dataset()

    parquet_path = target_dir / PARQUET_FILENAME
    csv_path = target_dir / CSV_FILENAME
    meta_path = target_dir / METADATA_FILENAME

    df.to_parquet(parquet_path, index=False)
    df.to_csv(csv_path, index=False)
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(
        f"[CyberLens ETL] {metadata['source_mode']} completed: "
        f"{len(df):,} CVEs ({metadata['kev_records_in_dataset']:,} KEV, "
        f"{metadata['ransomware_kev_records']:,} Ransomware, "
        f"{metadata['epss_surge_records']:,} EPSS Surges) -> {parquet_path}"
    )
    return df, metadata


if __name__ == "__main__":
    run_etl_pipeline()
