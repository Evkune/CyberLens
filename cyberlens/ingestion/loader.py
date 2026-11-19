from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd

from cyberlens.config import (
    ATTACK_COMPLEXITY_ORDER,
    ATTACK_VECTOR_ORDER,
    CSV_FILENAME,
    DEFAULT_DATA_DIR,
    LAYER_ORDER,
    METADATA_FILENAME,
    PARQUET_FILENAME,
    PRIVILEGES_REQUIRED_ORDER,
)


def _apply_schema_types(df: pd.DataFrame) -> pd.DataFrame:
    typed = df.copy()

    # Enforce Munzner Ordered -> Ordinal Sequential typing on security prerequisites
    if "attack_vector" in typed.columns:
        typed["attack_vector"] = pd.Categorical(
            typed["attack_vector"], categories=ATTACK_VECTOR_ORDER, ordered=True
        )
    if "privileges_required" in typed.columns:
        typed["privileges_required"] = pd.Categorical(
            typed["privileges_required"], categories=PRIVILEGES_REQUIRED_ORDER, ordered=True
        )
    if "attack_complexity" in typed.columns:
        typed["attack_complexity"] = pd.Categorical(
            typed["attack_complexity"], categories=ATTACK_COMPLEXITY_ORDER, ordered=True
        )
    if "layer" in typed.columns:
        extra_layers = [v for v in typed["layer"].dropna().unique() if v not in LAYER_ORDER]
        typed["layer"] = pd.Categorical(
            typed["layer"], categories=LAYER_ORDER + extra_layers, ordered=False
        )

    for col in ("vendor", "cwe_family"):
        if col in typed.columns:
            typed[col] = typed[col].astype("category")

    for bool_col in ("is_kev", "is_ransomware", "is_epss_surge"):
        if bool_col in typed.columns:
            typed[bool_col] = typed[bool_col].fillna(False).astype(bool)

    for num_col in (
        "cvss_base",
        "cvss_impact",
        "cvss_exploitability",
        "epss_score",
        "epss_percentile",
        "epss_score_30d",
        "epss_delta_30d",
        "epss_velocity_ratio",
        "days_to_exploit",
    ):
        if num_col in typed.columns:
            typed[num_col] = pd.to_numeric(typed[num_col], errors="coerce")

    if "disclosure_date" in typed.columns:
        typed["disclosure_year"] = (
            pd.to_datetime(typed["disclosure_date"], errors="coerce").dt.year.fillna(2024).astype(int)
        )

    return typed


@lru_cache(maxsize=4)
def _load_cached(resolved_path: str) -> pd.DataFrame:
    path = Path(resolved_path)
    if path.suffix == ".parquet":
        raw = pd.read_parquet(path)
    else:
        raw = pd.read_csv(path)
    return _apply_schema_types(raw)


def load_dataset(data_path: Optional[str | Path] = None) -> pd.DataFrame:
    if data_path is not None:
        target = Path(data_path).resolve()
    else:
        parquet_candidate = DEFAULT_DATA_DIR / PARQUET_FILENAME
        csv_candidate = DEFAULT_DATA_DIR / CSV_FILENAME
        if parquet_candidate.exists():
            target = parquet_candidate.resolve()
        elif csv_candidate.exists():
            target = csv_candidate.resolve()
        else:
            from cyberlens.ingestion.etl_pipeline import run_etl_pipeline

            df, _ = run_etl_pipeline(output_dir=DEFAULT_DATA_DIR)
            return _apply_schema_types(df)

    return _load_cached(str(target)).copy()


def load_dataset_metadata(data_dir: Optional[str | Path] = None) -> Dict[str, Any]:
    target_dir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    meta_path = target_dir / METADATA_FILENAME
    if not meta_path.exists():
        return {"source_mode": "unknown"}
    return json.loads(meta_path.read_text(encoding="utf-8"))


def clear_dataset_cache() -> None:
    _load_cached.cache_clear()
