import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd
import numpy as np

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

def load_dataset(data_path: Optional[str] = None) -> pd.DataFrame:
    if data_path:
        target = Path(data_path)
    else:
        parquet_candidate = DEFAULT_DATA_DIR / "cve_unified_dataset.parquet"
        csv_candidate = DEFAULT_DATA_DIR / "cve_unified_dataset.csv"
        if parquet_candidate.exists():
            target = parquet_candidate
        elif csv_candidate.exists():
            target = csv_candidate
        else:
            from cyberlens.etl_pipeline import run_etl_pipeline
            return run_etl_pipeline(output_dir=str(DEFAULT_DATA_DIR))
            
    if target.suffix == ".parquet":
        return pd.read_parquet(target)
    return pd.read_csv(target)

def filter_by_enterprise_stack(df: pd.DataFrame, selected_vendors: Optional[List[str]] = None) -> pd.DataFrame:
    if not selected_vendors:
        return df
    return df[df["vendor"].isin(selected_vendors)].copy()

def filter_by_layers(df: pd.DataFrame, selected_layers: Optional[List[str]] = None) -> pd.DataFrame:
    if not selected_layers:
        return df
    return df[df["layer"].isin(selected_layers)].copy()

def classify_risk_quadrants(
    df: pd.DataFrame, 
    cvss_threshold: float = 7.0, 
    epss_threshold: float = 0.30
) -> pd.DataFrame:
    classified = df.copy()
    
    conditions = [
        (classified["cvss_base"] >= cvss_threshold) & (classified["epss_score"] >= epss_threshold),
        (classified["cvss_base"] < cvss_threshold) & (classified["epss_score"] >= epss_threshold),
        (classified["cvss_base"] >= cvss_threshold) & (classified["epss_score"] < epss_threshold),
        (classified["cvss_base"] < cvss_threshold) & (classified["epss_score"] < epss_threshold)
    ]
    
    labels = [
        "Q1: Red Alert (High Severity + Weaponized)",
        "Q2: Hidden Threat (Moderate CVSS + High Exploit)",
        "Q3: Paper Tiger (High CVSS + Low Exploit)",
        "Q4: Dormant Backlog (Low Priority)"
    ]
    
    classified["risk_quadrant"] = np.select(conditions, labels, default="Q4: Dormant Backlog (Low Priority)")
    return classified

def calculate_kpis(df: pd.DataFrame) -> Dict[str, Any]:
    total = len(df)
    if total == 0:
        return {
            "total_count": 0,
            "kev_count": 0,
            "high_epss_count": 0,
            "median_cvss": 0.0,
            "median_epss": 0.0
        }
        
    kev_count = int(df["is_kev"].sum())
    high_epss_count = int((df["epss_score"] >= 0.30).sum())
    median_cvss = round(float(df["cvss_base"].median()), 1)
    median_epss = round(float(df["epss_score"].median()), 4)
    
    return {
        "total_count": total,
        "kev_count": kev_count,
        "high_epss_count": high_epss_count,
        "median_cvss": median_cvss,
        "median_epss": median_epss
    }
