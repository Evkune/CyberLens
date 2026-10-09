import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import numpy as np
import pandas as pd

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

VENDORS_STACK = {
    "Microsoft": {
        "layer": "OS & Firmware",
        "products": ["Windows Server", "Windows 11", "Exchange Server", "Active Directory"],
        "cwe_weights": [0.40, 0.15, 0.20, 0.05, 0.15, 0.05],
        "exploit_decay_scale": 18.0
    },
    "Linux": {
        "layer": "OS & Firmware",
        "products": ["Kernel", "glibc", "systemd", "eBPF Core"],
        "cwe_weights": [0.55, 0.10, 0.15, 0.05, 0.10, 0.05],
        "exploit_decay_scale": 45.0
    },
    "Cisco": {
        "layer": "Network Infrastructure",
        "products": ["IOS XE", "ASA Software", "Nexus Switches", "AnyConnect VPN"],
        "cwe_weights": [0.30, 0.20, 0.25, 0.10, 0.10, 0.05],
        "exploit_decay_scale": 9.0
    },
    "Fortinet": {
        "layer": "Network Infrastructure",
        "products": ["FortiOS", "FortiGate", "FortiAnalyzer", "FortiClient"],
        "cwe_weights": [0.25, 0.25, 0.30, 0.05, 0.10, 0.05],
        "exploit_decay_scale": 11.0
    },
    "Apache": {
        "layer": "Web & Application",
        "products": ["HTTP Server", "Struts", "Tomcat", "Log4j"],
        "cwe_weights": [0.10, 0.45, 0.15, 0.05, 0.15, 0.10],
        "exploit_decay_scale": 14.0
    },
    "Nginx": {
        "layer": "Web & Application",
        "products": ["Nginx Core", "Nginx Plus", "Unit App Server"],
        "cwe_weights": [0.35, 0.20, 0.20, 0.10, 0.10, 0.05],
        "exploit_decay_scale": 28.0
    },
    "PostgreSQL": {
        "layer": "Database & Storage",
        "products": ["PostgreSQL Server", "pgAdmin", "libpq"],
        "cwe_weights": [0.20, 0.40, 0.15, 0.10, 0.10, 0.05],
        "exploit_decay_scale": 60.0
    },
    "VMware": {
        "layer": "OS & Firmware",
        "products": ["ESXi", "vCenter Server", "Workstation Pro"],
        "cwe_weights": [0.35, 0.15, 0.25, 0.05, 0.15, 0.05],
        "exploit_decay_scale": 16.0
    }
}

CWE_FAMILIES = [
    "Memory Corruption (CWE-119)",
    "Injection (CWE-89/78)",
    "Authentication Bypass (CWE-287)",
    "Cryptographic Flaws (CWE-310)",
    "Improper Access Control (CWE-284)",
    "Untrusted Deserialization (CWE-502)"
]

def generate_cve_dataset(n_samples: int = 4500, seed: int = 2026) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    
    vendors = list(VENDORS_STACK.keys())
    vendor_probs = [0.25, 0.20, 0.15, 0.10, 0.12, 0.06, 0.06, 0.06]
    selected_vendors = rng.choice(vendors, size=n_samples, p=vendor_probs)
    
    records = []
    base_date = datetime(2022, 1, 1)
    
    for i, v_name in enumerate(selected_vendors):
        v_meta = VENDORS_STACK[v_name]
        prod = rng.choice(v_meta["products"])
        layer = v_meta["layer"]
        cwe = rng.choice(CWE_FAMILIES, p=v_meta["cwe_weights"])
        
        cvss_base = np.clip(np.round(rng.normal(loc=7.1, scale=1.7), 1), 2.0, 10.0)
        cvss_impact = np.clip(np.round(cvss_base * rng.uniform(0.45, 0.65), 1), 1.0, 6.0)
        
        raw_epss = rng.lognormal(mean=-3.8, sigma=1.5)
        epss_score = float(np.clip(np.round(raw_epss / (raw_epss + 1.2), 4), 0.0005, 0.9850))
        
        if cvss_base >= 8.5 and cwe in ["Authentication Bypass (CWE-287)", "Injection (CWE-89/78)"]:
            if rng.random() < 0.25:
                epss_score = float(np.clip(epss_score + rng.uniform(0.35, 0.70), 0.01, 0.99))
        
        kev_prob = 0.02 + (0.55 * (epss_score ** 1.3)) + (0.04 if cvss_base >= 9.0 else 0.0)
        is_kev = bool(rng.random() < np.clip(kev_prob, 0.01, 0.85))
        
        if "Network" in layer or cwe == "Injection (CWE-89/78)":
            vector = rng.choice(["Network", "Adjacent", "Local"], p=[0.75, 0.15, 0.10])
        else:
            vector = rng.choice(["Network", "Adjacent", "Local"], p=[0.45, 0.15, 0.40])
            
        complexity = rng.choice(["Low", "High"], p=[0.78, 0.22])
        privs = rng.choice(["None", "Low", "High"], p=[0.55, 0.30, 0.15])
        
        pub_offset = int(rng.integers(0, 1500))
        pub_date = base_date + timedelta(days=pub_offset)
        
        if is_kev:
            decay_scale = v_meta["exploit_decay_scale"]
            days_lag = int(np.clip(np.round(rng.exponential(scale=decay_scale) + 2), 2, 180))
        else:
            days_lag = None
            
        cve_id = f"CVE-{pub_date.year}-{1000 + i}"
        
        records.append({
            "cve_id": cve_id,
            "vendor": v_name,
            "product": prod,
            "layer": layer,
            "cwe_family": cwe,
            "cvss_base": cvss_base,
            "cvss_impact": cvss_impact,
            "epss_score": epss_score,
            "is_kev": is_kev,
            "attack_vector": vector,
            "attack_complexity": complexity,
            "privileges_required": privs,
            "disclosure_date": pub_date.strftime("%Y-%m-%d"),
            "days_to_exploit": days_lag
        })
        
    df = pd.DataFrame(records)
    return df

def run_etl_pipeline(output_dir: Optional[str] = None) -> pd.DataFrame:
    target_dir = Path(output_dir) if output_dir else DEFAULT_DATA_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    
    df = generate_cve_dataset(n_samples=4500, seed=2026)
    
    parquet_path = target_dir / "cve_unified_dataset.parquet"
    csv_path = target_dir / "cve_unified_dataset.csv"
    
    df.to_parquet(parquet_path, index=False)
    df.to_csv(csv_path, index=False)
    print(f"ETL completed: {len(df)} records exported to {parquet_path} and {csv_path}")
    return df

if __name__ == "__main__":
    run_etl_pipeline()
