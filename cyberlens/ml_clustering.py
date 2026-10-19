import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from typing import Tuple, Dict, Any

# Official FIRST.org CVSS v3.1 Exploitability Sub-Score Weights
ATTACK_VECTOR_WEIGHTS = {
    "Network": 0.85,
    "Adjacent": 0.62,
    "Local": 0.55,
    "Physical": 0.20
}

PRIVILEGES_REQUIRED_WEIGHTS = {
    "None": 0.85,
    "Low": 0.62,
    "High": 0.27
}

def compute_exploitability_metric(df: pd.DataFrame) -> pd.Series:
    """Computes normalized access ease based on CVSS v3.1 vector and privileges."""
    w_av = df["attack_vector"].map(ATTACK_VECTOR_WEIGHTS).fillna(0.55)
    w_pr = df["privileges_required"].map(PRIVILEGES_REQUIRED_WEIGHTS).fillna(0.62)
    return 8.22 * w_av * w_pr

def perform_threat_clustering(
    df: pd.DataFrame, 
    n_clusters: int = 4, 
    random_state: int = 42
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Performs 4D unsupervised K-Means threat clustering using logit-transformed EPSS,
    Z-score standardization, and deterministic CISO archetype mapping.
    """
    if len(df) < n_clusters or len(df) == 0:
        res = df.copy()
        res["threat_cluster"] = "Unassigned"
        return res, {"silhouette": 0.0, "cluster_names": {}}
        
    res_df = df.copy()
    
    # 1. Logit Transform on heavy-tailed EPSS score (inverting logistic link)
    eps = 1e-4
    clipped_epss = np.clip(res_df["epss_score"].fillna(0.001), eps, 1.0 - eps)
    res_df["epss_logit"] = np.log(clipped_epss / (1.0 - clipped_epss))
    
    # 2. Principled Quantification of Access Complexity
    res_df["access_ease"] = compute_exploitability_metric(res_df)
    
    # 3. 4D Feature Space Formulation & Z-Score Standardization
    features = ["cvss_base", "epss_logit", "cvss_impact", "access_ease"]
    X_raw = res_df[features].fillna(0).values
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    
    # 4. K-Means++ Clustering
    kmeans = KMeans(n_clusters=n_clusters, init="k-means++", n_init=15, random_state=random_state)
    labels = kmeans.fit_predict(X_scaled)
    res_df["cluster_id"] = labels
    
    # 5. Model Validation via Silhouette Coefficient
    try:
        sample_size = min(len(res_df), 1500)
        sil_score = float(silhouette_score(X_scaled[:sample_size], labels[:sample_size]))
    except Exception:
        sil_score = 0.0
        
    # 6. Deterministic Centroid-to-Archetype Mapping for CISOs
    # Analyze standardized centroid coordinates
    centroids = kmeans.cluster_centers_
    cluster_profiles = {}
    
    for c_id in range(n_clusters):
        subset = res_df[res_df["cluster_id"] == c_id]
        cluster_profiles[c_id] = {
            "mean_cvss": float(subset["cvss_base"].mean()),
            "mean_epss": float(subset["epss_score"].mean()),
            "kev_ratio": float(subset["is_kev"].mean()),
            "z_epss": float(centroids[c_id][1]),
            "z_cvss": float(centroids[c_id][0]),
            "count": len(subset)
        }
        
    # Deterministic Archetype Assignment Rules
    cluster_names = {}
    remaining_ids = set(range(n_clusters))
    
    # Archetype A: Critical Weapons (Highest z_epss + z_cvss)
    a_id = max(remaining_ids, key=lambda c: cluster_profiles[c]["z_epss"] + cluster_profiles[c]["z_cvss"])
    cluster_names[a_id] = "Cluster A: Critical Weapons (High CVSS + Exploit)"
    remaining_ids.remove(a_id)
    
    # Archetype B: Silent Threats (Highest remaining z_epss)
    if remaining_ids:
        b_id = max(remaining_ids, key=lambda c: cluster_profiles[c]["z_epss"])
        cluster_names[b_id] = "Cluster B: Silent Threats (Moderate CVSS + Active Exploit)"
        remaining_ids.remove(b_id)
        
    # Archetype C: Paper Tigers (Highest remaining z_cvss - z_epss)
    if remaining_ids:
        c_id = max(remaining_ids, key=lambda c: cluster_profiles[c]["z_cvss"] - cluster_profiles[c]["z_epss"])
        cluster_names[c_id] = "Cluster C: Paper Tigers (High CVSS + Low Exploit)"
        remaining_ids.remove(c_id)
        
    # Archetype D: Dormant Backlog (Remaining lowest risk)
    for rem_id in remaining_ids:
        cluster_names[rem_id] = "Cluster D: Dormant Backlog (Low Risk)"
        
    res_df["threat_cluster"] = res_df["cluster_id"].map(cluster_names)
    
    metadata = {
        "n_clusters": n_clusters,
        "silhouette": round(sil_score, 3),
        "profiles": cluster_profiles,
        "cluster_names": cluster_names
    }
    
    return res_df, metadata
