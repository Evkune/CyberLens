import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from typing import Tuple, Dict, Any

def perform_threat_clustering(
    df: pd.DataFrame, 
    n_clusters: int = 4, 
    random_state: int = 42
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    if len(df) < n_clusters or len(df) == 0:
        res = df.copy()
        res["threat_cluster"] = "Unassigned"
        return res, {"silhouette": 0.0, "cluster_names": {}}
        
    features = ["cvss_base", "epss_score", "cvss_impact"]
    X = df[features].fillna(0).values
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    kmeans = KMeans(n_clusters=n_clusters, random_state=random_state, n_init=10)
    labels = kmeans.fit_predict(X_scaled)
    
    res_df = df.copy()
    res_df["cluster_id"] = labels
    
    # Analyze cluster centroids to assign meaningful threat archetypes
    cluster_profiles = {}
    cluster_names = {}
    
    for c_id in range(n_clusters):
        subset = res_df[res_df["cluster_id"] == c_id]
        mean_cvss = subset["cvss_base"].mean()
        mean_epss = subset["epss_score"].mean()
        kev_ratio = subset["is_kev"].mean()
        
        cluster_profiles[c_id] = {
            "mean_cvss": mean_cvss,
            "mean_epss": mean_epss,
            "kev_ratio": kev_ratio,
            "count": len(subset)
        }
        
    # Rank clusters by threat urgency
    sorted_clusters = sorted(
        cluster_profiles.keys(),
        key=lambda c: (cluster_profiles[c]["mean_epss"] * 0.7 + (cluster_profiles[c]["mean_cvss"] / 10.0) * 0.3),
        reverse=True
    )
    
    archetype_labels = [
        "Cluster A: Critical Weapons (High CVSS + Exploit)",
        "Cluster B: Silent Threats (Moderate CVSS + Active Exploit)",
        "Cluster C: Paper Tigers (High CVSS + Low Exploit)",
        "Cluster D: Dormant Backlog (Low Risk)"
    ]
    
    for rank, c_id in enumerate(sorted_clusters):
        if rank < len(archetype_labels):
            cluster_names[c_id] = archetype_labels[rank]
        else:
            cluster_names[c_id] = f"Cluster {chr(65 + rank)}: Specialized Tier"
            
    res_df["threat_cluster"] = res_df["cluster_id"].map(cluster_names)
    
    metadata = {
        "n_clusters": n_clusters,
        "profiles": cluster_profiles,
        "cluster_names": cluster_names
    }
    
    return res_df, metadata
