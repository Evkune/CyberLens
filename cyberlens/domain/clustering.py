from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Set

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import calinski_harabasz_score, davies_bouldin_score, silhouette_score
from sklearn.preprocessing import StandardScaler

from cyberlens.config import CVSS_AC_WEIGHTS, CVSS_AV_WEIGHTS, CVSS_PR_WEIGHTS


@dataclass
class ClusteringResult:
    df: pd.DataFrame
    n_clusters: int
    silhouette: float
    davies_bouldin: float
    calinski_harabasz: float
    cluster_names: Dict[int, str]
    profiles: Dict[int, Dict[str, Any]]


def compute_access_ease(df: pd.DataFrame) -> pd.Series:
    """CVSS v3.1 exploitability access ease incorporating Attack Vector, Complexity, and Privileges."""
    w_av = df["attack_vector"].astype(str).map(CVSS_AV_WEIGHTS).fillna(0.55)
    w_ac = (
        df["attack_complexity"].astype(str).map(CVSS_AC_WEIGHTS).fillna(0.77)
        if "attack_complexity" in df.columns
        else pd.Series(0.77, index=df.index)
    )
    w_pr = df["privileges_required"].astype(str).map(CVSS_PR_WEIGHTS).fillna(0.62)
    return (8.22 * w_av * w_ac * w_pr).astype(float)


def _assign_unique_archetypes(
    centroids: np.ndarray,
    profiles: Dict[int, Dict[str, Any]],
) -> Dict[int, str]:
    """Deterministic, collision-free archetype naming for K in [3, 6]."""
    n_clusters = len(profiles)
    remaining: Set[int] = set(range(n_clusters))
    names: Dict[int, str] = {}

    # Feature index layout: 0=cvss_base, 1=epss_logit, 2=epss_delta_30d, 3=cvss_impact, 4=access_ease
    # 1. Critical Weapons: highest combined severity + empirical exploitability
    a_id = max(remaining, key=lambda c: float(centroids[c][0] + centroids[c][1]))
    names[a_id] = "Cluster A: Critical Weapons (High CVSS + Exploit)"
    remaining.remove(a_id)

    # 2. Silent Threats: highest empirical exploit relative to moderate CVSS
    if remaining:
        b_id = max(remaining, key=lambda c: float(centroids[c][1] - 0.5 * centroids[c][0]))
        names[b_id] = "Cluster B: Silent Threats (Moderate CVSS + Active Exploit)"
        remaining.remove(b_id)

    # 3. Paper Tigers: highest theoretical CVSS with low empirical exploitability
    if remaining:
        c_id = max(remaining, key=lambda c: float(centroids[c][0] - centroids[c][1]))
        names[c_id] = "Cluster C: Paper Tigers (High CVSS + Low Exploit)"
        remaining.remove(c_id)

    # 4. Dormant Backlog: lowest overall risk among remaining
    if remaining:
        d_id = min(remaining, key=lambda c: float(centroids[c][0] + centroids[c][1] + centroids[c][2]))
        names[d_id] = "Cluster D: Dormant Backlog (Low Risk)"
        remaining.remove(d_id)

    # 5. Rising Velocity (for K >= 5): highest EPSS 30-day acceleration
    if remaining:
        e_id = max(remaining, key=lambda c: float(centroids[c][2] + 0.3 * centroids[c][1]))
        names[e_id] = "Cluster E: Rising Velocity (EPSS Surge)"
        remaining.remove(e_id)

    # 6. Exposed Surface (for K >= 6): highest network/unauthenticated access ease
    if remaining:
        f_id = max(remaining, key=lambda c: float(centroids[c][4]))
        names[f_id] = "Cluster F: Exposed Surface (High Access Ease)"
        remaining.remove(f_id)

    # Safety fallback if K > 6 is ever requested
    for idx, extra_id in enumerate(sorted(remaining), start=1):
        names[extra_id] = f"Cluster G{idx}: Secondary Profile"

    return names


def perform_threat_clustering(
    df: pd.DataFrame,
    n_clusters: int = 4,
    random_state: int = 42,
) -> ClusteringResult:
    """5D unsupervised K-Means++ threat clustering over logit-EPSS, velocity, severity, impact, and access ease."""
    n_clusters = max(2, int(n_clusters))
    if len(df) < n_clusters or len(df) == 0:
        res = df.copy()
        res["cluster_id"] = -1
        res["threat_cluster"] = "Unassigned"
        return ClusteringResult(
            df=res,
            n_clusters=0,
            silhouette=0.0,
            davies_bouldin=0.0,
            calinski_harabasz=0.0,
            cluster_names={},
            profiles={},
        )

    res_df = df.copy()
    eps = 1e-4
    clipped_epss = np.clip(res_df["epss_score"].fillna(0.001).to_numpy(dtype=float), eps, 1.0 - eps)
    res_df["epss_logit"] = np.log(clipped_epss / (1.0 - clipped_epss))
    res_df["access_ease"] = compute_access_ease(res_df)

    delta_col = (
        res_df["epss_delta_30d"].fillna(0.0).to_numpy(dtype=float)
        if "epss_delta_30d" in res_df.columns
        else np.zeros(len(res_df), dtype=float)
    )
    # Soft-compress heavy-tailed 30d velocity so rare surges don't hijack a full K=4 centroid
    delta_compressed = np.tanh(delta_col / 0.15)

    core_cols = ["cvss_base", "epss_logit", "cvss_impact", "access_ease"]
    x_core = res_df[core_cols].fillna(0.0).to_numpy(dtype=float)
    x_core_scaled = StandardScaler().fit_transform(x_core)

    # Feature order: 0=cvss_base, 1=epss_logit, 2=epss_delta_compressed, 3=cvss_impact, 4=access_ease
    x_scaled = np.column_stack(
        [
            x_core_scaled[:, 0],
            x_core_scaled[:, 1],
            delta_compressed * 0.5,
            x_core_scaled[:, 2],
            x_core_scaled[:, 3],
        ]
    )

    kmeans = KMeans(
        n_clusters=n_clusters,
        init="k-means++",
        n_init=15,
        random_state=random_state,
    )
    labels = kmeans.fit_predict(x_scaled)
    res_df["cluster_id"] = labels

    unique_labels = len(np.unique(labels))
    if unique_labels >= 2 and len(res_df) > unique_labels:
        sample_size = min(len(res_df), 2000)
        rng = np.random.default_rng(random_state)
        if len(res_df) > sample_size:
            sample_idx = rng.choice(len(res_df), size=sample_size, replace=False)
            sil = float(silhouette_score(x_scaled[sample_idx], labels[sample_idx]))
        else:
            sil = float(silhouette_score(x_scaled, labels))
        dbi = float(davies_bouldin_score(x_scaled, labels))
        chi = float(calinski_harabasz_score(x_scaled, labels))
    else:
        sil, dbi, chi = 0.0, 0.0, 0.0

    centroids = kmeans.cluster_centers_
    profiles: Dict[int, Dict[str, Any]] = {}
    for c_id in range(n_clusters):
        sub = res_df.loc[res_df["cluster_id"] == c_id]
        profiles[c_id] = {
            "count": int(len(sub)),
            "mean_cvss": round(float(sub["cvss_base"].mean()), 2) if len(sub) else 0.0,
            "mean_epss": round(float(sub["epss_score"].mean()), 4) if len(sub) else 0.0,
            "mean_delta_30d": (
                round(float(sub["epss_delta_30d"].mean()), 4)
                if ("epss_delta_30d" in sub.columns and len(sub))
                else 0.0
            ),
            "kev_ratio": round(float(sub["is_kev"].mean()), 4) if len(sub) else 0.0,
            "z_cvss": round(float(centroids[c_id][0]), 3),
            "z_epss": round(float(centroids[c_id][1]), 3),
            "z_delta": round(float(centroids[c_id][2]), 3),
        }

    cluster_names = _assign_unique_archetypes(centroids, profiles)
    for c_id, name in cluster_names.items():
        profiles[c_id]["name"] = name

    res_df["threat_cluster"] = res_df["cluster_id"].map(cluster_names)

    return ClusteringResult(
        df=res_df,
        n_clusters=n_clusters,
        silhouette=round(sil, 3),
        davies_bouldin=round(dbi, 3),
        calinski_harabasz=round(chi, 1),
        cluster_names=cluster_names,
        profiles=profiles,
    )
