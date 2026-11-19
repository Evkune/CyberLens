from __future__ import annotations

import pandas as pd
import pytest

from cyberlens.domain.clustering import compute_access_ease, perform_threat_clustering
from cyberlens.ingestion.loader import load_dataset


@pytest.fixture(scope="module")
def sample_df() -> pd.DataFrame:
    return load_dataset().head(1200)


def test_access_ease_incorporates_attack_complexity() -> None:
    df = pd.DataFrame(
        [
            {"attack_vector": "Network", "attack_complexity": "Low", "privileges_required": "None"},
            {"attack_vector": "Network", "attack_complexity": "High", "privileges_required": "None"},
            {"attack_vector": "Local", "attack_complexity": "High", "privileges_required": "High"},
        ]
    )
    ease = compute_access_ease(df)
    assert ease.iloc[0] > ease.iloc[1] > ease.iloc[2]


@pytest.mark.parametrize("k", [3, 4, 5, 6])
def test_clustering_unique_archetype_names_for_all_k(sample_df: pd.DataFrame, k: int) -> None:
    res = perform_threat_clustering(sample_df, n_clusters=k, random_state=42)

    assert res.n_clusters == k
    assert len(res.cluster_names) == k
    assert len(set(res.cluster_names.values())) == k, f"Duplicate cluster names for K={k}: {res.cluster_names}"
    assert res.df["threat_cluster"].nunique() == k
    assert res.df["threat_cluster"].notna().all()
    assert -1.0 <= res.silhouette <= 1.0
    assert res.davies_bouldin > 0.0
    assert res.calinski_harabasz > 0.0


def test_clustering_handles_empty_or_tiny_input() -> None:
    empty = pd.DataFrame(columns=["cvss_base", "epss_score", "cvss_impact", "attack_vector", "privileges_required"])
    res = perform_threat_clustering(empty, n_clusters=4)
    assert res.n_clusters == 0
    assert res.silhouette == 0.0
    assert "threat_cluster" in res.df.columns
