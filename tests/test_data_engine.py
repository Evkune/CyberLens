import pytest
import pandas as pd
import numpy as np
from cyberlens.data_engine import (
    load_dataset,
    filter_by_enterprise_stack,
    filter_by_layers,
    classify_risk_quadrants,
    calculate_kpis
)
from cyberlens.ml_clustering import perform_threat_clustering

@pytest.fixture
def sample_data():
    return load_dataset()

def test_dataset_schema_and_boundaries(sample_data):
    assert len(sample_data) > 0
    required_cols = [
        "cve_id", "vendor", "product", "layer", "cwe_family",
        "cvss_base", "cvss_impact", "epss_score", "is_kev",
        "attack_vector", "attack_complexity", "privileges_required"
    ]
    for col in required_cols:
        assert col in sample_data.columns, f"Missing required column: {col}"
        
    # Check valid mathematical domains
    assert sample_data["cvss_base"].min() >= 0.0
    assert sample_data["cvss_base"].max() <= 10.0
    assert sample_data["epss_score"].min() >= 0.0
    assert sample_data["epss_score"].max() <= 1.0

def test_enterprise_filtering(sample_data):
    vendors = ["Microsoft", "Cisco"]
    filtered = filter_by_enterprise_stack(sample_data, vendors)
    assert set(filtered["vendor"].unique()).issubset(set(vendors))
    assert len(filtered) < len(sample_data)

def test_quadrant_classification(sample_data):
    classified = classify_risk_quadrants(sample_data, cvss_threshold=7.0, epss_threshold=0.3)
    assert "risk_quadrant" in classified.columns
    assert classified["risk_quadrant"].nunique() >= 2

def test_threat_clustering(sample_data):
    clustered, meta = perform_threat_clustering(sample_data.head(500), n_clusters=4)
    assert "threat_cluster" in clustered.columns
    assert len(meta["cluster_names"]) == 4
    assert clustered["threat_cluster"].notnull().all()

def test_kpi_computation(sample_data):
    kpis = calculate_kpis(sample_data)
    assert kpis["total_count"] == len(sample_data)
    assert kpis["kev_count"] >= 0
    assert 0.0 <= kpis["median_cvss"] <= 10.0
