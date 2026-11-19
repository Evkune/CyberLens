from __future__ import annotations

import pandas as pd
import pytest

from cyberlens.config import (
    ATTACK_COMPLEXITY_ORDER,
    ATTACK_VECTOR_ORDER,
    PRIVILEGES_REQUIRED_ORDER,
    REQUIRED_SCHEMA_COLUMNS,
)
from cyberlens.ingestion.etl_pipeline import (
    generate_offline_fallback_dataset,
    map_cwe_family,
    map_vendor_and_layer,
)
from cyberlens.ingestion.loader import clear_dataset_cache, load_dataset, load_dataset_metadata


@pytest.fixture(scope="module")
def dataset() -> pd.DataFrame:
    clear_dataset_cache()
    return load_dataset()


def test_dataset_schema_and_domains(dataset: pd.DataFrame) -> None:
    assert len(dataset) >= 1000
    for col in REQUIRED_SCHEMA_COLUMNS:
        assert col in dataset.columns, f"Missing column: {col}"

    assert dataset["cve_id"].is_unique
    assert dataset["cvss_base"].between(0.0, 10.0).all()
    assert dataset["cvss_impact"].between(0.0, 10.0).all()
    assert dataset["epss_score"].between(0.0, 1.0).all()
    assert dataset["epss_score_30d"].between(0.0, 1.0).all()
    assert dataset["epss_delta_30d"].between(-1.0, 1.0).all()

    kev_days = dataset.loc[dataset["is_kev"], "days_to_exploit"].dropna()
    assert (kev_days >= 0).all()
    assert dataset.loc[~dataset["is_kev"], "days_to_exploit"].isna().all()
    assert (~dataset.loc[~dataset["is_kev"], "is_ransomware"]).all()


def test_munzner_ordinal_categorical_typing(dataset: pd.DataFrame) -> None:
    av_dtype = dataset["attack_vector"].dtype
    pr_dtype = dataset["privileges_required"].dtype
    ac_dtype = dataset["attack_complexity"].dtype

    assert isinstance(av_dtype, pd.CategoricalDtype) and av_dtype.ordered
    assert list(av_dtype.categories) == ATTACK_VECTOR_ORDER

    assert isinstance(pr_dtype, pd.CategoricalDtype) and pr_dtype.ordered
    assert list(pr_dtype.categories) == PRIVILEGES_REQUIRED_ORDER

    assert isinstance(ac_dtype, pd.CategoricalDtype) and ac_dtype.ordered
    assert list(ac_dtype.categories) == ATTACK_COMPLEXITY_ORDER


def test_vendor_and_cwe_mapping() -> None:
    assert map_vendor_and_layer("paloaltonetworks", "pan-os") == (
        "Palo Alto Networks",
        "Network Infrastructure",
    )
    assert map_vendor_and_layer("microsoft", "Windows Server") == (
        "Microsoft",
        "OS & Firmware",
    )
    assert map_vendor_and_layer("unknown_hobby_vendor", "toy_app") is None

    cwe_id, family = map_cwe_family(["CWE-787"])
    assert cwe_id == "CWE-787"
    assert "Memory Corruption" in family

    cwe_id2, family2 = map_cwe_family(["CWE-99999"])
    assert cwe_id2 == "CWE-99999"
    assert "Input Validation" in family2


def test_offline_fallback_schema_parity() -> None:
    df_a, meta_a = generate_offline_fallback_dataset(n_samples=200, seed=7)
    df_b, _ = generate_offline_fallback_dataset(n_samples=200, seed=7)

    assert list(df_a.columns) == REQUIRED_SCHEMA_COLUMNS
    assert meta_a["source_mode"] == "offline_fallback"
    pd.testing.assert_frame_equal(df_a, df_b)


def test_dataset_metadata_present() -> None:
    meta = load_dataset_metadata()
    assert meta.get("source_mode") in {"live_feeds", "offline_fallback"}
    assert meta.get("total_records", 0) > 0
