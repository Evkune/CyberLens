from __future__ import annotations

import re
from typing import List

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import pytest

from cyberlens.domain.clustering import perform_threat_clustering
from cyberlens.domain.prioritization import enrich_prioritization, rank_action_queue
from cyberlens.ingestion.loader import load_dataset
from cyberlens.ui.mod_triage_queue import format_action_queue_table
from cyberlens.viz.idiom_bubble import create_prioritization_bubble_plot
from cyberlens.viz.idiom_ridgeline import (
    BASELINE_STEP,
    RIDGE_MAX_HEIGHT,
    compute_reflected_kde,
    create_velocity_ridgeline_plot,
)
from cyberlens.viz.idiom_treemap import (
    ROOT_NODE_LABEL,
    create_architectural_treemap,
    extract_treemap_click_filter,
)


@pytest.fixture(scope="module")
def sample_df() -> pd.DataFrame:
    df = load_dataset()
    # Ensure both KEV and non-KEV records are well represented in the test slice
    kev_part = df.loc[df["is_kev"]].head(250)
    non_kev_part = df.loc[~df["is_kev"]].head(350)
    combined = pd.concat([kev_part, non_kev_part], ignore_index=True)
    return enrich_prioritization(combined, cvss_cutoff=7.0, epss_cutoff=0.30)


@pytest.mark.parametrize("color_mode", ["sla_tier", "threat_cluster", "epss_velocity"])
@pytest.mark.parametrize("y_scale", ["linear", "log"])
def test_bubble_plot_webgl_modes_scales_and_no_nan_tooltips(
    sample_df: pd.DataFrame,
    color_mode: str,
    y_scale: str,
) -> None:
    work_df = (
        perform_threat_clustering(sample_df, n_clusters=4).df
        if color_mode == "threat_cluster"
        else sample_df
    )

    fig = create_prioritization_bubble_plot(
        work_df,
        cvss_thresh=7.0,
        epss_thresh=0.30,
        color_by=color_mode,
        y_scale=y_scale,
        show_landmarks=True,
    )

    assert len(fig.data) > 0
    for trace in fig.data:
        assert isinstance(trace, go.Scattergl), f"Expected WebGL Scattergl trace, got {type(trace)}"
        if trace.customdata is not None:
            flat_strings = [str(cell) for row in trace.customdata for cell in row]
            assert not any(
                s.lower() in {"nan", "null"} or "nan" in s.lower() for s in flat_strings
            ), "Found NaN/null in Bubble Plot customdata tooltip payload"

    assert fig.layout.yaxis.type == y_scale


def test_bubble_plot_focus_context_landmarks_and_pinned_cve(sample_df: pd.DataFrame) -> None:
    target_cve = str(sample_df.loc[sample_df["is_kev"], "cve_id"].iloc[0])

    fig = create_prioritization_bubble_plot(
        sample_df,
        cvss_thresh=7.0,
        epss_thresh=0.30,
        color_by="sla_tier",
        focus_layer="Network Infrastructure",
        inspected_cve=target_cve,
        show_landmarks=True,
    )

    trace_names = [str(t.name) for t in fig.data]
    assert any("Context" in name for name in trace_names)
    assert any(f"Pinned: {target_cve}" in name for name in trace_names)

    # Quadrant corner labels (4) + CVSS/EPSS cutoffs (2) + Landmarks (2) + Pinned callout (1)
    assert len(fig.layout.annotations) >= 7
    for ann in fig.layout.annotations:
        if ann.showarrow:
            # Verify adaptive offsets keep callouts inside safe pixel bounds
            assert -90 <= int(ann.ax) <= 90
            assert -70 <= int(ann.ay) <= 70


@pytest.mark.parametrize("metric", ["expected_risk", "actionable_count", "kev_count"])
def test_treemap_metrics_and_strict_parent_child_additivity(
    sample_df: pd.DataFrame,
    metric: str,
) -> None:
    fig = create_architectural_treemap(sample_df, metric=metric, as_widget=False)
    assert len(fig.data) == 1

    trace = fig.data[0]
    assert isinstance(trace, go.Treemap)
    assert trace.branchvalues == "total"
    assert trace.tiling.packing == "squarify"

    ids = list(trace.ids)
    parents = list(trace.parents)
    values = [float(v) for v in trace.values]

    assert ROOT_NODE_LABEL in ids
    assert len(ids) > 5

    # Verify parent value strictly equals sum of immediate children for every internal node
    children_map = {}
    for node_id, parent_id, val in zip(ids, parents, values):
        if parent_id:
            children_map.setdefault(parent_id, 0.0)
            children_map[parent_id] += val

    for node_id, val in zip(ids, values):
        if node_id in children_map:
            assert np.isclose(
                val, children_map[node_id], rtol=1e-4, atol=1e-3
            ), f"Parent {node_id} value {val} != sum of children {children_map[node_id]}"


def test_treemap_click_filter_extraction() -> None:
    assert extract_treemap_click_filter(None) == {
        "layer": None,
        "cwe_family": None,
        "vendor": None,
    }
    assert extract_treemap_click_filter(ROOT_NODE_LABEL) == {
        "layer": None,
        "cwe_family": None,
        "vendor": None,
    }
    assert extract_treemap_click_filter(
        f"{ROOT_NODE_LABEL}|Network Infrastructure|Injection (CWE-89/78)|Cisco"
    ) == {
        "layer": "Network Infrastructure",
        "cwe_family": "Injection (CWE-89/78)",
        "vendor": "Cisco",
    }
    assert extract_treemap_click_filter(f"{ROOT_NODE_LABEL}|OS & Firmware") == {
        "layer": "OS & Firmware",
        "cwe_family": None,
        "vendor": None,
    }


def test_ridgeline_mirror_kde_p50_sorting_direct_y_labels_and_sla_lines(
    sample_df: pd.DataFrame,
) -> None:
    # 1. Mirror KDE preserves zero-day boundary density at t = 0
    zero_day_sample = np.array([0.0, 0.0, 1.0, 2.0, 3.0, 5.0, 12.0, 25.0])
    t_grid = np.linspace(0.0, 60.0, 120)
    kde_vals = compute_reflected_kde(zero_day_sample, t_grid)
    assert kde_vals[0] > 0.0
    assert (kde_vals >= 0.0).all()

    # 2. Ridgeline plot sorted strictly by ascending P50 median on Y-axis
    fig = create_velocity_ridgeline_plot(
        sample_df,
        max_days=120,
        highlight_vendor="Microsoft",
    )
    assert len(fig.data) > 0

    # Verify direct Y-axis labels are enabled and ordered by ascending P50
    assert fig.layout.yaxis.showticklabels is True
    tickvals = list(fig.layout.yaxis.tickvals)
    ticktext = list(fig.layout.yaxis.ticktext)
    assert len(tickvals) >= 2
    assert len(tickvals) == len(ticktext)

    # Check 25% overlap geometry (baseline step = 0.75, ridge height = 1.00)
    assert np.isclose(BASELINE_STEP, 0.75)
    assert np.isclose(RIDGE_MAX_HEIGHT, 1.00)
    for i in range(1, len(tickvals)):
        assert np.isclose(tickvals[i] - tickvals[i - 1], 0.75)

    p50_values: List[float] = []
    for label in ticktext:
        match = re.search(r"P50=(\d+(?:\.\d+)?)d", str(label))
        assert match is not None, f"Missing P50 label in Y-axis ticktext: {label}"
        p50_values.append(float(match.group(1)))

    assert p50_values == sorted(p50_values), f"Y-axis cohorts not sorted by ascending P50: {p50_values}"

    # Verify customdata length matches x length on every curve trace with customdata
    for trace in fig.data:
        if getattr(trace, "customdata", None) is not None:
            assert len(trace.customdata) == len(trace.x)

    # Verify SLA reference lines (24h = 1.0d, 14d = 14.0d) and 0-7d Flash Zone vrect exist
    shapes = fig.layout.shapes or ()
    x_positions = {float(s.x0) for s in shapes if getattr(s, "x0", None) is not None}
    assert 1.0 in x_positions, "Missing 24h (1.0d) P0 SLA reference line"
    assert 14.0 in x_positions, "Missing 14d Legacy Compliance SLA reference line"
    assert 0.0 in x_positions, "Missing 0-7d Zero-Day Flash Zone vrect"


def test_triage_queue_table_formatting_and_empty_resilience(sample_df: pd.DataFrame) -> None:
    ranked = rank_action_queue(sample_df.head(50))
    table = format_action_queue_table(ranked)
    assert len(table) == 50
    assert "SLA Tier" in table.columns
    assert "CVE ID" in table.columns
    assert "Blind-Spot" in table.columns
    assert not table.isna().any().any()

    # Empty resilience across all 3 idioms + table formatter
    empty_df = sample_df.iloc[0:0].copy()
    empty_bubble = create_prioritization_bubble_plot(empty_df, show_title=False)
    empty_treemap = create_architectural_treemap(empty_df, as_widget=False, show_title=False)
    empty_ridgeline = create_velocity_ridgeline_plot(empty_df, show_title=False)
    assert len(empty_bubble.data) == 0
    assert len(empty_treemap.data) == 0
    assert len(empty_ridgeline.data) == 0
    assert empty_bubble.layout.xaxis.visible is False
    assert empty_bubble.layout.yaxis.visible is False
    assert empty_treemap.layout.xaxis.visible is False
    assert empty_treemap.layout.yaxis.visible is False
    assert empty_ridgeline.layout.xaxis.visible is False
    assert empty_ridgeline.layout.yaxis.visible is False
    assert len(format_action_queue_table(empty_df)) == 0


def test_polish_invariants_legend_order_treemap_hover_and_velocity_semantics(
    sample_df: pd.DataFrame,
) -> None:
    # 1. Bubble plot reversed legend traceorder, default pan dragmode & pre_enriched fast-path parity
    fig_std = create_prioritization_bubble_plot(sample_df, show_title=False, pre_enriched=False)
    fig_fast = create_prioritization_bubble_plot(sample_df, show_title=False, pre_enriched=True)
    assert fig_std.layout.legend.traceorder == "reversed"
    assert fig_std.layout.dragmode == "pan"
    assert len(fig_std.data) == len(fig_fast.data)

    # 2. Treemap hovertemplate never duplicates the active metric label
    for metric in ("expected_risk", "actionable_count", "kev_count"):
        tm = create_architectural_treemap(sample_df, metric=metric, as_widget=False, show_title=False)
        ht = str(tm.data[0].hovertemplate)
        assert ht.count("Actuarial Expected Risk") == 1
        assert ht.count("Confirmed CISA KEV Exploits") == 1

    # 3. Ridgeline semantic velocity color: slow cohorts (P50 > 14d) never wrap to emergency crimson
    from cyberlens.viz.idiom_ridgeline import _velocity_cohort_color

    assert _velocity_cohort_color(1.0) == "#B91C1C"
    assert _velocity_cohort_color(5.0) == "#B45309"
    assert _velocity_cohort_color(10.0) == "#1D4ED8"
    assert _velocity_cohort_color(373.0) == "#71717A"

    # 4. Operational Patch Queue places core triage metrics before verbose product/layer fields
    table = format_action_queue_table(rank_action_queue(sample_df.head(20)))
    assert list(table.columns[:7]) == [
        "SLA Tier",
        "CVE ID",
        "Vendor",
        "CVSS",
        "EPSS",
        "Δ30d",
        "Threat Signal",
    ]


def test_shiny_app_factory_and_cached_ml_decoupling() -> None:
    from shiny import App

    from cyberlens.app import _cached_clustering, create_app

    app_instance = create_app()
    assert isinstance(app_instance, App)

    vendors_key = ("Cisco", "Microsoft")
    res_1 = _cached_clustering(vendors_key, 4)
    res_2 = _cached_clustering(vendors_key, 4)
    assert res_1 is res_2
    assert res_1.n_clusters == 4

