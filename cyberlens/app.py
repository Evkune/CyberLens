from __future__ import annotations

from functools import lru_cache
from typing import Dict, List, Optional, Tuple

import pandas as pd
import plotly.graph_objects as go
from shiny import App, Inputs, Outputs, Session, reactive, ui
from shinywidgets import output_widget, render_plotly

from cyberlens.config import LAYER_ORDER
from cyberlens.domain.clustering import ClusteringResult, perform_threat_clustering
from cyberlens.domain.metrics import TriageMetrics, calculate_triage_metrics
from cyberlens.domain.prioritization import enrich_prioritization, filter_by_scope
from cyberlens.ingestion.loader import load_dataset, load_dataset_metadata
from cyberlens.ui.mod_kpi_header import (
    create_cross_filter_bus,
    kpi_header_server,
    kpi_header_ui,
)
from cyberlens.ui.mod_sidebar import sidebar_server, sidebar_ui
from cyberlens.ui.mod_triage_queue import triage_queue_server, triage_queue_ui
from cyberlens.ui.styles import get_soc_styles
from cyberlens.viz.idiom_bubble import create_prioritization_bubble_plot
from cyberlens.viz.idiom_ridgeline import create_velocity_ridgeline_plot
from cyberlens.viz.idiom_treemap import (
    create_architectural_treemap,
    extract_treemap_click_filter,
)


@lru_cache(maxsize=32)
def _cached_clustering(vendors_key: Tuple[str, ...], k_clusters: int) -> ClusteringResult:
    base = load_dataset()
    scoped = filter_by_scope(base, vendors=vendors_key) if vendors_key else base.iloc[0:0].copy()
    return perform_threat_clustering(scoped, n_clusters=k_clusters)


def _attach_bubble_callbacks(widget: object, bus: object) -> None:
    traces = getattr(widget, "data", ())
    for trace in traces:
        customdata = getattr(trace, "customdata", None)
        if customdata is None:
            continue

        def _on_select(t: object, points: object, selector: object) -> None:
            inds = getattr(points, "point_inds", None)
            cdata = getattr(t, "customdata", None)
            if inds and cdata is not None:
                cves = tuple(
                    str(cdata[i][0]) for i in inds if 0 <= i < len(cdata)
                )
                if cves:
                    bus.brushed_cves.set(cves)

        def _on_click(t: object, points: object, state: object) -> None:
            inds = getattr(points, "point_inds", None)
            cdata = getattr(t, "customdata", None)
            if inds and cdata is not None:
                idx = inds[0]
                if 0 <= idx < len(cdata):
                    cve_id = str(cdata[idx][0])
                    bus.inspected_cve.set(cve_id)

        try:
            if hasattr(trace, "on_selection"):
                trace.on_selection(_on_select)
            if hasattr(trace, "on_click"):
                trace.on_click(_on_click)
        except Exception:
            pass


def _attach_treemap_callbacks(widget: go.FigureWidget, bus: object) -> None:
    if not widget.data:
        return
    trace = widget.data[0]

    def _handle_click(t: object, points: object, state: object) -> None:
        inds = getattr(points, "point_inds", None)
        if inds:
            idx = inds[0]
            trace_ids = getattr(t, "ids", None)
            clicked_id = trace_ids[idx] if trace_ids is not None and idx < len(trace_ids) else None
            selection = extract_treemap_click_filter(clicked_id)
            bus.layer.set(selection.get("layer"))
            bus.cwe_family.set(selection.get("cwe_family"))
            bus.vendor.set(selection.get("vendor"))

    try:
        if hasattr(trace, "on_click"):
            trace.on_click(_handle_click)
    except Exception:
        pass


def _sync_figure_widget(widget: go.FigureWidget, fig: go.Figure) -> None:
    """Updates an existing FigureWidget in-place to avoid anywidget teardown/remount races."""
    with widget.batch_update():
        widget.data = []
        if fig.data:
            widget.add_traces(list(fig.data))
        widget.layout = fig.layout


def _attach_ridgeline_callbacks(widget: object, bus: object) -> None:
    traces = getattr(widget, "data", ())
    for trace in traces:
        meta = getattr(trace, "meta", None)
        if not isinstance(meta, dict) or "vendor" not in meta:
            continue

        def _on_ridge_click(t: object, points: object, state: object) -> None:
            inds = getattr(points, "point_inds", None)
            t_meta = getattr(t, "meta", None)
            if inds and isinstance(t_meta, dict) and "vendor" in t_meta:
                clicked_vendor = str(t_meta["vendor"])
                current = bus.vendor.get()
                bus.vendor.set(None if current == clicked_vendor else clicked_vendor)

        try:
            if hasattr(trace, "on_click"):
                trace.on_click(_on_ridge_click)
        except Exception:
            pass


def create_app() -> App:
    dataset = load_dataset()
    meta = load_dataset_metadata()
    available_vendors: List[str] = sorted(dataset["vendor"].astype(str).unique().tolist())
    present_layers = set(dataset["layer"].astype(str).unique().tolist())
    available_layers: List[str] = [l for l in LAYER_ORDER if l in present_layers] + sorted(
        present_layers - set(LAYER_ORDER)
    )
    total_raw_records = len(dataset)
    snapshot_date = str(
        meta.get("epss_date_current")
        or str(meta.get("generated_at_utc", ""))[:10]
        or "N/A"
    )
    source_badge_text = (
        f"Snapshot: {total_raw_records:,} CVEs · {int(dataset['is_kev'].sum()):,} CISA KEVs"
    )

    app_ui = ui.page_fluid(
        get_soc_styles(),
        ui.panel_title(
            ui.div(
                ui.div(
                    ui.h2("CyberLens", class_="editorial-title"),
                    ui.p(
                        "Vulnerability Triage & Risk-Based Prioritization",
                        class_="editorial-subtitle",
                    ),
                ),
                ui.div(
                    ui.span(source_badge_text, class_="snapshot-pill"),
                ),
                class_="editorial-header",
            )
        ),
        ui.layout_sidebar(
            sidebar_ui("sidebar", available_vendors=available_vendors, available_layers=available_layers),
            ui.div(
                kpi_header_ui("kpi_header"),
                ui.div(
                    ui.div(
                        ui.div(
                            ui.div(
                                ui.span("Threat Prioritization: Severity vs Weaponization", class_="card-header-title"),
                                ui.span("Lasso or click bubbles", class_="card-header-hint"),
                                class_="card-header-bar",
                            ),
                            output_widget("plot_bubble", height="430px"),
                            class_="soc-section",
                        ),
                        class_="col-12 col-lg-6 editorial-col-left",
                    ),
                    ui.div(
                        ui.div(
                            ui.div(
                                ui.span("Attack Surface Hierarchy (Squarified Treemap)", class_="card-header-title"),
                                ui.span("Click tiles to cross-filter", class_="card-header-hint"),
                                class_="card-header-bar",
                            ),
                            output_widget("plot_treemap", height="430px"),
                            class_="soc-section",
                        ),
                        class_="col-12 col-lg-6 editorial-col-right",
                    ),
                    class_="row g-0 editorial-two-col",
                ),
                ui.div(
                    output_widget("plot_ridgeline", height="340px"),
                    class_="soc-section soc-section-bordered",
                ),
                triage_queue_ui("triage_queue"),
                ui.div(
                    ui.accordion(
                        ui.accordion_panel(
                            "Methodology & Scoring Definitions",
                            ui.markdown(
                                """
                                - **Prioritization Scatter (`go.Scattergl`):** Compares NVD CVSS v3.1 base severity against FIRST EPSS v3 30-day exploitation probability and CISA KEV status. Marker area scales with CVSS Impact (`a = 0.7`, `D_max = 28 px`); diamonds mark ransomware-linked KEVs and triangles mark 30-day EPSS velocity surges.
                                - **Architectural Treemap:** Aggregates vulnerabilities across `Layer -> CWE Family -> Vendor`, sized by expected risk (`sum(CVSS * P_eff)`), actionable queue count, or confirmed KEV count, and shaded by network exposure ratio.
                                - **Exploitation Velocity Ridgeline:** Estimates disclosure-to-KEV lag density on `[0, +inf)` using boundary-reflected Gaussian KDE, ordered by ascending cohort median (`P50`) with `24h` (`P0`) and `14d` SLA reference thresholds.
                                - **5D Logit K-Means:** Optional K-Means++ clustering (`K in [3, 6]`) over standardized CVSS, logit-EPSS, EPSS velocity, impact, and exposure features; updates only the scatter overlay and cluster diagnostics.
                                """
                            ),
                        ),
                        id="acc_methodology",
                        open=False,
                    ),
                    style="margin-top: 14px;",
                ),
                ui.tags.footer(
                    ui.span("CyberLens — Evan Gendrot & Minerva Nayeli Rosas Sanchez"),
                    ui.span(f"Snapshot: {snapshot_date}", class_="mono-num"),
                    class_="editorial-footer",
                ),
            ),
        ),
    )

    def server(input: Inputs, output: Outputs, session: Session) -> None:
        base_df = load_dataset()
        bus = create_cross_filter_bus()

        # Node 1: Inventory Scope (depends ONLY on selected vendors)
        @reactive.calc
        def scoped_df() -> pd.DataFrame:
            vendors = sidebar_state.selected_vendors()
            return filter_by_scope(base_df, vendors=vendors)

        # Node 2: 5D Logit K-Means Clustering (isolated from sliders, Treemap, Ridgeline, and KPIs)
        @reactive.calc
        def ml_result() -> Optional[ClusteringResult]:
            vendors_key = tuple(sorted(sidebar_state.selected_vendors()))
            k_val = sidebar_state.k_clusters()
            return _cached_clustering(vendors_key, k_val)

        sidebar_state = sidebar_server(
            "sidebar",
            available_vendors=available_vendors,
            ml_result_calc=ml_result,
        )

        # Node 3: Vectorized RBVM Prioritization & Preset Filtering (isolated from ML!)
        @reactive.calc
        def triaged_df() -> pd.DataFrame:
            df = scoped_df()
            cvss_t = sidebar_state.cvss_cutoff()
            epss_t = sidebar_state.epss_cutoff()
            enriched = enrich_prioritization(df, cvss_cutoff=cvss_t, epss_cutoff=epss_t)
            preset = sidebar_state.cti_preset()
            if preset != "all":
                enriched = filter_by_scope(enriched, preset=preset)
            return enriched

        # Node 4: Cross-Filtered Active Slice for KPIs & 24h Patch Queue (isolated from ML!)
        @reactive.calc
        def focused_df() -> pd.DataFrame:
            df = triaged_df()
            if len(df) == 0:
                return df

            sb_layer = sidebar_state.focus_layer()
            c_layer = bus.layer.get()
            c_cwe = bus.cwe_family.get()
            c_vendor = bus.vendor.get()
            brushed = bus.brushed_cves.get()

            active_layers = [l for l in (c_layer, sb_layer if sb_layer != "All" else None) if l]
            return filter_by_scope(
                df,
                vendors=[c_vendor] if c_vendor else None,
                layers=active_layers if active_layers else None,
                cwe_families=[c_cwe] if c_cwe else None,
                cve_ids=brushed if brushed else None,
            )

        # Node 5: Single-Pass Shared Triage Metrics (computed ONCE for Banner + 4 KPIs)
        @reactive.calc
        def triage_metrics() -> TriageMetrics:
            return calculate_triage_metrics(
                focused_df(),
                cvss_cutoff=sidebar_state.cvss_cutoff(),
                epss_cutoff=sidebar_state.epss_cutoff(),
                pre_enriched=True,
            )

        treemap_reset_seq = reactive.Value(0)

        kpi_header_server(
            "kpi_header",
            metrics_calc=triage_metrics,
            total_raw_count=total_raw_records,
            vendor_count_calc=lambda: (len(sidebar_state.selected_vendors()), len(available_vendors)),
            cvss_cutoff_calc=sidebar_state.cvss_cutoff,
            epss_cutoff_calc=sidebar_state.epss_cutoff,
            cti_preset_calc=sidebar_state.cti_preset,
            focus_layer_calc=sidebar_state.focus_layer,
            bus=bus,
            on_reset_treemap=lambda: treemap_reset_seq.set(treemap_reset_seq.get() + 1),
        )

        triage_queue_server(
            "triage_queue",
            focused_df_calc=focused_df,
            bus=bus,
        )

        # Persistent FigureWidgets initialized once per session and updated in-place
        bubble_widget = go.FigureWidget()
        treemap_widget = go.FigureWidget()
        ridgeline_widget = go.FigureWidget()

        @output
        @render_plotly
        def plot_bubble() -> go.FigureWidget:
            return bubble_widget

        @output
        @render_plotly
        def plot_treemap() -> go.FigureWidget:
            return treemap_widget

        @output
        @render_plotly
        def plot_ridgeline() -> go.FigureWidget:
            return ridgeline_widget

        # Idiom 1: WebGL Prioritization Bubble Plot (reads ML ONLY when ML color mode is active)
        @reactive.effect
        def _sync_bubble_widget() -> None:
            df = triaged_df()
            color_mode = sidebar_state.color_by()

            if color_mode == "threat_cluster":
                res = ml_result()
                if res is not None and len(res.df) > 0 and len(df) > 0:
                    cluster_map = res.df.set_index("cve_id")["threat_cluster"]
                    df = df.copy()
                    df["threat_cluster"] = df["cve_id"].map(cluster_map).fillna("Unassigned")

            sb_layer = sidebar_state.focus_layer()
            effective_layer = bus.layer.get() or (sb_layer if sb_layer != "All" else None)

            fig = create_prioritization_bubble_plot(
                df,
                cvss_thresh=sidebar_state.cvss_cutoff(),
                epss_thresh=sidebar_state.epss_cutoff(),
                color_by=color_mode,
                y_scale=sidebar_state.y_scale(),
                focus_layer=effective_layer,
                focus_cwe=bus.cwe_family.get(),
                focus_vendor=bus.vendor.get(),
                highlighted_cves=bus.brushed_cves.get(),
                inspected_cve=bus.inspected_cve.get(),
                show_landmarks=sidebar_state.show_landmarks(),
                as_widget=False,
                show_title=False,
            )
            _sync_figure_widget(bubble_widget, fig)
            _attach_bubble_callbacks(bubble_widget, bus)

        # Idiom 2: Accessible Squarified Treemap (strictly isolated from ML & Y-scale & Landmarks!)
        @reactive.effect
        def _sync_treemap_widget() -> None:
            _ = treemap_reset_seq.get()
            df = triaged_df()
            brushed = bus.brushed_cves.get()
            if brushed:
                df = filter_by_scope(df, cve_ids=brushed)

            fig = create_architectural_treemap(
                df,
                metric=sidebar_state.treemap_metric(),
                as_widget=False,
                show_title=False,
            )
            _sync_figure_widget(treemap_widget, fig)
            _attach_treemap_callbacks(treemap_widget, bus)

        # Idiom 3: Sorted SLA Velocity Ridgeline (strictly isolated from CVSS/EPSS sliders & ML!)
        @reactive.effect
        def _sync_ridgeline_widget() -> None:
            df = scoped_df()
            fig = create_velocity_ridgeline_plot(
                df,
                max_days=120,
                highlight_vendor=bus.vendor.get(),
                as_widget=False,
            )
            _sync_figure_widget(ridgeline_widget, fig)
            _attach_ridgeline_callbacks(ridgeline_widget, bus)

    return App(app_ui, server)


app = create_app()

if __name__ == "__main__":
    app.run(port=8000)
