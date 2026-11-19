from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from shiny import Inputs, Outputs, Session, module, reactive, render, ui

from cyberlens.config import (
    CORE_STACK_VENDORS,
    DEFAULT_CVSS_CUTOFF,
    DEFAULT_EPSS_CUTOFF,
    DEFAULT_SELECTED_VENDORS,
)
from cyberlens.domain.clustering import ClusteringResult

CTI_PRESET_CHOICES: Dict[str, str] = {
    "all": "All Scoped Vulnerabilities",
    "emergency_24h": "P0 Emergency (< 24h SLA)",
    "silent_threats": "Q2 Silent Threats (CVSS Blind Spots)",
    "ransomware_kev": "Confirmed Ransomware KEV",
    "epss_surge": "EPSS 30d Velocity Surges (Δ30d)",
    "kev_only": "All CISA KEV Exploits",
}

BUBBLE_COLOR_MODES: Dict[str, str] = {
    "sla_tier": "SLA Triage Tier (P0–P4)",
    "threat_cluster": "K-Means Threat Archetype",
    "epss_velocity": "EPSS 30d Velocity (ΔSurge)",
}

TREEMAP_METRIC_CHOICES: Dict[str, str] = {
    "expected_risk": "Expected Risk (CVSS × P_eff)",
    "actionable_count": "Actionable Queue (P0–P2)",
    "kev_count": "Confirmed CISA KEV",
}


@dataclass(frozen=True)
class SidebarState:
    selected_vendors: Callable[[], List[str]]
    cti_preset: Callable[[], str]
    focus_layer: Callable[[], str]
    cvss_cutoff: Callable[[], float]
    epss_cutoff: Callable[[], float]
    color_by: Callable[[], str]
    y_scale: Callable[[], str]
    treemap_metric: Callable[[], str]
    show_landmarks: Callable[[], bool]
    enable_ml: Callable[[], bool]
    k_clusters: Callable[[], int]


@module.ui
def sidebar_ui(
    available_vendors: List[str],
    available_layers: List[str],
    default_vendors: Optional[List[str]] = None,
) -> ui.Sidebar:
    initial_vendors = [
        v for v in (default_vendors or DEFAULT_SELECTED_VENDORS) if v in available_vendors
    ] or available_vendors

    return ui.sidebar(
        ui.div("Triage Preset", class_="sidebar-section-title"),
        ui.input_select(
            "cti_preset",
            "Rapid Triage Lens:",
            choices=CTI_PRESET_CHOICES,
            selected="all",
        ),
        ui.tags.hr(class_="sidebar-divider"),
        ui.div("Operational Triage Cutoffs", class_="sidebar-section-title"),
        ui.input_slider(
            "cvss_cutoff",
            "CVSS Severity Cutoff (τ_CVSS):",
            min=4.0,
            max=9.5,
            value=DEFAULT_CVSS_CUTOFF,
            step=0.1,
        ),
        ui.input_slider(
            "epss_cutoff",
            "EPSS Weaponization Cutoff (τ_EPSS):",
            min=0.05,
            max=0.75,
            value=DEFAULT_EPSS_CUTOFF,
            step=0.05,
        ),
        ui.tags.hr(class_="sidebar-divider"),
        ui.div("Visual Encoding & Focus", class_="sidebar-section-title"),
        ui.input_select(
            "color_by",
            "Bubble Color Channel:",
            choices=BUBBLE_COLOR_MODES,
            selected="sla_tier",
        ),
        ui.input_radio_buttons(
            "y_scale",
            "Bubble EPSS Y-Axis Scale:",
            choices={"linear": "Linear [0–100%]", "log": "Log10 (Tail Detail)"},
            selected="linear",
            inline=True,
        ),
        ui.input_select(
            "treemap_metric",
            "Treemap Surface Area Metric:",
            choices=TREEMAP_METRIC_CHOICES,
            selected="expected_risk",
        ),
        ui.input_select(
            "focus_layer",
            "Isolate Architectural Tier:",
            choices=["All"] + list(available_layers),
            selected="All",
        ),
        ui.input_switch("show_landmarks", "Pin Reference Landmarks", value=True),
        ui.tags.hr(class_="sidebar-divider"),
        ui.div("5D Threat Clustering (K-Means++)", class_="sidebar-section-title"),
        ui.input_switch("enable_ml", "Enable 5D Logit K-Means", value=False),
        ui.panel_conditional(
            "input.enable_ml",
            ui.input_slider(
                "k_clusters",
                "Threat Archetypes (K):",
                min=3,
                max=6,
                value=4,
                step=1,
            ),
            ui.output_ui("ml_quality_card"),
        ),
        ui.tags.hr(class_="sidebar-divider"),
        ui.div("Enterprise Asset Inventory", class_="sidebar-section-title"),
        ui.div(
            ui.input_action_button(
                "btn_select_all_vendors",
                "All Vendors",
                class_="btn-swiss",
                style="margin-right: 4px;",
            ),
            ui.input_action_button(
                "btn_default_vendors",
                "Core Stack",
                class_="btn-swiss",
            ),
            style="margin-bottom: 6px;",
        ),
        ui.input_checkbox_group(
            "selected_vendors",
            "Monitored Software Vendors:",
            choices={v: v for v in available_vendors},
            selected=initial_vendors,
        ),
        width=295,
        bg="#FAFAFA",
    )


@module.server
def sidebar_server(
    input: Inputs,
    output: Outputs,
    session: Session,
    available_vendors: List[str],
    ml_result_calc: Callable[[], Optional[ClusteringResult]],
) -> SidebarState:
    @reactive.effect
    @reactive.event(input.btn_select_all_vendors)
    def _select_all() -> None:
        ui.update_checkbox_group("selected_vendors", selected=available_vendors)

    @reactive.effect
    @reactive.event(input.btn_default_vendors)
    def _select_defaults() -> None:
        defaults = [v for v in CORE_STACK_VENDORS if v in available_vendors] or available_vendors
        ui.update_checkbox_group("selected_vendors", selected=defaults)

    @reactive.effect
    @reactive.event(input.enable_ml)
    def _sync_ml_color_channel() -> None:
        if input.enable_ml():
            ui.update_select("color_by", selected="threat_cluster")
        elif input.color_by() == "threat_cluster":
            ui.update_select("color_by", selected="sla_tier")

    @output
    @render.ui
    def ml_quality_card() -> ui.Tag:
        if not input.enable_ml():
            return ui.div()
        res = ml_result_calc()
        if res is None or res.n_clusters == 0:
            return ui.div("Insufficient records for clustering.", class_="ml-summary-box")

        rows = []
        for c_id in sorted(res.profiles.keys()):
            prof = res.profiles[c_id]
            short_name = str(prof.get("name", f"Cluster {c_id}")).split("(")[0].strip()
            rows.append(
                ui.div(
                    ui.span(f"{short_name}: ", style="font-weight: 700; color: #09090B;"),
                    ui.span(
                        f"n={prof['count']:,} · CVSS {prof['mean_cvss']:.1f} · EPSS {prof['mean_epss']:.1%}",
                        class_="mono-num",
                        style="color: #52525B;",
                    ),
                    style="font-size: 10.5px; margin-top: 2px;",
                )
            )

        return ui.div(
            ui.div(
                ui.span("5D Model Diagnostics", style="font-weight: 700; color: #09090B;"),
                ui.span(
                    f"K={res.n_clusters} | Silhouette: {res.silhouette:.3f} | DBI: {res.davies_bouldin:.2f}",
                    class_="mono-num",
                    style="display: block; color: #52525B; font-size: 10.5px; margin-top: 2px;",
                ),
                style="border-bottom: 1px solid #E4E4E7; padding-bottom: 4px; margin-bottom: 4px;",
            ),
            *rows,
            class_="ml-summary-box",
        )

    return SidebarState(
        selected_vendors=lambda: list(input.selected_vendors() or []),
        cti_preset=lambda: str(input.cti_preset() or "all"),
        focus_layer=lambda: str(input.focus_layer() or "All"),
        cvss_cutoff=lambda: float(input.cvss_cutoff()),
        epss_cutoff=lambda: float(input.epss_cutoff()),
        color_by=lambda: str(input.color_by() or "sla_tier"),
        y_scale=lambda: str(input.y_scale() or "linear"),
        treemap_metric=lambda: str(input.treemap_metric() or "expected_risk"),
        show_landmarks=lambda: bool(input.show_landmarks()),
        enable_ml=lambda: bool(input.enable_ml()),
        k_clusters=lambda: int(input.k_clusters()),
    )
