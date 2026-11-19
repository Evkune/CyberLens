from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from shiny import Inputs, Outputs, Session, module, reactive, render, ui

from cyberlens.domain.metrics import TriageMetrics
from cyberlens.ui.mod_sidebar import CTI_PRESET_CHOICES


@dataclass
class CrossFilterBus:
    layer: reactive.Value[Optional[str]]
    cwe_family: reactive.Value[Optional[str]]
    vendor: reactive.Value[Optional[str]]
    brushed_cves: reactive.Value[Optional[Tuple[str, ...]]]
    inspected_cve: reactive.Value[Optional[str]]

    def reset_all(self) -> None:
        self.layer.set(None)
        self.cwe_family.set(None)
        self.vendor.set(None)
        self.brushed_cves.set(None)
        self.inspected_cve.set(None)

    def has_active_filters(self) -> bool:
        return any(
            [
                self.layer.get() is not None,
                self.cwe_family.get() is not None,
                self.vendor.get() is not None,
                self.brushed_cves.get() is not None,
                self.inspected_cve.get() is not None,
            ]
        )


def create_cross_filter_bus() -> CrossFilterBus:
    return CrossFilterBus(
        layer=reactive.Value(None),
        cwe_family=reactive.Value(None),
        vendor=reactive.Value(None),
        brushed_cves=reactive.Value(None),
        inspected_cve=reactive.Value(None),
    )


@module.ui
def kpi_header_ui() -> ui.TagChild:
    return ui.div(
        ui.output_ui("little_law_banner"),
        ui.output_ui("filter_chips_bar"),
        ui.div(
            ui.div(
                ui.div("Immediate SLA Queue (24h / 72h)", class_="kpi-title"),
                ui.output_ui("kpi_urgent"),
                class_="kpi-cell",
            ),
            ui.div(
                ui.div("Active In-The-Wild (CISA KEV)", class_="kpi-title"),
                ui.output_ui("kpi_kev"),
                class_="kpi-cell",
            ),
            ui.div(
                ui.div("Silent Threats (CVSS Blind Spots)", class_="kpi-title"),
                ui.output_ui("kpi_silent"),
                class_="kpi-cell",
            ),
            ui.div(
                ui.div("Workload Compression", class_="kpi-title"),
                ui.output_ui("kpi_compression"),
                class_="kpi-cell",
            ),
            class_="kpi-strip",
        ),
    )


@module.server
def kpi_header_server(
    input: Inputs,
    output: Outputs,
    session: Session,
    metrics_calc: Callable[[], TriageMetrics],
    total_raw_count: int,
    vendor_count_calc: Callable[[], Tuple[int, int]],
    cvss_cutoff_calc: Callable[[], float],
    epss_cutoff_calc: Callable[[], float],
    cti_preset_calc: Callable[[], str],
    focus_layer_calc: Callable[[], str],
    bus: CrossFilterBus,
    on_reset_sidebar_focus: Optional[Callable[[], None]] = None,
    on_reset_treemap: Optional[Callable[[], None]] = None,
) -> None:
    @reactive.effect
    @reactive.event(input.btn_reset_cross_filters)
    def _handle_reset() -> None:
        bus.reset_all()
        if on_reset_sidebar_focus is not None:
            on_reset_sidebar_focus()
        if on_reset_treemap is not None:
            on_reset_treemap()

    @output
    @render.ui
    def little_law_banner() -> ui.Tag:
        m = metrics_calc()
        sel_v, tot_v = vendor_count_calc()
        cvss_t = cvss_cutoff_calc()
        epss_t = epss_cutoff_calc()

        scope_desc = f"{sel_v}/{tot_v} Enterprise Vendors" if sel_v < tot_v else "All Enterprise Vendors"
        if m.compliance_tickets > 0:
            reduction_str = f"-{m.alert_reduction_pct:.1f}% Queue Compression"
        else:
            reduction_str = "Balanced Queue"

        missed_kev_pct = max(0.0, 100.0 - m.compliance_kev_capture_pct)

        return ui.div(
            ui.div(
                ui.span("Triage Policy Comparison: ", style="color: #09090B; font-weight: 700;"),
                ui.span(f"{scope_desc} ", style="color: #09090B; font-weight: 600;"),
                ui.span(
                    f"({m.total_count:,} / {total_raw_count:,} CVEs)",
                    class_="mono-num",
                    style="color: #52525B; font-size: 11px; margin-right: 8px;",
                ),
                ui.span("|", style="color: #E4E4E7; margin: 0 6px;"),
                ui.span(f"CVSS-Only Policy (>= {cvss_t:.1f}): ", style="color: #52525B;"),
                ui.span(
                    f"{m.compliance_tickets:,} tickets",
                    class_="mono-num",
                    style="color: #09090B; font-weight: 700;",
                ),
                ui.span(
                    f" (misses {missed_kev_pct:.0f}% of KEVs)",
                    class_="mono-num",
                    style="color: #B91C1C; font-size: 11px; font-weight: 600;",
                ),
                ui.span(" / ", style="color: #E4E4E7; margin: 0 6px;"),
                ui.span(f"Actionable (P0–P2 @ EPSS >= {epss_t:.0%}): ", style="color: #52525B;"),
                ui.span(
                    f"{m.actionable_tickets:,} tickets ",
                    class_="mono-num",
                    style="color: #09090B; font-weight: 700;",
                ),
                ui.span(
                    f"({reduction_str} · 100% KEV Recall)",
                    class_="mono-num",
                    style=(
                        "color: #09090B; font-weight: 600; font-size: 11px; "
                        "background: #F4F4F5; padding: 2px 7px; "
                        "border-radius: 3px; border: 1px solid #E4E4E7;"
                    ),
                ),
            ),
            class_="little-law-banner",
        )

    @output
    @render.ui
    def filter_chips_bar() -> ui.Tag:
        preset = cti_preset_calc()
        sidebar_layer = focus_layer_calc()
        c_layer = bus.layer.get()
        c_cwe = bus.cwe_family.get()
        c_vendor = bus.vendor.get()
        brushed = bus.brushed_cves.get()
        pinned = bus.inspected_cve.get()

        chips = []
        if preset != "all":
            chips.append(
                ui.span(
                    f"Preset: {CTI_PRESET_CHOICES.get(preset, preset)}",
                    class_="filter-chip chip-preset",
                )
            )
        if sidebar_layer and sidebar_layer != "All":
            chips.append(ui.span(f"Sidebar Tier: {sidebar_layer}", class_="filter-chip"))
        if c_layer:
            chips.append(ui.span(f"Treemap Layer: {c_layer}", class_="filter-chip"))
        if c_cwe:
            chips.append(ui.span(f"Treemap CWE: {c_cwe}", class_="filter-chip"))
        if c_vendor:
            chips.append(ui.span(f"Focused Vendor: {c_vendor}", class_="filter-chip"))
        if brushed:
            chips.append(ui.span(f"Lasso Selection: {len(brushed):,} CVEs", class_="filter-chip mono-num"))
        if pinned:
            chips.append(ui.span(f"Pinned CVE: {pinned}", class_="filter-chip chip-pin mono-num"))

        if not chips:
            return ui.div(
                ui.div(
                    ui.span(
                        "Cross-Filter Ready: ",
                        style="color: #09090B; font-weight: 700;",
                    ),
                    ui.span(
                        "Click any Treemap tile, lasso-select bubbles, or select a table row to synchronize views.",
                        style="color: #52525B;",
                    ),
                ),
                class_="filter-chips-bar",
            )

        return ui.div(
            ui.div(
                ui.span("Active Cross-Filters: ", style="color: #52525B; font-weight: 700; margin-right: 8px;"),
                *chips,
            ),
            ui.input_action_button(
                "btn_reset_cross_filters",
                "Reset Cross-Filters",
                class_="btn-swiss",
            ),
            class_="filter-chips-bar",
        )

    @output
    @render.ui
    def kpi_urgent() -> ui.Tag:
        m = metrics_calc()
        return ui.div(
            ui.div(f"{m.urgent_24_72h_count:,}", style="color: #B91C1C;", class_="kpi-val"),
            ui.div(
                f"P0 (<24h): {m.p0_emergency_count:,} · P1 (<72h): {m.p1_urgent_count:,}",
                class_="kpi-sub",
            ),
        )

    @output
    @render.ui
    def kpi_kev() -> ui.Tag:
        m = metrics_calc()
        return ui.div(
            ui.div(f"{m.kev_count:,}", style="color: #B91C1C;", class_="kpi-val"),
            ui.div(
                f"Ransomware: {m.ransomware_kev_count:,} · P50 Lag: "
                f"{f'{m.median_days_to_exploit:.0f}d' if m.median_days_to_exploit is not None else 'N/A'}",
                class_="kpi-sub",
            ),
        )

    @output
    @render.ui
    def kpi_silent() -> ui.Tag:
        m = metrics_calc()
        return ui.div(
            ui.div(f"{m.silent_threats_count:,}", style="color: #B45309;", class_="kpi-val"),
            ui.div(
                f"Low-CVSS blind spots · 30d Surges: {m.epss_surge_count:,}",
                class_="kpi-sub",
            ),
        )

    @output
    @render.ui
    def kpi_compression() -> ui.Tag:
        m = metrics_calc()
        return ui.div(
            ui.div(f"-{m.alert_reduction_pct:.1f}%", style="color: #09090B;", class_="kpi-val"),
            ui.div(
                f"{m.actionable_tickets:,} actionable vs {m.compliance_tickets:,} CVSS-only ({m.p3_paper_tigers_count:,} deferred)",
                class_="kpi-sub",
            ),
        )
