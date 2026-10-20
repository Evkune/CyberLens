import os
import pandas as pd
from shiny import App, render, ui, reactive
from shinywidgets import output_widget, render_plotly

from cyberlens.data_engine import (
    load_dataset,
    filter_by_enterprise_stack,
    filter_by_layers,
    classify_risk_quadrants,
    calculate_kpis
)
from cyberlens.ml_clustering import perform_threat_clustering
from cyberlens.idiom_bubble import create_prioritization_bubble_plot
from cyberlens.idiom_treemap import create_architectural_treemap
from cyberlens.idiom_ridgeline import create_velocity_ridgeline_plot

# Ingest and cache unified CVE dataset
RAW_DATA = load_dataset()
AVAILABLE_VENDORS = sorted(RAW_DATA["vendor"].unique().tolist())
AVAILABLE_LAYERS = sorted(RAW_DATA["layer"].unique().tolist())

app_ui = ui.page_fluid(
    ui.tags.head(
        ui.tags.style("""
            body { background-color: #0b1120; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
            .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; margin-bottom: 16px; padding: 14px; }
            .kpi-box { text-align: center; padding: 10px; border-radius: 8px; background-color: #0f172a; border: 1px solid #1e293b; }
            .kpi-title { font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600; letter-spacing: 0.5px; }
            .kpi-val { font-size: 24px; font-weight: 700; margin-top: 4px; }
            .sidebar-card { background-color: #111827; border: 1px solid #374151; border-radius: 10px; padding: 14px; }
        """)
    ),
    ui.panel_title(
        ui.div(
            ui.div(
                ui.h2("CyberLens: Vulnerability Threat Prioritization", style="margin-bottom: 2px; color: #38bdf8; font-weight: 700;"),
                ui.p("Threat-Informed Visual Analytics for Enterprise Attack Surface Management (Munzner Framework)", style="color: #94a3b8; font-size: 13px; margin: 0;"),
            ),
            ui.div(
                ui.span("Master Innovación Digital — UPM", class_="badge", style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid #0284c7; padding: 4px 10px; border-radius: 6px; font-size: 12px; margin-right: 8px;"),
                ui.span("Evan Gendrot (INSA)", class_="badge", style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #059669; padding: 4px 10px; border-radius: 6px; font-size: 12px;"),
                style="margin-top: 6px;"
            ),
            style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 12px; margin-bottom: 14px;"
        )
    ),
    ui.layout_sidebar(
        ui.sidebar(
            ui.h4("Enterprise Asset Scope", style="color: #38bdf8; font-size: 14px; font-weight: 700;"),
            ui.p("Filter vulnerabilities threatening your specific software inventory:", style="font-size: 11px; color: #94a3b8;"),
            ui.input_checkbox_group(
                "selected_vendors",
                "Software Vendors:",
                choices={v: v for v in AVAILABLE_VENDORS},
                selected=["Microsoft", "Linux", "Cisco", "Apache", "Fortinet"]
            ),
            ui.tags.hr(style="border-color: #334155; margin: 12px 0;"),
            ui.h4("Focus + Context (Shneiderman)", style="color: #38bdf8; font-size: 14px; font-weight: 700;"),
            ui.input_select(
                "focus_layer",
                "Isolate Architectural Tier:",
                choices=["All"] + AVAILABLE_LAYERS,
                selected="All"
            ),
            ui.input_switch("show_landmarks", "Show Case Study Landmarks", value=False),
            ui.tags.hr(style="border-color: #334155; margin: 12px 0;"),
            ui.h4("Operational Triage", style="color: #38bdf8; font-size: 14px; font-weight: 700;"),
            ui.input_slider("cvss_cutoff", "CVSS Triage Threshold:", min=4.0, max=9.5, value=7.0, step=0.1),
            ui.input_slider("epss_cutoff", "EPSS Weaponization Cutoff:", min=0.05, max=0.75, value=0.30, step=0.05),
            ui.tags.hr(style="border-color: #334155; margin: 12px 0;"),
            ui.h4("Threat Clustering (K-Means)", style="color: #38bdf8; font-size: 14px; font-weight: 700;"),
            ui.input_switch("enable_ml", "Enable K-Means Clustering", value=False),
            ui.panel_conditional(
                "input.enable_ml",
                ui.input_slider("k_clusters", "Number of Threat Archetypes (K):", min=3, max=6, value=4, step=1)
            ),
            width=280,
            bg="#0f172a"
        ),
        ui.div(
            # Active Triage State & Workload Compression Banner
            ui.output_ui("triage_status_banner"),
            # KPI Summary Row
            ui.row(
                ui.column(3, ui.div(ui.div("Enterprise CVE Scope", class_="kpi-title"), ui.output_ui("kpi_total"), class_="kpi-box")),
                ui.column(3, ui.div(ui.div("Active In-The-Wild (KEV)", class_="kpi-title"), ui.output_ui("kpi_kev"), class_="kpi-box")),
                ui.column(3, ui.div(ui.div("Imminent Weaponization", class_="kpi-title"), ui.output_ui("kpi_epss"), class_="kpi-box")),
                ui.column(3, ui.div(ui.div("Median Risk Profile", class_="kpi-title"), ui.output_ui("kpi_median"), class_="kpi-box")),
                style="margin-bottom: 14px;"
            ),
            # Top Visualization Row: Idiom 1 (Scatter) & Idiom 2 (Treemap)
            ui.row(
                ui.column(6, ui.div(output_widget("plot_bubble", height="460px"), class_="card")),
                ui.column(6, ui.div(output_widget("plot_treemap", height="460px"), class_="card"))
            ),
            # Bottom Visualization Row: Idiom 3 (Ridgeline Velocity)
            ui.row(
                ui.column(12, ui.div(output_widget("plot_ridgeline", height="340px"), class_="card"))
            ),
            # Methodology Footer Accordion
            ui.accordion(
                ui.accordion_panel(
                    "Methodological Rationale (Tamara Munzner Framework Compliance)",
                    ui.markdown("""
                    - **Domain & Persona:** Enterprise CISO & Lead Vulnerability Analyst managing heterogeneous infrastructure.
                    - **Task 1 (Bubble Plot):** *{Identify, Outliers & Correlation}* between theoretical severity (CVSS) and empirical weaponization (EPSS). Positions X and Y dominate the mental model (Rank #1 channel per Stevens' Law). Mark area quadratically scales with CVSS Impact.
                    - **Task 2 (Treemap):** *{Compare, Summarize, Structural Weakness Hierarchy}* across architectural layers (OS, Web, Network). Replaces redundant scatter plots with space-filling layout (Tables slide 64).
                    - **Task 3 (Ridgeline):** *{Discover, Compare, Continuous Weaponization Distributions}* across vendor cohorts (Tables slide 32). Completely rejects simplistic min/max SQL lookups in favor of continuous Kernel Density Estimation (KDE).
                    - **Interaction:** Global enterprise asset inventory filter, dynamic operational threshold crosshairs, and K-Means threat archetypes discovery.
                    """)
                ),
                id="acc_methodology"
            )
        )
    )
)

def server(input, output, session):
    
    @reactive.calc
    def filtered_df():
        vendors = input.selected_vendors()
        df = filter_by_enterprise_stack(RAW_DATA, vendors)
        if input.enable_ml():
            k = input.k_clusters()
            df, _ = perform_threat_clustering(df, n_clusters=k)
        return df

    # Dynamic Triage State & Workload Compression Banner
    @output
    @render.ui
    def triage_status_banner():
        df = filtered_df()
        total_raw = len(RAW_DATA)
        total_filtered = len(df)
        
        focus = input.focus_layer()
        vendors = input.selected_vendors()
        cvss_cutoff = input.cvss_cutoff()
        epss_cutoff = input.epss_cutoff()
        
        compliance_tickets = len(df[df["cvss_base"] >= cvss_cutoff])
        cyberlens_priority = len(df[df["is_kev"] | (df["epss_score"] >= epss_cutoff)])
        
        if compliance_tickets > 0:
            reduction_pct = max(0.0, (1.0 - (cyberlens_priority / compliance_tickets)) * 100)
            reduction_str = f"-{reduction_pct:.1f}% SOC Alert Reduction"
            reduction_color = "#10b981"
        else:
            reduction_str = "Balanced Triage"
            reduction_color = "#38bdf8"
            
        scope_desc = f"{len(vendors)} Vendors" if len(vendors) < len(AVAILABLE_VENDORS) else "All Enterprise Assets"
        layer_desc = f"Tier: {focus}" if focus != "All" else "All Tiers"
        
        return ui.div(
            ui.div(
                ui.span("Active Scope: ", style="color: #94a3b8; font-weight: 600;"),
                ui.span(f"{scope_desc} ➔ {layer_desc} ", style="color: #f8fafc; font-weight: 600;"),
                ui.span(f"({total_filtered:,} / {total_raw:,} CVEs in scope)", style="color: #38bdf8; font-size: 11px; margin-right: 12px;"),
                ui.span("| ", style="color: #475569; margin: 0 8px;"),
                ui.span(f"Compliance Baseline (CVSS ≥ {cvss_cutoff:.1f}): ", style="color: #94a3b8;"),
                ui.span(f"{compliance_tickets:,} tickets", style="color: #f1f5f9; font-weight: 700;"),
                ui.span(" ➔ ", style="color: #64748b;"),
                ui.span("CyberLens Priority: ", style="color: #94a3b8;"),
                ui.span(f"{cyberlens_priority:,} tickets ", style="color: #fbbf24; font-weight: 700;"),
                ui.span(f"({reduction_str})", style=f"color: {reduction_color}; font-weight: 700; font-size: 12px; background: rgba(16, 185, 129, 0.12); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(16, 185, 129, 0.3);")
            ),
            style="background: #0f172a; border: 1px solid #1e293b; border-left: 4px solid #38bdf8; border-radius: 6px; padding: 8px 14px; margin-bottom: 14px; font-size: 12px; display: flex; align-items: center; justify-content: space-between;"
        )

    # KPI Outputs
    @output
    @render.ui
    def kpi_total():
        kpis = calculate_kpis(filtered_df())
        return ui.span(f"{kpis['total_count']:,}", style="color: #38bdf8;", class_="kpi-val")

    @output
    @render.ui
    def kpi_kev():
        kpis = calculate_kpis(filtered_df())
        return ui.span(f"{kpis['kev_count']:,}", style="color: #ef4444;", class_="kpi-val")

    @output
    @render.ui
    def kpi_epss():
        kpis = calculate_kpis(filtered_df())
        return ui.span(f"{kpis['high_epss_count']:,}", style="color: #f59e0b;", class_="kpi-val")

    @output
    @render.ui
    def kpi_median():
        kpis = calculate_kpis(filtered_df())
        return ui.span(f"CVSS {kpis['median_cvss']} / EPSS {kpis['median_epss']:.1%}", style="color: #cbd5e1; font-size: 18px;", class_="kpi-val")

    # Idiom 1: Prioritization Bubble Plot
    @output
    @render_plotly
    def plot_bubble():
        df = filtered_df()
        cvss_t = input.cvss_cutoff()
        epss_t = input.epss_cutoff()
        focus = input.focus_layer()
        landmarks = input.show_landmarks()
        return create_prioritization_bubble_plot(
            df, 
            cvss_thresh=cvss_t, 
            epss_thresh=epss_t,
            focus_layer=None if focus == "All" else focus,
            show_landmarks=landmarks
        )

    # Idiom 2: Architectural Treemap
    @output
    @render_plotly
    def plot_treemap():
        df = filtered_df()
        return create_architectural_treemap(df, metric="threat_weight")

    # Idiom 3: Exploitation Velocity Ridgeline
    @output
    @render_plotly
    def plot_ridgeline():
        df = filtered_df()
        return create_velocity_ridgeline_plot(df, max_days=120)

app = App(app_ui, server)

if __name__ == "__main__":
    app.run(port=8000)
