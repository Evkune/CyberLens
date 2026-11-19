from __future__ import annotations

import io
from typing import Callable, Iterator

import numpy as np
import pandas as pd
from shiny import Inputs, Outputs, Session, module, reactive, render, ui

from cyberlens.config import SLA_TIER_ORDER
from cyberlens.domain.prioritization import enrich_prioritization, rank_action_queue
from cyberlens.ui.mod_kpi_header import CrossFilterBus
from cyberlens.ui.styles import get_sla_badge_style

QUEUE_SCOPE_CHOICES = {
    "urgent_24_72h": "Immediate 24h / 72h Surge (P0–P1)",
    "actionable_p0_p2": "Actionable SLA Queue (P0–P2)",
    "all_scoped": "All Scoped CVEs (P0–P4)",
}


def format_action_queue_table(ranked_df: pd.DataFrame) -> pd.DataFrame:
    """Formats a ranked RBVM dataframe into a clean, NaN-free operational table for DataGrid display."""
    if len(ranked_df) == 0:
        return pd.DataFrame(
            columns=[
                "SLA Tier",
                "CVE ID",
                "Vendor",
                "Product",
                "CVSS",
                "EPSS",
                "Δ30d",
                "Threat Signal",
                "Blind-Spot",
                "Vector",
                "Layer",
                "KEV Lag",
            ]
        )

    is_kev = ranked_df["is_kev"].to_numpy(dtype=bool, na_value=False)
    is_ransom = (
        ranked_df["is_ransomware"].to_numpy(dtype=bool, na_value=False)
        if "is_ransomware" in ranked_df.columns
        else np.zeros(len(ranked_df), dtype=bool)
    )
    is_surge = (
        ranked_df["is_epss_surge"].to_numpy(dtype=bool, na_value=False)
        if "is_epss_surge" in ranked_df.columns
        else np.zeros(len(ranked_df), dtype=bool)
    )

    signal = np.select(
        [is_kev & is_ransom, is_kev, is_surge],
        ["KEV · RANSOMWARE", "CISA KEV", "EPSS Surge"],
        default="Standard",
    )

    epss_pct = pd.to_numeric(ranked_df["epss_score"], errors="coerce").fillna(0.0).to_numpy() * 100.0
    delta_pct = (
        pd.to_numeric(ranked_df["epss_delta_30d"], errors="coerce").fillna(0.0).to_numpy() * 100.0
        if "epss_delta_30d" in ranked_df.columns
        else np.zeros(len(ranked_df), dtype=float)
    )
    blindspot = (
        pd.to_numeric(ranked_df["blindspot_score"], errors="coerce").fillna(0.0).to_numpy()
        if "blindspot_score" in ranked_df.columns
        else np.zeros(len(ranked_df), dtype=float)
    )
    lag_col = (
        ranked_df["days_to_exploit_display"].astype(str).to_numpy()
        if "days_to_exploit_display" in ranked_df.columns
        else np.full(len(ranked_df), "N/A", dtype=object)
    )

    return pd.DataFrame(
        {
            "SLA Tier": ranked_df["sla_tier"].astype(str).to_numpy(),
            "CVE ID": ranked_df["cve_id"].astype(str).to_numpy(),
            "Vendor": ranked_df["vendor"].astype(str).to_numpy(),
            "Product": ranked_df["product"].astype(str).to_numpy(),
            "CVSS": pd.to_numeric(ranked_df["cvss_base"], errors="coerce").fillna(0.0).round(1).to_numpy(),
            "EPSS": np.char.mod("%.1f%%", epss_pct),
            "Δ30d": np.char.mod("%+.1f%%", delta_pct),
            "Threat Signal": signal,
            "Blind-Spot": np.char.mod("%.2f", blindspot),
            "Vector": ranked_df["attack_vector"].astype(str).to_numpy(),
            "Layer": ranked_df["layer"].astype(str).to_numpy(),
            "KEV Lag": lag_col,
        }
    )


@module.ui
def triage_queue_ui() -> ui.TagChild:
    return ui.div(
        ui.div(
            ui.div(
                ui.span(
                    "Operational Patch Queue & CVE Inspector",
                    class_="card-header-title",
                ),
                ui.span(
                    " — Select any row to inspect details and pin on the scatter plot",
                    class_="card-header-hint",
                ),
            ),
            ui.div(
                ui.input_radio_buttons(
                    "queue_filter_mode",
                    None,
                    choices=QUEUE_SCOPE_CHOICES,
                    selected="actionable_p0_p2",
                    inline=True,
                ),
                ui.download_button(
                    "download_action_queue_csv",
                    "Export Action Queue (CSV)",
                    class_="btn-swiss-dark",
                    style="margin-left: 10px; white-space: nowrap; flex-shrink: 0;",
                ),
                style="display: flex; flex-wrap: wrap; align-items: center; gap: 10px;",
            ),
            class_="card-header-bar",
        ),
        ui.row(
            ui.div(
                ui.output_data_frame("triage_grid"),
                class_="col-12 col-xl-8",
            ),
            ui.div(
                ui.output_ui("cve_inspector_drawer"),
                class_="col-12 col-xl-4",
            ),
        ),
        class_="soc-section soc-section-bordered",
    )


@module.server
def triage_queue_server(
    input: Inputs,
    output: Outputs,
    session: Session,
    focused_df_calc: Callable[[], pd.DataFrame],
    bus: CrossFilterBus,
) -> None:
    @reactive.calc
    def active_queue_df() -> pd.DataFrame:
        df = focused_df_calc()
        if len(df) == 0:
            return df
        work = df if "sla_tier" in df.columns else enrich_prioritization(df)
        mode = input.queue_filter_mode() or "actionable_p0_p2"
        if mode == "urgent_24_72h":
            sub = work.loc[work["sla_tier"].isin(SLA_TIER_ORDER[:2])]
            if len(sub) > 0:
                work = sub
        elif mode == "actionable_p0_p2":
            sub = work.loc[work["is_actionable"].astype(bool)]
            if len(sub) > 0:
                work = sub
        return rank_action_queue(work)

    @output
    @render.data_frame
    def triage_grid() -> render.DataGrid:
        display_df = format_action_queue_table(active_queue_df())
        return render.DataGrid(
            display_df,
            selection_mode="row",
            filters=True,
            summary=True,
            height="360px",
            width="100%",
        )

    @reactive.effect
    def _sync_grid_selection_to_bus() -> None:
        sel = triage_grid.cell_selection()
        if not sel:
            return
        rows = sel.get("rows", ())
        if not rows:
            return
        ranked = active_queue_df()
        row_idx = int(rows[0])
        if 0 <= row_idx < len(ranked):
            cve_id = str(ranked.iloc[row_idx]["cve_id"])
            bus.inspected_cve.set(cve_id)

    @reactive.effect
    @reactive.event(input.btn_pin_top_cve)
    def _pin_current_preview() -> None:
        ranked = active_queue_df()
        if len(ranked) > 0 and bus.inspected_cve.get() is None:
            bus.inspected_cve.set(str(ranked.iloc[0]["cve_id"]))

    @reactive.effect
    @reactive.event(input.btn_unpin_cve)
    def _clear_pinned_cve() -> None:
        bus.inspected_cve.set(None)

    @output
    @render.ui
    def cve_inspector_drawer() -> ui.Tag:
        df_full = focused_df_calc()
        ranked = active_queue_df()
        if len(df_full) == 0 or len(ranked) == 0:
            return ui.div(
                ui.h5("CVE Inspector", style="color: #09090B; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;"),
                ui.p(
                    "No vulnerabilities in the current filter scope.",
                    style="color: #52525B; font-size: 12px;",
                ),
                class_="cve-inspector-card",
            )

        pinned_id = bus.inspected_cve.get()
        is_explicit_pin = False
        if pinned_id and (df_full["cve_id"] == pinned_id).any():
            record = df_full.loc[df_full["cve_id"] == pinned_id].iloc[0]
            is_explicit_pin = True
        else:
            record = ranked.iloc[0]

        cve_id = str(record["cve_id"])
        vendor = str(record["vendor"])
        product = str(record["product"])
        layer = str(record["layer"])
        cwe_id = str(record.get("cwe_id", "N/A"))
        cwe_family = str(record["cwe_family"])
        sla_tier = str(record["sla_tier"])
        quadrant = str(record.get("risk_quadrant", ""))
        cvss_base = float(record["cvss_base"])
        cvss_impact = float(record["cvss_impact"])
        epss_score = float(record["epss_score"])
        epss_delta = float(record.get("epss_delta_30d", 0.0))
        blindspot = float(record.get("blindspot_score", 0.0))
        days_lag = str(record.get("days_to_exploit_display", "N/A"))
        av = str(record["attack_vector"])
        ac = str(record.get("attack_complexity", "Low"))
        pr = str(record["privileges_required"])
        is_kev = bool(record["is_kev"])
        is_ransom = bool(record.get("is_ransomware", False))
        req_action = str(record.get("kev_required_action", "") or "").strip()
        desc = str(record.get("description", "") or "").strip()
        disclosure_date = str(record.get("disclosure_date", "N/A") or "N/A")[:10]

        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        cisa_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

        status_pill = (
            ui.span(
                "Pinned on Plot",
                style="background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; padding: 2px 7px; border-radius: 3px; font-size: 10.5px; font-weight: 700;",
            )
            if is_explicit_pin
            else ui.span(
                "Top Priority Preview",
                style="background: #FFFFFF; color: #52525B; border: 1px solid #E4E4E7; padding: 2px 7px; border-radius: 3px; font-size: 10.5px; font-weight: 600;",
            )
        )

        pin_control = (
            ui.input_action_button(
                "btn_unpin_cve",
                "Unpin from Plot",
                class_="btn-swiss",
            )
            if is_explicit_pin
            else ui.input_action_button(
                "btn_pin_top_cve",
                "Pin on Plot",
                class_="btn-swiss",
            )
        )

        kev_box = (
            ui.div(
                ui.div(
                    ui.span(
                        "CISA KEV MANDATE" + (" · RANSOMWARE CAMPAIGN" if is_ransom else ""),
                        style="color: #B91C1C; font-weight: 700; font-size: 11px;",
                    )
                ),
                ui.div(
                    req_action
                    or "Apply vendor remediation patch immediately per BOD 22-01 directive.",
                    style="color: #7F1D1D; margin-top: 2px;",
                ),
                class_="cve-action-box",
            )
            if is_kev
            else ui.div()
        )

        return ui.div(
            ui.div(
                ui.div(
                    ui.span(
                        cve_id,
                        class_="mono-num",
                        style="font-size: 15px; font-weight: 700; color: #09090B; margin-right: 8px;",
                    ),
                    ui.span(sla_tier, style=get_sla_badge_style(sla_tier)),
                ),
                status_pill,
                style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 4px;",
            ),
            ui.div(
                f"{vendor} · {product} (Disclosed: {disclosure_date})",
                style="font-size: 12px; color: #09090B; font-weight: 600; margin-top: 6px;",
            ),
            ui.div(
                quadrant,
                style="font-size: 11px; color: #52525B; margin-top: 2px;",
            ),
            ui.div(
                ui.div(
                    ui.div("CVSS v3.1 / Impact", class_="cve-meta-label"),
                    ui.div(f"{cvss_base:.1f} / {cvss_impact:.1f}", class_="cve-meta-val"),
                    class_="cve-meta-item",
                ),
                ui.div(
                    ui.div("EPSS (30d) / Δ30d", class_="cve-meta-label"),
                    ui.div(f"{epss_score:.1%} ({epss_delta:+.1%})", class_="cve-meta-val"),
                    class_="cve-meta-item",
                ),
                ui.div(
                    ui.div("Blind-Spot / KEV Lag", class_="cve-meta-label"),
                    ui.div(f"{blindspot:.2f} · Lag: {days_lag}", class_="cve-meta-val"),
                    class_="cve-meta-item",
                ),
                ui.div(
                    ui.div("Vector / AC / Privs", class_="cve-meta-label"),
                    ui.div(f"{av} / {ac} / {pr}", class_="cve-meta-val"),
                    class_="cve-meta-item",
                ),
                ui.div(
                    ui.div("Architectural Tier", class_="cve-meta-label"),
                    ui.div(layer, class_="cve-meta-val"),
                    class_="cve-meta-item",
                ),
                ui.div(
                    ui.div("MITRE Weakness", class_="cve-meta-label"),
                    ui.div(f"{cwe_id} · {cwe_family.split('(')[0].strip()}", class_="cve-meta-val"),
                    class_="cve-meta-item",
                ),
                class_="cve-meta-grid",
            ),
            kev_box,
            ui.div(
                desc[:240] + ("..." if len(desc) > 240 else "")
                if desc
                else "Unified vulnerability record from NVD / FIRST EPSS / CISA KEV snapshot.",
                style="font-size: 11px; color: #52525B; margin-top: 8px; line-height: 1.45;",
            ),
            ui.div(
                ui.tags.a(
                    "NVD Advisory (nist.gov)",
                    href=nvd_url,
                    target="_blank",
                    rel="noopener noreferrer",
                    class_="external-link-btn",
                ),
                ui.tags.a(
                    "CISA KEV Catalog",
                    href=cisa_url,
                    target="_blank",
                    rel="noopener noreferrer",
                    class_="external-link-btn",
                ),
                pin_control,
                style="margin-top: 10px; display: flex; flex-wrap: wrap; align-items: center; gap: 6px;",
            ),
            class_="cve-inspector-card",
        )

    @render.download_button(filename="cyberlens_soc_patch_queue.csv")
    def download_action_queue_csv() -> Iterator[str]:
        ranked = active_queue_df()
        export_cols = [
            "sla_tier",
            "sla_target_hours",
            "cve_id",
            "vendor",
            "product",
            "layer",
            "cwe_id",
            "cwe_family",
            "cvss_base",
            "cvss_impact",
            "epss_score",
            "epss_delta_30d",
            "is_kev",
            "is_ransomware",
            "is_silent_threat",
            "blindspot_score",
            "expected_risk",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "days_to_exploit_display",
            "kev_required_action",
        ]
        available_cols = [c for c in export_cols if c in ranked.columns]
        buf = io.StringIO()
        ranked[available_cols].to_csv(buf, index=False)
        yield buf.getvalue()
