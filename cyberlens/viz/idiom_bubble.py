from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from cyberlens.config import (
    DEFAULT_CVSS_CUTOFF,
    DEFAULT_EPSS_CUTOFF,
    SLA_TIER_ORDER,
)
from cyberlens.domain.clustering import perform_threat_clustering
from cyberlens.domain.prioritization import enrich_prioritization
from cyberlens.viz.theme import (
    ACCENT_PRIMARY,
    CONTEXT_GHOST_COLOR,
    CONTEXT_GHOST_OPACITY,
    GRID_COLOR,
    SLA_TIER_STYLES,
    TEXT_MUTED,
    TEXT_PRIMARY,
    VELOCITY_DIVERGING_SCALE,
    ZERO_LINE_COLOR,
    apply_swiss_light_layout,
    get_cluster_style,
    maybe_figure_widget,
)

# Stevens' Power Law area calibration: Area = A_min + k * (CVSS_Impact)^0.7
STEVENS_A_MIN = 28.27
STEVENS_K_SCALE = 167.61
STEVENS_EXPONENT = 0.7
MAX_BUBBLE_DIAMETER_PX = 28.0


def _compute_safe_offsets(x_val: float, y_val: float, y_scale: str = "linear") -> Tuple[int, int]:
    """Adaptive pixel offsets (ax, ay) preventing landmark callouts from clipping outside the plot canvas."""
    if x_val >= 8.0:
        ax = -72
    elif x_val <= 3.2:
        ax = 72
    elif x_val >= 6.5:
        ax = -58
    else:
        ax = 58

    if y_scale == "log":
        log_y = np.log10(max(y_val, 1e-4))
        ay = 46 if log_y > -0.45 else (-46 if log_y < -2.5 else -40)
    else:
        ay = 46 if y_val >= 0.76 else (-46 if y_val <= 0.18 else -42)
    return ax, ay


def _annotation_y(y_val: float, y_scale: str) -> float:
    clipped = max(float(y_val), 1e-4)
    return float(np.log10(clipped)) if y_scale == "log" else float(y_val)


def _build_marker_symbols(df: pd.DataFrame) -> np.ndarray:
    is_kev = df["is_kev"].to_numpy(dtype=bool, na_value=False)
    is_ransom = (
        df["is_ransomware"].to_numpy(dtype=bool, na_value=False)
        if "is_ransomware" in df.columns
        else np.zeros(len(df), dtype=bool)
    )
    is_surge = (
        df["is_epss_surge"].to_numpy(dtype=bool, na_value=False)
        if "is_epss_surge" in df.columns
        else np.zeros(len(df), dtype=bool)
    )
    return np.select(
        [is_kev & is_ransom, is_surge],
        ["diamond", "triangle-up"],
        default="circle",
    )


def _build_clean_customdata(sub: pd.DataFrame) -> np.ndarray:
    cve_id = sub["cve_id"].astype(str).fillna("Unknown").to_numpy()
    vendor = sub["vendor"].astype(str).fillna("Unknown").to_numpy()
    product = sub["product"].astype(str).fillna("Unknown").to_numpy()
    cwe_family = sub["cwe_family"].astype(str).fillna("Uncategorized").to_numpy()
    layer = sub["layer"].astype(str).fillna("Uncategorized").to_numpy()
    vector = sub["attack_vector"].astype(str).fillna("Unknown").to_numpy()
    privs = sub["privileges_required"].astype(str).fillna("Unknown").to_numpy()

    impact_vals = pd.to_numeric(sub["cvss_impact"], errors="coerce").fillna(0.0).to_numpy()
    impact_str = np.char.mod("%.1f", impact_vals)

    if "days_to_exploit_display" in sub.columns:
        raw_days = sub["days_to_exploit_display"].astype(str).to_numpy()
        days_str = np.where(
            (raw_days == "N/A") | (raw_days == "nan") | (raw_days == "None"),
            "N/A (Not in KEV)",
            raw_days,
        )
    elif "days_to_exploit" in sub.columns:
        d_series = pd.to_numeric(sub["days_to_exploit"], errors="coerce")
        valid = d_series.notna().to_numpy()
        days_str = np.full(len(sub), "N/A (Not in KEV)", dtype=object)
        if valid.any():
            days_str[valid] = (d_series[valid].round().astype(int).astype(str) + "d").to_numpy()
    else:
        days_str = np.full(len(sub), "N/A (Not in KEV)", dtype=object)

    delta_vals = (
        pd.to_numeric(sub["epss_delta_30d"], errors="coerce").fillna(0.0).to_numpy() * 100.0
        if "epss_delta_30d" in sub.columns
        else np.zeros(len(sub), dtype=float)
    )
    delta_str = np.char.mod("%+.1f%%", delta_vals)

    is_kev = sub["is_kev"].to_numpy(dtype=bool, na_value=False)
    is_ransom = (
        sub["is_ransomware"].to_numpy(dtype=bool, na_value=False)
        if "is_ransomware" in sub.columns
        else np.zeros(len(sub), dtype=bool)
    )
    ransom_str = np.select(
        [is_kev & is_ransom, is_kev],
        ["CISA KEV + Ransomware", "CISA KEV Confirmed"],
        default="Not in KEV",
    )

    sla_str = (
        sub["sla_tier"].astype(str).fillna(SLA_TIER_ORDER[-1]).to_numpy()
        if "sla_tier" in sub.columns
        else np.full(len(sub), SLA_TIER_ORDER[-1], dtype=object)
    )

    blindspot_vals = (
        pd.to_numeric(sub["blindspot_score"], errors="coerce").fillna(0.0).to_numpy()
        if "blindspot_score" in sub.columns
        else np.zeros(len(sub), dtype=float)
    )
    blindspot_str = np.char.mod("%.2f", blindspot_vals)

    epss_vals = pd.to_numeric(sub["epss_score"], errors="coerce").fillna(0.0).to_numpy() * 100.0
    epss_str = np.char.mod("%.2f%%", epss_vals)

    return np.stack(
        (
            cve_id,
            vendor,
            product,
            cwe_family,
            layer,
            vector,
            privs,
            impact_str,
            days_str,
            delta_str,
            ransom_str,
            sla_str,
            blindspot_str,
            epss_str,
        ),
        axis=-1,
    )


BUBBLE_HOVERTEMPLATE = (
    "<b>%{customdata[0]}</b> &nbsp;|&nbsp; <b>%{customdata[1]} %{customdata[2]}</b><br>"
    "<b>SLA Tier:</b> %{customdata[11]} &nbsp;|&nbsp; <b>KEV Status:</b> %{customdata[10]}<br>"
    "<b>Weakness:</b> %{customdata[3]} &nbsp;|&nbsp; <b>Layer:</b> %{customdata[4]}<br>"
    "<b>Vector:</b> %{customdata[5]} (Privs: %{customdata[6]})<br>"
    "<extra>"
    "<b>CVSS Base:</b> %{x:.1f} (Impact: %{customdata[7]})<br>"
    "<b>EPSS (30d):</b> %{customdata[13]} (Δ30d: %{customdata[9]})<br>"
    "<b>Blind-Spot Score:</b> %{customdata[12]}<br>"
    "<b>Days to KEV:</b> %{customdata[8]}"
    "</extra>"
)


def _add_quadrant_corner_labels(fig: go.Figure) -> None:
    corners = [
        (0.99, 0.985, "right", "top", "Q1 · CRITICAL WEAPONS", "#B91C1C"),
        (0.01, 0.985, "left", "top", "Q2 · SILENT THREATS (BLIND SPOTS)", "#B45309"),
        (0.99, 0.015, "right", "bottom", "Q3 · PAPER TIGERS (ALERT FATIGUE)", "#1D4ED8"),
        (0.01, 0.015, "left", "bottom", "Q4 · DORMANT BACKLOG", "#52525B"),
    ]
    for x_pos, y_pos, x_anchor, y_anchor, label, color in corners:
        fig.add_annotation(
            x=x_pos,
            y=y_pos,
            xref="paper",
            yref="paper",
            xanchor=x_anchor,
            yanchor=y_anchor,
            text=f"<b>{label}</b>",
            showarrow=False,
            font=dict(size=9, color=color),
            bgcolor="rgba(255, 255, 255, 0.88)",
            bordercolor="#E4E4E7",
            borderwidth=1,
            borderpad=3,
        )


def create_prioritization_bubble_plot(
    df: pd.DataFrame,
    cvss_thresh: float = DEFAULT_CVSS_CUTOFF,
    epss_thresh: float = DEFAULT_EPSS_CUTOFF,
    color_by: str = "sla_tier",
    y_scale: str = "linear",
    focus_layer: Optional[str] = None,
    focus_cwe: Optional[str] = None,
    focus_vendor: Optional[str] = None,
    highlighted_cves: Optional[Iterable[str]] = None,
    inspected_cve: Optional[str] = None,
    show_landmarks: bool = False,
    as_widget: bool = False,
    show_title: bool = True,
) -> go.Figure:
    fig = go.Figure()

    if len(df) == 0:
        fig.add_annotation(
            text="No vulnerabilities matching the selected asset inventory.",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=14, color=TEXT_MUTED),
        )
        apply_swiss_light_layout(fig, title="Threat Prioritization: Empty Scope")
        return maybe_figure_widget(fig, as_widget=as_widget)

    # Always enrich with current slider thresholds so SLA tiers and quadrants reflect active cutoffs
    plot_df = enrich_prioritization(df, cvss_cutoff=cvss_thresh, epss_cutoff=epss_thresh)

    mode_key = (color_by or "sla_tier").lower().strip()
    if mode_key in {"threat_cluster", "ml_cluster", "kmeans", "cluster"}:
        resolved_mode = "threat_cluster"
        if "threat_cluster" not in plot_df.columns:
            plot_df = perform_threat_clustering(plot_df, n_clusters=4).df
    elif mode_key in {"epss_velocity", "velocity", "epss_delta_30d", "surge"}:
        resolved_mode = "epss_velocity"
    else:
        resolved_mode = "sla_tier"

    y_scale_clean = "log" if str(y_scale).lower().strip() == "log" else "linear"

    impact_vals = pd.to_numeric(plot_df["cvss_impact"], errors="coerce").fillna(0.0).clip(lower=0.0)
    plot_df["impact_area"] = STEVENS_A_MIN + STEVENS_K_SCALE * np.power(impact_vals, STEVENS_EXPONENT)
    max_area = float(plot_df["impact_area"].max())
    sizeref_val = (2.0 * max_area) / (MAX_BUBBLE_DIAMETER_PX**2) if max_area > 0 else 1.0

    y_coords = (
        np.clip(plot_df["epss_score"].to_numpy(dtype=float, na_value=1e-4), 1e-4, 1.0)
        if y_scale_clean == "log"
        else plot_df["epss_score"].to_numpy(dtype=float, na_value=0.0)
    )
    plot_df["_y_plot"] = y_coords

    # Focus + Context partitioning across architectural layer, CWE, vendor, or brushed CVE selection
    focus_mask = np.ones(len(plot_df), dtype=bool)
    focus_tags: List[str] = []

    if focus_layer and focus_layer != "All":
        focus_mask &= (plot_df["layer"].astype(str) == focus_layer).to_numpy()
        focus_tags.append(focus_layer)
    if focus_cwe and focus_cwe != "All":
        focus_mask &= (plot_df["cwe_family"].astype(str) == focus_cwe).to_numpy()
        focus_tags.append(focus_cwe)
    if focus_vendor and focus_vendor != "All":
        focus_mask &= (plot_df["vendor"].astype(str) == focus_vendor).to_numpy()
        focus_tags.append(focus_vendor)
    if highlighted_cves is not None:
        cve_set = set(highlighted_cves)
        if cve_set:
            focus_mask &= plot_df["cve_id"].isin(cve_set).to_numpy()
            focus_tags.append(f"{len(cve_set)} Brushed CVEs")

    is_focus_active = bool(focus_tags) and not focus_mask.all()

    if is_focus_active:
        context_df = plot_df.loc[~focus_mask]
        active_render_df = plot_df.loc[focus_mask]
        if len(context_df) > 0:
            fig.add_trace(
                go.Scattergl(
                    x=context_df["cvss_base"],
                    y=context_df["_y_plot"],
                    mode="markers",
                    name=f"Context ({len(context_df):,} unselected)",
                    marker=dict(
                        size=context_df["impact_area"],
                        sizemode="area",
                        sizeref=sizeref_val,
                        sizemin=2.0,
                        color=CONTEXT_GHOST_COLOR,
                        opacity=CONTEXT_GHOST_OPACITY,
                        line=dict(width=0),
                    ),
                    hoverinfo="skip",
                    showlegend=True,
                )
            )
    else:
        active_render_df = plot_df

    # Render active focal traces in WebGL (Scattergl)
    if resolved_mode == "sla_tier":
        ordered_tiers = sorted(SLA_TIER_STYLES.keys(), key=lambda t: SLA_TIER_STYLES[t]["zorder"])
        for tier in ordered_tiers:
            sub = active_render_df.loc[active_render_df["sla_tier"] == tier]
            if len(sub) == 0:
                continue
            cfg = SLA_TIER_STYLES[tier]
            fig.add_trace(
                go.Scattergl(
                    x=sub["cvss_base"],
                    y=sub["_y_plot"],
                    mode="markers",
                    name=tier,
                    marker=dict(
                        size=sub["impact_area"],
                        sizemode="area",
                        sizeref=sizeref_val,
                        sizemin=3.0,
                        symbol=_build_marker_symbols(sub),
                        color=cfg["color"],
                        opacity=cfg["opacity"],
                        line=dict(width=cfg["line_width"], color=cfg["line_color"]),
                    ),
                    customdata=_build_clean_customdata(sub),
                    hovertemplate=BUBBLE_HOVERTEMPLATE,
                )
            )
    elif resolved_mode == "threat_cluster":
        unique_clusters = [str(c) for c in active_render_df["threat_cluster"].dropna().unique()]
        styled_clusters: List[Tuple[str, Dict[str, object]]] = [
            (c_name, get_cluster_style(c_name, idx))
            for idx, c_name in enumerate(sorted(unique_clusters))
        ]
        styled_clusters.sort(key=lambda item: int(item[1]["zorder"]))

        for c_name, cfg in styled_clusters:
            sub = active_render_df.loc[active_render_df["threat_cluster"].astype(str) == c_name]
            if len(sub) == 0:
                continue
            fig.add_trace(
                go.Scattergl(
                    x=sub["cvss_base"],
                    y=sub["_y_plot"],
                    mode="markers",
                    name=c_name,
                    marker=dict(
                        size=sub["impact_area"],
                        sizemode="area",
                        sizeref=sizeref_val,
                        sizemin=3.0,
                        symbol=_build_marker_symbols(sub),
                        color=cfg["color"],
                        opacity=cfg["opacity"],
                        line=dict(width=cfg["line_width"], color=cfg["line_color"]),
                    ),
                    customdata=_build_clean_customdata(sub),
                    hovertemplate=BUBBLE_HOVERTEMPLATE,
                )
            )
    else:
        # EPSS 30d Velocity (Surge) diverging colorscale mode
        sub = active_render_df
        if len(sub) > 0:
            deltas = (
                pd.to_numeric(sub["epss_delta_30d"], errors="coerce").fillna(0.0).to_numpy()
                if "epss_delta_30d" in sub.columns
                else np.zeros(len(sub), dtype=float)
            )
            fig.add_trace(
                go.Scattergl(
                    x=sub["cvss_base"],
                    y=sub["_y_plot"],
                    mode="markers",
                    name="ΔEPSS 30d Velocity",
                    marker=dict(
                        size=sub["impact_area"],
                        sizemode="area",
                        sizeref=sizeref_val,
                        sizemin=3.0,
                        symbol=_build_marker_symbols(sub),
                        color=deltas,
                        colorscale=VELOCITY_DIVERGING_SCALE,
                        cmin=-0.05,
                        cmax=0.30,
                        opacity=0.84,
                        line=dict(width=0.6, color="rgba(9, 9, 11, 0.25)"),
                        colorbar=dict(
                            title=dict(text="ΔEPSS (30d)", font=dict(size=10, color=TEXT_MUTED)),
                            tickformat="+.0%",
                            tickfont=dict(size=9, color=TEXT_MUTED),
                            len=0.72,
                            thickness=12,
                        ),
                    ),
                    customdata=_build_clean_customdata(sub),
                    hovertemplate=BUBBLE_HOVERTEMPLATE,
                )
            )

    # Crosshair Triage Threshold Boundaries
    fig.add_vline(
        x=cvss_thresh,
        line=dict(color="#71717A", dash="dash", width=1.2),
        annotation_text=f"CVSS Cutoff ({cvss_thresh:.1f})",
        annotation_position="bottom left",
        annotation_font=dict(size=10, color=TEXT_MUTED),
    )
    fig.add_hline(
        y=max(epss_thresh, 1e-4) if y_scale_clean == "log" else epss_thresh,
        line=dict(color="#71717A", dash="dash", width=1.2),
        annotation_text=f"EPSS Cutoff ({epss_thresh:.0%})",
        annotation_position="bottom right",
        annotation_font=dict(size=10, color=TEXT_MUTED),
    )

    _add_quadrant_corner_labels(fig)

    # Case Study Landmarks with adaptive boundary-safe offsets
    if show_landmarks and len(plot_df) > 0:
        apex_candidates = plot_df.loc[plot_df["is_kev"] & (plot_df["cvss_base"] >= 8.5)].sort_values(
            "epss_score", ascending=False
        )
        if len(apex_candidates) > 0:
            apex = apex_candidates.iloc[0]
            x_a = float(apex["cvss_base"])
            y_a = float(apex["_y_plot"])
            ax_a, ay_a = _compute_safe_offsets(x_a, y_a, y_scale_clean)
            fig.add_annotation(
                x=x_a,
                y=_annotation_y(y_a, y_scale_clean),
                text=(
                    f"<b>Apex Weapon ({apex['sla_tier'].split(':')[0]})</b><br>"
                    f"{apex['cve_id']} ({apex['vendor']})<br>"
                    f"CVSS {x_a:.1f} | EPSS {float(apex['epss_score']):.0%}"
                ),
                showarrow=True,
                arrowhead=2,
                arrowsize=1,
                arrowwidth=1.4,
                arrowcolor="#B91C1C",
                ax=ax_a,
                ay=ay_a,
                font=dict(size=10, color=TEXT_PRIMARY),
                bgcolor="rgba(255, 255, 255, 0.94)",
                bordercolor="#B91C1C",
                borderwidth=1.0,
                borderpad=4,
            )

        silent_candidates = plot_df.loc[plot_df["is_silent_threat"]].sort_values(
            ["is_kev", "blindspot_score", "epss_score"],
            ascending=[False, False, False],
        )
        if len(silent_candidates) > 0:
            silent = silent_candidates.iloc[0]
            x_s = float(silent["cvss_base"])
            y_s = float(silent["_y_plot"])
            ax_s, ay_s = _compute_safe_offsets(x_s, y_s, y_scale_clean)
            fig.add_annotation(
                x=x_s,
                y=_annotation_y(y_s, y_scale_clean),
                text=(
                    f"<b>Silent Threat (Blind Spot)</b><br>"
                    f"{silent['cve_id']} ({silent['vendor']})<br>"
                    f"CVSS {x_s:.1f} | EPSS {float(silent['epss_score']):.0%}"
                ),
                showarrow=True,
                arrowhead=2,
                arrowsize=1,
                arrowwidth=1.4,
                arrowcolor="#B45309",
                ax=ax_s,
                ay=ay_s,
                font=dict(size=10, color=TEXT_PRIMARY),
                bgcolor="rgba(255, 255, 255, 0.94)",
                bordercolor="#B45309",
                borderwidth=1.0,
                borderpad=4,
            )

    # Dynamic Pin for Inspected CVE from 24h Patch Queue or click
    if inspected_cve:
        pinned_rows = plot_df.loc[plot_df["cve_id"] == inspected_cve]
        if len(pinned_rows) > 0:
            pin = pinned_rows.iloc[0]
            x_p = float(pin["cvss_base"])
            y_p = float(pin["_y_plot"])
            ax_p, ay_p = _compute_safe_offsets(x_p, y_p, y_scale_clean)
            fig.add_trace(
                go.Scattergl(
                    x=[x_p],
                    y=[y_p],
                    mode="markers",
                    name=f"Pinned: {inspected_cve}",
                    marker=dict(
                        size=22,
                        color="rgba(29, 78, 216, 0.14)",
                        symbol="circle",
                        line=dict(width=2.2, color=ACCENT_PRIMARY),
                    ),
                    customdata=_build_clean_customdata(pinned_rows.iloc[[0]]),
                    hovertemplate=BUBBLE_HOVERTEMPLATE,
                )
            )
            fig.add_annotation(
                x=x_p,
                y=_annotation_y(y_p, y_scale_clean),
                text=(
                    f"<b>Pinned CVE: {pin['cve_id']}</b><br>"
                    f"{pin['vendor']} {pin['product']}<br>"
                    f"{pin['sla_tier']} | CVSS {x_p:.1f} | EPSS {float(pin['epss_score']):.1%}"
                ),
                showarrow=True,
                arrowhead=2,
                arrowsize=1.0,
                arrowwidth=1.5,
                arrowcolor=ACCENT_PRIMARY,
                ax=ax_p,
                ay=ay_p,
                font=dict(size=10, color=TEXT_PRIMARY),
                bgcolor="rgba(255, 255, 255, 0.96)",
                bordercolor=ACCENT_PRIMARY,
                borderwidth=1.2,
                borderpad=4,
            )

    focus_suffix = f" — Focus: {' · '.join(focus_tags)}" if is_focus_active else ""
    yaxis_cfg: Dict[str, object]
    if y_scale_clean == "log":
        yaxis_cfg = dict(
            title="EPSS v3 30-Day Probability (Log10)",
            type="log",
            range=[-4.05, 0.08],
            tickvals=[0.0001, 0.001, 0.01, 0.1, 0.3, 1.0],
            ticktext=["0.01%", "0.1%", "1%", "10%", "30%", "100%"],
            gridcolor=GRID_COLOR,
            zerolinecolor=ZERO_LINE_COLOR,
            linecolor=ZERO_LINE_COLOR,
            tickfont=dict(color=TEXT_MUTED, size=10),
            title_font=dict(color=TEXT_MUTED, size=11),
        )
    else:
        yaxis_cfg = dict(
            title="EPSS v3 30-Day Exploit Probability",
            type="linear",
            range=[-0.04, 1.06],
            tickformat=".0%",
            gridcolor=GRID_COLOR,
            zerolinecolor=ZERO_LINE_COLOR,
            linecolor=ZERO_LINE_COLOR,
            tickfont=dict(color=TEXT_MUTED, size=10),
            title_font=dict(color=TEXT_MUTED, size=11),
        )

    apply_swiss_light_layout(
        fig,
        title=f"Threat Prioritization: Severity vs Weaponization{focus_suffix}" if show_title else "",
        margin=dict(l=52, r=16, t=92 if not show_title else 96, b=46),
        xaxis=dict(
            title="NVD CVSS v3.1 Base Score",
            range=[0.0, 10.3],
            gridcolor=GRID_COLOR,
            zerolinecolor=ZERO_LINE_COLOR,
            linecolor=ZERO_LINE_COLOR,
            tickfont=dict(color=TEXT_MUTED, size=10),
            title_font=dict(color=TEXT_MUTED, size=11),
        ),
        yaxis=yaxis_cfg,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.01,
            xanchor="left",
            x=0.0,
            font=dict(size=9.5, color=TEXT_MUTED),
        ),
        dragmode="lasso",
    )
    if show_title:
        fig.update_layout(
            title=dict(
                x=0.0,
                xanchor="left",
                y=0.975,
                yanchor="top",
                font=dict(size=13, color=TEXT_PRIMARY),
            )
        )

    return maybe_figure_widget(fig, as_widget=as_widget)
