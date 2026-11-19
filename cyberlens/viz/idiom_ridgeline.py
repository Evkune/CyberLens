from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from scipy.stats import gaussian_kde, iqr

from cyberlens.viz.theme import (
    GRID_COLOR,
    RIDGELINE_COHORT_PALETTE,
    TEXT_MUTED,
    TEXT_PRIMARY,
    ZERO_LINE_COLOR,
    apply_swiss_light_layout,
    hex_to_rgba,
    maybe_figure_widget,
)

BASELINE_STEP = 0.75
RIDGE_MAX_HEIGHT = 1.00  # Step 0.75 with peak height 1.00 yields a controlled 25% vertical overlap


def compute_reflected_kde(days_array: np.ndarray, t_grid: np.ndarray) -> np.ndarray:
    """
    Computes boundary-corrected Gaussian KDE on [0, +inf) using Schuster-Silverman
    mirror reflection to preserve zero-day weaponization spikes (0 <= t < 7 days).
    """
    t_clean = np.asarray(days_array, dtype=float)
    t_clean = t_clean[(t_clean >= 0.0) & (~np.isnan(t_clean))]
    n = len(t_clean)
    if n < 3:
        return np.zeros_like(t_grid, dtype=float)

    std_dev = float(np.std(t_clean, ddof=1))
    if std_dev <= 1e-6:
        # Degenerate zero-variance spike (e.g. all zero-days at t=0)
        density = np.exp(-0.5 * ((t_grid - float(np.mean(t_clean))) / 1.5) ** 2)
        density[t_grid < 0] = 0.0
        return density

    iqr_scale = float(iqr(t_clean)) / 1.34
    sigma_robust = min(std_dev, iqr_scale) if iqr_scale > 0 else std_dev
    h_opt = 0.9 * sigma_robust * (n ** (-0.2))
    bw_factor = max(h_opt / std_dev, 0.08)

    kde = gaussian_kde(t_clean, bw_method=bw_factor)
    density_reflected = kde.evaluate(t_grid) + kde.evaluate(-t_grid)
    density_reflected[t_grid < 0] = 0.0
    return density_reflected


def create_velocity_ridgeline_plot(
    df: pd.DataFrame,
    max_days: int = 120,
    highlight_vendor: Optional[str] = None,
    as_widget: bool = False,
) -> go.Figure:
    fig = go.Figure()

    if len(df) == 0 or "days_to_exploit" not in df.columns:
        fig.add_annotation(
            text="Insufficient weaponization event data for selected cohorts (min 5 events required).",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=14, color=TEXT_MUTED),
        )
        apply_swiss_light_layout(fig, title="Exploitation Velocity Density by Vendor Cohort")
        return maybe_figure_widget(fig, as_widget=as_widget)

    kev_df = df.loc[df["is_kev"].astype(bool) & df["days_to_exploit"].notna()].copy()

    if len(kev_df) < 5:
        fig.add_annotation(
            text="Insufficient weaponization event data for selected cohorts (min 5 events required).",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=14, color=TEXT_MUTED),
        )
        apply_swiss_light_layout(fig, title="Exploitation Velocity Density by Vendor Cohort")
        return maybe_figure_widget(fig, as_widget=as_widget)

    kev_df["vendor_str"] = kev_df["vendor"].astype(str)
    kev_df["days_num"] = pd.to_numeric(kev_df["days_to_exploit"], errors="coerce")

    cohorts: List[Dict[str, Any]] = []
    for v_name, grp in kev_df.groupby("vendor_str", observed=True):
        vals = grp["days_num"].dropna().to_numpy(dtype=float)
        vals = vals[vals >= 0.0]
        if len(vals) < 3:
            continue
        p50 = float(np.median(vals))
        zero_day_pct = float(np.mean(vals <= 7.0) * 100.0)
        cohorts.append(
            {
                "vendor": str(v_name),
                "values": vals,
                "n": int(len(vals)),
                "p50": p50,
                "zero_day_pct": zero_day_pct,
            }
        )

    if not cohorts:
        fig.add_annotation(
            text="No vendor cohort meets the minimum sample size (n >= 3 KEV observations).",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=14, color=TEXT_MUTED),
        )
        apply_swiss_light_layout(fig, title="Exploitation Velocity Density by Vendor Cohort")
        return maybe_figure_widget(fig, as_widget=as_widget)

    # Sort strictly by P50 median ascending (fastest zero-day weaponization ecosystems ordered first)
    cohorts.sort(key=lambda c: (c["p50"], c["vendor"]))

    x_grid = np.linspace(0.0, float(max_days), 300)
    tickvals: List[float] = []
    ticktext: List[str] = []

    is_highlight_active = bool(
        highlight_vendor
        and highlight_vendor != "All"
        and any(c["vendor"] == highlight_vendor for c in cohorts)
    )

    p50_marker_x: List[float] = []
    p50_marker_y: List[float] = []
    p50_marker_text: List[str] = []
    p50_marker_colors: List[str] = []

    for i, cohort in enumerate(cohorts):
        v_name = cohort["vendor"]
        subset = cohort["values"]
        n_obs = cohort["n"]
        p50 = cohort["p50"]
        zd_pct = cohort["zero_day_pct"]

        color = RIDGELINE_COHORT_PALETTE[i % len(RIDGELINE_COHORT_PALETTE)]
        density = compute_reflected_kde(subset, x_grid)
        max_d = float(density.max())
        density_scaled = (
            (density / max_d * RIDGE_MAX_HEIGHT) if max_d > 0 else np.zeros_like(x_grid)
        )

        baseline = i * BASELINE_STEP
        curve_y = baseline + density_scaled

        tickvals.append(baseline)
        ticktext.append(f"{v_name} (n={n_obs} | P50={p50:.0f}d)")

        if is_highlight_active:
            is_focused = v_name == highlight_vendor
            fill_alpha = 0.42 if is_focused else 0.06
            line_width = 2.6 if is_focused else 1.0
            line_color = color if is_focused else hex_to_rgba(color, 0.35)
        else:
            fill_alpha = 0.18
            line_width = 1.8
            line_color = color

        # 1. Closed polygon area fill trace (hover skipped to avoid 600-point customdata mismatch)
        fig.add_trace(
            go.Scatter(
                x=np.concatenate([x_grid, x_grid[::-1]]),
                y=np.concatenate([curve_y, np.full_like(x_grid, baseline)]),
                fill="toself",
                fillcolor=hex_to_rgba(color, fill_alpha),
                line=dict(color="rgba(0,0,0,0)", width=0),
                name=f"{v_name} Fill",
                hoverinfo="skip",
                showlegend=False,
            )
        )

        # 2. Top ridge curve trace with exact 300-point customdata for accurate hover & click
        customdata = np.column_stack(
            [
                np.full(len(x_grid), v_name, dtype=object),
                np.full(len(x_grid), str(n_obs), dtype=object),
                np.full(len(x_grid), f"{p50:.1f}d", dtype=object),
                np.full(len(x_grid), f"{zd_pct:.0f}%", dtype=object),
                np.char.mod("%.2f", density_scaled),
            ]
        )

        fig.add_trace(
            go.Scatter(
                x=x_grid,
                y=curve_y,
                mode="lines",
                line=dict(color=line_color, width=line_width),
                name=f"{v_name} (n={n_obs} | P50={p50:.0f}d)",
                meta={"vendor": v_name, "p50": p50, "n": n_obs, "baseline": baseline},
                customdata=customdata,
                hovertemplate=(
                    "<b>%{customdata[0]}</b> (n=%{customdata[1]} KEV exploits)<br>"
                    "• Exposure Lag: <b>%{x:.1f} days</b><br>"
                    "• Cohort Median (P50): <b>%{customdata[2]}</b><br>"
                    "• Zero-Day / Flash Ratio (≤7d): <b>%{customdata[3]}</b><br>"
                    "• Relative KDE Density: %{customdata[4]}"
                    "<extra></extra>"
                ),
                showlegend=False,
            )
        )

        # 3. Record P50 median marker position on this ridge (clamped to visible [0, max_days])
        p50_clamped = float(np.clip(p50, 0.0, float(max_days)))
        p50_height = float(np.interp(p50_clamped, x_grid, curve_y))
        p50_marker_x.append(p50_clamped)
        p50_marker_y.append(p50_height)
        p50_marker_text.append(f"{v_name}: P50 = {p50:.1f}d")
        p50_marker_colors.append(color)

    # Render P50 median diamonds across all cohorts
    if p50_marker_x:
        fig.add_trace(
            go.Scatter(
                x=p50_marker_x,
                y=p50_marker_y,
                mode="markers",
                name="Cohort Median (P50)",
                marker=dict(
                    symbol="diamond",
                    size=8,
                    color=p50_marker_colors,
                    line=dict(width=1.3, color="#FFFFFF"),
                ),
                text=p50_marker_text,
                hovertemplate="<b>%{text}</b><extra>Median Exploitation Velocity</extra>",
                showlegend=False,
            )
        )

    # Operational SLA Reference Landmarks: 0-7d Flash Zone, 24h (P0 SLA), and 14d (Legacy SLA)
    fig.add_vrect(
        x0=0.0,
        x1=7.0,
        fillcolor="rgba(185, 28, 28, 0.06)",
        line_width=0,
        annotation_text="0–7d Flash Zone",
        annotation_position="top left",
        annotation_font=dict(size=9, color="#B91C1C"),
    )
    fig.add_vline(
        x=1.0,
        line=dict(color="#B91C1C", dash="dot", width=1.4),
        annotation_text="24h SLA (P0)",
        annotation_position="bottom right",
        annotation_font=dict(size=9, color="#B91C1C"),
    )
    fig.add_vline(
        x=14.0,
        line=dict(color="#B45309", dash="dash", width=1.4),
        annotation_text="14d Legacy SLA (Δt < 0)",
        annotation_position="top right",
        annotation_yshift=-16,
        annotation_xshift=4,
        annotation_font=dict(size=9, color="#B45309"),
    )

    max_baseline = tickvals[-1] if tickvals else 1.0
    title_suffix = f" — Highlight: {highlight_vendor}" if is_highlight_active else ""

    apply_swiss_light_layout(
        fig,
        title=(
            "Exploitation Velocity by Vendor Cohort "
            "(Sorted by P50 Lag)"
            f"{title_suffix}"
        ),
        margin=dict(l=180, r=20, t=52, b=56),
        xaxis=dict(
            title="Elapsed Days from Disclosure to CISA KEV Weaponization (t_KEV − t_NVD)",
            range=[0, max_days],
            gridcolor=GRID_COLOR,
            zerolinecolor=ZERO_LINE_COLOR,
            linecolor=ZERO_LINE_COLOR,
            tickfont=dict(color=TEXT_MUTED, size=10),
            title_font=dict(color=TEXT_MUTED, size=11),
        ),
        yaxis=dict(
            title="",
            showticklabels=True,
            tickmode="array",
            tickvals=tickvals,
            ticktext=ticktext,
            tickfont=dict(size=11, color=TEXT_PRIMARY),
            range=[-0.15, max_baseline + RIDGE_MAX_HEIGHT + 0.25],
            gridcolor=GRID_COLOR,
            zeroline=False,
        ),
        showlegend=False,
    )

    return maybe_figure_widget(fig, as_widget=as_widget)
