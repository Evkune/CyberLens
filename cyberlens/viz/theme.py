from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import plotly.graph_objects as go

from cyberlens.config import SLA_TIER_ORDER

BG_PAGE = "#FFFFFF"
BG_SIDEBAR = "#FAFAFA"
BG_DARK = "#FFFFFF"
BG_ELEVATED = "#FAFAFA"
GRID_COLOR = "#F4F4F5"
ZERO_LINE_COLOR = "#E4E4E7"
BORDER_COLOR = "#E4E4E7"
TEXT_PRIMARY = "#09090B"
TEXT_SECONDARY = "#52525B"
TEXT_MUTED = "#52525B"
ACCENT_PRIMARY = "#1D4ED8"
ACCENT_CYAN = "#1D4ED8"

CONTEXT_GHOST_COLOR = "#D4D4D8"
CONTEXT_GHOST_OPACITY = 0.25

SLA_TIER_COLORS: Dict[str, str] = {
    SLA_TIER_ORDER[0]: "#B91C1C",
    SLA_TIER_ORDER[1]: "#B45309",
    SLA_TIER_ORDER[2]: "#1D4ED8",
    SLA_TIER_ORDER[3]: "#71717A",
    SLA_TIER_ORDER[4]: "#A1A1AA",
}

CLUSTER_PALETTE: List[str] = [
    "#B91C1C",
    "#B45309",
    "#1D4ED8",
    "#71717A",
    "#52525B",
    "#0F766E",
]

TREEMAP_SEQUENTIAL_SCALE: List[Tuple[float, str]] = [
    (0.00, "#F4F4F5"),
    (0.35, "#CBD5E1"),
    (0.70, "#FDE68A"),
    (1.00, "#FCA5A5"),
]

SLA_TIER_STYLES: Dict[str, Dict[str, Any]] = {
    SLA_TIER_ORDER[4]: {
        "color": SLA_TIER_COLORS[SLA_TIER_ORDER[4]],
        "opacity": 0.28,
        "line_width": 0.4,
        "line_color": "rgba(9, 9, 11, 0.15)",
        "zorder": 1,
    },
    SLA_TIER_ORDER[3]: {
        "color": SLA_TIER_COLORS[SLA_TIER_ORDER[3]],
        "opacity": 0.36,
        "line_width": 0.4,
        "line_color": "rgba(9, 9, 11, 0.20)",
        "zorder": 2,
    },
    SLA_TIER_ORDER[2]: {
        "color": SLA_TIER_COLORS[SLA_TIER_ORDER[2]],
        "opacity": 0.72,
        "line_width": 0.8,
        "line_color": "#FFFFFF",
        "zorder": 3,
    },
    SLA_TIER_ORDER[1]: {
        "color": SLA_TIER_COLORS[SLA_TIER_ORDER[1]],
        "opacity": 0.86,
        "line_width": 1.0,
        "line_color": "#FFFFFF",
        "zorder": 4,
    },
    SLA_TIER_ORDER[0]: {
        "color": SLA_TIER_COLORS[SLA_TIER_ORDER[0]],
        "opacity": 0.94,
        "line_width": 1.2,
        "line_color": "#FFFFFF",
        "zorder": 5,
    },
}

VELOCITY_DIVERGING_SCALE: List[Tuple[float, str]] = [
    (0.00, "#A1A1AA"),
    (0.22, "#52525B"),
    (0.45, "#1D4ED8"),
    (0.72, "#B45309"),
    (1.00, "#B91C1C"),
]

RIDGELINE_COHORT_PALETTE: List[str] = [
    "#B91C1C",
    "#B45309",
    "#1D4ED8",
    "#3F3F46",
    "#52525B",
    "#71717A",
    "#52525B",
    "#3F3F46",
    "#71717A",
    "#A1A1AA",
]

CLUSTER_COLOR_BY_PREFIX: Dict[str, Tuple[str, float, int]] = {
    "Cluster A": (CLUSTER_PALETTE[0], 0.90, 6),
    "Cluster B": (CLUSTER_PALETTE[1], 0.84, 5),
    "Cluster E": (CLUSTER_PALETTE[2], 0.78, 4),
    "Cluster F": (CLUSTER_PALETTE[5], 0.72, 3),
    "Cluster C": (CLUSTER_PALETTE[4], 0.42, 2),
    "Cluster D": (CLUSTER_PALETTE[3], 0.28, 1),
}


def get_cluster_style(cluster_name: str, fallback_idx: int = 0) -> Dict[str, Any]:
    for prefix, (color, opacity, zorder) in CLUSTER_COLOR_BY_PREFIX.items():
        if cluster_name.startswith(prefix):
            is_focal = zorder >= 4
            return {
                "color": color,
                "opacity": opacity,
                "line_width": 1.0 if is_focal else 0.4,
                "line_color": "#FFFFFF" if is_focal else "rgba(9, 9, 11, 0.18)",
                "zorder": zorder,
            }
    color = CLUSTER_PALETTE[fallback_idx % len(CLUSTER_PALETTE)]
    return {
        "color": color,
        "opacity": 0.65,
        "line_width": 0.6,
        "line_color": "#FFFFFF",
        "zorder": 3,
    }


def hex_to_rgba(hex_color: str, alpha: float) -> str:
    clean = hex_color.lstrip("#")
    if len(clean) != 6:
        return f"rgba(82, 82, 91, {alpha:.2f})"
    r = int(clean[0:2], 16)
    g = int(clean[2:4], 16)
    b = int(clean[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha:.2f})"


def apply_swiss_light_layout(
    fig: go.Figure,
    title: str,
    margin: Optional[Dict[str, int]] = None,
    **extra_layout: Any,
) -> go.Figure:
    fig.update_layout(
        autosize=True,
        title=dict(text=title, font=dict(size=13, color=TEXT_PRIMARY)),
        template="plotly_white",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            color=TEXT_PRIMARY,
            family="Inter, -apple-system, BlinkMacSystemFont, sans-serif",
        ),
        hoverlabel=dict(
            bgcolor="#FFFFFF",
            bordercolor="#09090B",
            font=dict(
                color="#09090B",
                size=11,
                family="Inter, -apple-system, BlinkMacSystemFont, sans-serif",
            ),
        ),
        margin=margin or dict(l=52, r=28, t=58, b=48),
        **extra_layout,
    )
    return fig


apply_soc_dark_layout = apply_swiss_light_layout


def maybe_figure_widget(fig: go.Figure, as_widget: bool = True) -> go.Figure:
    if not as_widget:
        return fig
    try:
        return go.FigureWidget(fig)
    except Exception:
        return fig


__all__ = [
    "ACCENT_CYAN",
    "ACCENT_PRIMARY",
    "BG_DARK",
    "BG_ELEVATED",
    "BG_PAGE",
    "BG_SIDEBAR",
    "BORDER_COLOR",
    "CLUSTER_PALETTE",
    "CONTEXT_GHOST_COLOR",
    "CONTEXT_GHOST_OPACITY",
    "GRID_COLOR",
    "RIDGELINE_COHORT_PALETTE",
    "SLA_TIER_COLORS",
    "SLA_TIER_STYLES",
    "TEXT_MUTED",
    "TEXT_PRIMARY",
    "TEXT_SECONDARY",
    "TREEMAP_SEQUENTIAL_SCALE",
    "VELOCITY_DIVERGING_SCALE",
    "ZERO_LINE_COLOR",
    "apply_soc_dark_layout",
    "apply_swiss_light_layout",
    "get_cluster_style",
    "hex_to_rgba",
    "maybe_figure_widget",
]
