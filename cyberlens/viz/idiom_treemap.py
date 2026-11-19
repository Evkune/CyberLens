from __future__ import annotations

from typing import Callable, Dict, List, Optional

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from cyberlens.config import CWE_FAMILY_RULES
from cyberlens.domain.prioritization import enrich_prioritization
from cyberlens.viz.theme import (
    BG_PAGE,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TREEMAP_SEQUENTIAL_SCALE,
    apply_swiss_light_layout,
    maybe_figure_widget,
)

ROOT_NODE_LABEL = "Enterprise Attack Surface"
ID_SEPARATOR = "|"

METRIC_LABELS: Dict[str, str] = {
    "expected_risk": "Actuarial Expected Risk (∑ CVSS × P_eff)",
    "actionable_count": "Actionable SLA Queue (P0–P2 Count)",
    "kev_count": "Confirmed CISA KEV Exploits",
    "cve_count": "Total Vulnerability Volume",
}


def resolve_treemap_metric(metric: str) -> str:
    key = (metric or "expected_risk").lower().strip()
    if key in {"expected_risk", "threat_weight", "actuarial_risk", "risk"}:
        return "expected_risk"
    if key in {"actionable_count", "actionable", "p0_p2", "actionable_queue"}:
        return "actionable_count"
    if key in {"kev_count", "confirmed_kev", "kev"}:
        return "kev_count"
    if key in {"cve_count", "count", "volume"}:
        return "cve_count"
    return "expected_risk"


def extract_treemap_click_filter(node_id: Optional[str]) -> Dict[str, Optional[str]]:
    """Extracts {layer, cwe_family, vendor} from a clicked Treemap node ID."""
    empty = {"layer": None, "cwe_family": None, "vendor": None}
    if not node_id or node_id == ROOT_NODE_LABEL:
        return empty

    if ID_SEPARATOR in node_id:
        parts = node_id.split(ID_SEPARATOR)
    else:
        # Fallback if a caller passes slash-delimited paths (preserving CWE-89/78)
        protected = node_id
        for cwe_label in CWE_FAMILY_RULES:
            if "/" in cwe_label and cwe_label in protected:
                protected = protected.replace(cwe_label, cwe_label.replace("/", "__SLASH__"))
        parts = [p.replace("__SLASH__", "/") for p in protected.split("/")]

    if parts and parts[0] == ROOT_NODE_LABEL:
        parts = parts[1:]

    return {
        "layer": parts[0] if len(parts) >= 1 and parts[0] else None,
        "cwe_family": parts[1] if len(parts) >= 2 and parts[1] else None,
        "vendor": parts[2] if len(parts) >= 3 and parts[2] else None,
    }


def create_architectural_treemap(
    df: pd.DataFrame,
    metric: str = "expected_risk",
    on_click_callback: Optional[Callable[[Dict[str, Optional[str]]], None]] = None,
    as_widget: bool = True,
    show_title: bool = True,
) -> go.Figure:
    fig = go.Figure()

    if len(df) == 0:
        fig.add_annotation(
            text="No vulnerabilities matching current selection.",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=14, color=TEXT_MUTED),
        )
        apply_swiss_light_layout(
            fig,
            title="Architectural Weakness Containment Hierarchy (Space-Filling Treemap)",
            margin=dict(l=10, r=10, t=45, b=10),
        )
        return maybe_figure_widget(fig, as_widget=as_widget)

    work = df.copy() if "expected_risk" in df.columns and "is_actionable" in df.columns else enrich_prioritization(df)

    # Convert categorical grouping columns to strings to avoid empty cartesian product groups
    work["layer_str"] = work["layer"].astype(str)
    work["cwe_str"] = work["cwe_family"].astype(str)
    work["vendor_str"] = work["vendor"].astype(str)
    work["cve_count"] = 1
    work["is_network_num"] = (work["attack_vector"].astype(str) == "Network").astype(float)
    work["kev_num"] = work["is_kev"].astype(int)
    work["actionable_num"] = work["is_actionable"].astype(int)
    work["cvss_num"] = pd.to_numeric(work["cvss_base"], errors="coerce").fillna(0.0)
    work["risk_num"] = pd.to_numeric(work["expected_risk"], errors="coerce").fillna(0.0)

    resolved_metric = resolve_treemap_metric(metric)
    val_source_col = {
        "expected_risk": "risk_num",
        "actionable_count": "actionable_num",
        "kev_count": "kev_num",
        "cve_count": "cve_count",
    }[resolved_metric]

    leaf_df = (
        work.groupby(["layer_str", "cwe_str", "vendor_str"], observed=True, as_index=False)
        .agg(
            metric_val=(val_source_col, "sum"),
            cve_count=("cve_count", "sum"),
            kev_count=("kev_num", "sum"),
            actionable_count=("actionable_num", "sum"),
            net_count=("is_network_num", "sum"),
            cvss_sum=("cvss_num", "sum"),
            expected_risk=("risk_num", "sum"),
        )
    )
    leaf_df["metric_val"] = leaf_df["metric_val"].astype(float).round(4)
    leaf_df = leaf_df.loc[leaf_df["metric_val"] > 0.0].copy()

    if len(leaf_df) == 0:
        fig.add_annotation(
            text=f"No records with positive {METRIC_LABELS[resolved_metric]} in current scope.",
            xref="paper",
            yref="paper",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=13, color=TEXT_MUTED),
        )
        apply_swiss_light_layout(
            fig,
            title="Architectural Weakness Containment Hierarchy (Space-Filling Treemap)",
            margin=dict(l=10, r=10, t=45, b=10),
        )
        return maybe_figure_widget(fig, as_widget=as_widget)

    cwe_df = (
        leaf_df.groupby(["layer_str", "cwe_str"], observed=True, as_index=False)
        .agg(
            metric_val=("metric_val", "sum"),
            cve_count=("cve_count", "sum"),
            kev_count=("kev_count", "sum"),
            actionable_count=("actionable_count", "sum"),
            net_count=("net_count", "sum"),
            cvss_sum=("cvss_sum", "sum"),
            expected_risk=("expected_risk", "sum"),
        )
    )

    layer_df = (
        cwe_df.groupby(["layer_str"], observed=True, as_index=False)
        .agg(
            metric_val=("metric_val", "sum"),
            cve_count=("cve_count", "sum"),
            kev_count=("kev_count", "sum"),
            actionable_count=("actionable_count", "sum"),
            net_count=("net_count", "sum"),
            cvss_sum=("cvss_sum", "sum"),
            expected_risk=("expected_risk", "sum"),
        )
    )

    ids: List[str] = []
    labels: List[str] = []
    parents: List[str] = []
    values: List[float] = []
    colors: List[float] = []
    customdata: List[List[object]] = []

    def _append_node(
        node_id: str,
        label: str,
        parent_id: str,
        metric_val: float,
        cve_cnt: int,
        kev_cnt: int,
        act_cnt: int,
        net_cnt: float,
        cvss_sum: float,
        exp_risk: float,
    ) -> None:
        net_ratio = float(net_cnt / cve_cnt) if cve_cnt > 0 else 0.0
        mean_cvss = float(cvss_sum / cve_cnt) if cve_cnt > 0 else 0.0
        ids.append(node_id)
        labels.append(label)
        parents.append(parent_id)
        values.append(float(metric_val))
        colors.append(net_ratio)
        customdata.append(
            [
                int(cve_cnt),
                int(kev_cnt),
                round(mean_cvss, 1),
                round(net_ratio, 4),
                int(act_cnt),
                round(float(exp_risk), 1),
            ]
        )

    # 1. Root Node (sum of all layers)
    _append_node(
        node_id=ROOT_NODE_LABEL,
        label=ROOT_NODE_LABEL,
        parent_id="",
        metric_val=float(layer_df["metric_val"].sum()),
        cve_cnt=int(layer_df["cve_count"].sum()),
        kev_cnt=int(layer_df["kev_count"].sum()),
        act_cnt=int(layer_df["actionable_count"].sum()),
        net_cnt=float(layer_df["net_count"].sum()),
        cvss_sum=float(layer_df["cvss_sum"].sum()),
        exp_risk=float(layer_df["expected_risk"].sum()),
    )

    # 2. Architectural Layer Nodes
    for row in layer_df.itertuples(index=False):
        layer_id = f"{ROOT_NODE_LABEL}{ID_SEPARATOR}{row.layer_str}"
        _append_node(
            node_id=layer_id,
            label=str(row.layer_str),
            parent_id=ROOT_NODE_LABEL,
            metric_val=float(row.metric_val),
            cve_cnt=int(row.cve_count),
            kev_cnt=int(row.kev_count),
            act_cnt=int(row.actionable_count),
            net_cnt=float(row.net_count),
            cvss_sum=float(row.cvss_sum),
            exp_risk=float(row.expected_risk),
        )

    # 3. CWE Weakness Family Nodes
    for row in cwe_df.itertuples(index=False):
        layer_id = f"{ROOT_NODE_LABEL}{ID_SEPARATOR}{row.layer_str}"
        cwe_id = f"{layer_id}{ID_SEPARATOR}{row.cwe_str}"
        _append_node(
            node_id=cwe_id,
            label=str(row.cwe_str),
            parent_id=layer_id,
            metric_val=float(row.metric_val),
            cve_cnt=int(row.cve_count),
            kev_cnt=int(row.kev_count),
            act_cnt=int(row.actionable_count),
            net_cnt=float(row.net_count),
            cvss_sum=float(row.cvss_sum),
            exp_risk=float(row.expected_risk),
        )

    # 4. Vendor Leaf Nodes
    for row in leaf_df.itertuples(index=False):
        cwe_id = f"{ROOT_NODE_LABEL}{ID_SEPARATOR}{row.layer_str}{ID_SEPARATOR}{row.cwe_str}"
        vendor_id = f"{cwe_id}{ID_SEPARATOR}{row.vendor_str}"
        _append_node(
            node_id=vendor_id,
            label=str(row.vendor_str),
            parent_id=cwe_id,
            metric_val=float(row.metric_val),
            cve_cnt=int(row.cve_count),
            kev_cnt=int(row.kev_count),
            act_cnt=int(row.actionable_count),
            net_cnt=float(row.net_count),
            cvss_sum=float(row.cvss_sum),
            exp_risk=float(row.expected_risk),
        )

    fig.add_trace(
        go.Treemap(
            ids=ids,
            labels=labels,
            parents=parents,
            values=values,
            branchvalues="total",
            customdata=customdata,
            tiling=dict(packing="squarify"),
            texttemplate="<b>%{label}</b><br>%{customdata[1]} KEV · %{customdata[3]:.0%} Net",
            textfont=dict(color=TEXT_PRIMARY, size=12),
            insidetextfont=dict(color=TEXT_PRIMARY, size=12),
            outsidetextfont=dict(color=TEXT_PRIMARY, size=11),
            pathbar=dict(
                visible=True,
                textfont=dict(color=TEXT_PRIMARY, size=11),
            ),
            marker=dict(
                colors=colors,
                colorscale=TREEMAP_SEQUENTIAL_SCALE,
                cmin=0.10,
                cmax=0.95,
                line=dict(width=1.5, color=BG_PAGE),
                colorbar=dict(
                    title=dict(text="Network Exposure", font=dict(size=10, color=TEXT_MUTED)),
                    tickformat=".0%",
                    tickfont=dict(size=9, color=TEXT_MUTED),
                    len=0.78,
                    thickness=12,
                ),
            ),
            hoverlabel=dict(
                bgcolor="#FFFFFF",
                bordercolor="#09090B",
                font=dict(color="#09090B", size=11),
            ),
            hovertemplate=(
                "<b>%{label}</b><br>"
                f"• {METRIC_LABELS[resolved_metric]}: <b>%{{value:.1f}}</b><br>"
                "• Actuarial Expected Risk: %{customdata[5]:.1f}<br>"
                "• Actionable SLA Queue (P0–P2): %{customdata[4]} / %{customdata[0]} CVEs<br>"
                "• Confirmed CISA KEV Exploits: %{customdata[1]}<br>"
                "• Mean CVSS Severity: %{customdata[2]:.1f}<br>"
                "• Network Attack Surface Ratio: %{customdata[3]:.1%}"
                "<extra></extra>"
            ),
        )
    )

    apply_swiss_light_layout(
        fig,
        title=f"Attack Surface Hierarchy — {METRIC_LABELS[resolved_metric]}" if show_title else "",
        margin=dict(l=8, r=8, t=46 if show_title else 26, b=8),
    )

    widget = maybe_figure_widget(fig, as_widget=as_widget)
    if on_click_callback is not None and hasattr(widget.data[0], "on_click"):
        def _handle_click(trace: object, points: object, state: object) -> None:
            inds = getattr(points, "point_inds", None)
            if inds:
                idx = inds[0]
                trace_ids = getattr(trace, "ids", None)
                clicked_id = trace_ids[idx] if trace_ids is not None and idx < len(trace_ids) else None
                on_click_callback(extract_treemap_click_filter(clicked_id))

        try:
            widget.data[0].on_click(_handle_click)
        except Exception:
            pass

    return widget
