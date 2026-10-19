import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np

def create_architectural_treemap(
    df: pd.DataFrame,
    metric: str = "threat_weight"
) -> go.Figure:
    if len(df) == 0:
        fig = go.Figure()
        fig.add_annotation(
            text="No vulnerabilities matching current selection.",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color="#94a3b8")
        )
        fig.update_layout(template="plotly_dark", paper_bgcolor="#0f172a", plot_bgcolor="#0f172a")
        return fig
        
    tree_df = df.copy()
    
    # Expected Risk Formulation: Expected Loss = Probability (EPSS) * Severity (CVSS)
    tree_df["cve_count"] = 1
    tree_df["threat_weight"] = tree_df["cvss_base"] * (tree_df["epss_score"] + 0.02)
    tree_df["is_network_num"] = (tree_df["attack_vector"] == "Network").astype(int)
    
    # Aggregation for hierarchical structure: Layer -> CWE Family -> Vendor
    grouped = tree_df.groupby(["layer", "cwe_family", "vendor"]).agg(
        cve_count=("cve_count", "sum"),
        threat_weight=("threat_weight", "sum"),
        network_ratio=("is_network_num", "mean"),
        mean_cvss=("cvss_base", "mean"),
        kev_count=("is_kev", "sum")
    ).reset_index()
    
    val_col = "threat_weight" if metric == "threat_weight" else "cve_count"
    
    # Topic 8: Perceptually uniform sequential ramp (YlOrRd desaturated for large tiles)
    fig = px.treemap(
        grouped,
        path=[px.Constant("Enterprise Attack Surface"), "layer", "cwe_family", "vendor"],
        values=val_col,
        color="network_ratio",
        color_continuous_scale="YlOrRd",
        range_color=[0.1, 0.9],
        custom_data=["cve_count", "kev_count", "mean_cvss", "network_ratio"]
    )
    
    # Topic 7: Squarified layout packing to minimize area judgment distortion
    fig.update_traces(
        textinfo="label+value",
        tiling=dict(packing="squarify"),
        hovertemplate=(
            "<b>%{label}</b><br>"
            "• Aggregate Threat Weight: %{value:.1f}<br>"
            "• Vulnerability Count: %{customdata[0]}<br>"
            "• Confirmed KEV Exploits: %{customdata[1]}<br>"
            "• Mean CVSS: %{customdata[2]:.1f}<br>"
            "• Network Exposure Ratio: %{customdata[3]:.1%}"
            "<extra></extra>"
        ),
        marker=dict(line=dict(width=1.2, color="#0f172a"))
    )
    
    fig.update_layout(
        title=dict(
            text="Architectural Weakness Containment Hierarchy (Space-Filling Treemap)",
            font=dict(size=14, color="#f8fafc")
        ),
        template="plotly_dark",
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        margin=dict(l=10, r=10, t=45, b=10),
        coloraxis_colorbar=dict(
            title=dict(text="Network Exposure", font=dict(size=11, color="#94a3b8")),
            tickformat=".0%",
            tickfont=dict(size=9, color="#94a3b8"),
            len=0.75
        )
    )
    
    return fig
