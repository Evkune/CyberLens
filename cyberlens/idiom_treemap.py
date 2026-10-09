import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np

def create_architectural_treemap(
    df: pd.DataFrame,
    metric: str = "threat_weight"  # "threat_weight" or "cve_count"
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
    
    # Calculate derived risk metrics for hierarchical aggregation
    tree_df["cve_count"] = 1
    tree_df["threat_weight"] = tree_df["cvss_base"] * (tree_df["epss_score"] + 0.05)
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
    
    fig = px.treemap(
        grouped,
        path=[px.Constant("Enterprise Attack Surface"), "layer", "cwe_family", "vendor"],
        values=val_col,
        color="network_ratio",
        color_continuous_scale=["#38bdf8", "#f59e0b", "#ef4444"],
        range_color=[0.2, 0.9],
        custom_data=["cve_count", "kev_count", "mean_cvss", "network_ratio"]
    )
    
    fig.update_traces(
        textinfo="label+value",
        hovertemplate=(
            "<b>%{label}</b><br>"
            "• Aggregate Risk Weight: %{value:.1f}<br>"
            "• Vulnerability Count: %{customdata[0]}<br>"
            "• CISA KEV Exploits: %{customdata[1]}<br>"
            "• Avg CVSS: %{customdata[2]:.1f}<br>"
            "• Network Remotely Exploitable: %{customdata[3]:.1%}"
            "<extra></extra>"
        ),
        marker=dict(line=dict(width=1, color="#1e293b"))
    )
    
    fig.update_layout(
        title=dict(
            text="<b>Idiom 2: Architectural Weakness Taxonomy</b> (Hierarchical Space-Filling Treemap)",
            font=dict(size=15, color="#f8fafc")
        ),
        template="plotly_dark",
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0b1120",
        margin=dict(l=20, r=20, t=50, b=20),
        coloraxis_colorbar=dict(
            title="Remote Network Vector %",
            tickformat=".0%",
            thickness=14,
            len=0.75,
            xanchor="left",
            x=1.01
        )
    )
    
    return fig
