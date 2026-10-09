import plotly.graph_objects as go
import pandas as pd
import numpy as np

def create_prioritization_bubble_plot(
    df: pd.DataFrame,
    cvss_thresh: float = 7.0,
    epss_thresh: float = 0.30,
    color_by: str = "threat_status"  # "threat_status" or "cluster"
) -> go.Figure:
    fig = go.Figure()
    
    if len(df) == 0:
        fig.add_annotation(
            text="No vulnerabilities matching the selected asset inventory.",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color="#94a3b8")
        )
        fig.update_layout(template="plotly_dark", paper_bgcolor="#0f172a", plot_bgcolor="#0f172a")
        return fig
        
    plot_df = df.copy()
    
    # Categorize threat status for distinct categorical hue encoding
    def get_status(row):
        if row["is_kev"]:
            return "Active In-The-Wild (CISA KEV)"
        elif row["epss_score"] >= epss_thresh:
            return "High Threat (Imminent Weaponization)"
        elif row["cvss_base"] >= cvss_thresh:
            return "Theoretical High (Paper Tiger)"
        return "Dormant / Low Priority"
        
    plot_df["status_label"] = plot_df.apply(get_status, axis=1)
    
    color_palette = {
        "Active In-The-Wild (CISA KEV)": "#ef4444",         # Red
        "High Threat (Imminent Weaponization)": "#f59e0b",  # Amber
        "Theoretical High (Paper Tiger)": "#38bdf8",        # Light Blue
        "Dormant / Low Priority": "#64748b"                 # Slate Gray
    }
    
    # Group by category to enable interactive Plotly legend filtering
    groups = plot_df["status_label"].unique()
    for grp in ["Active In-The-Wild (CISA KEV)", "High Threat (Imminent Weaponization)", "Theoretical High (Paper Tiger)", "Dormant / Low Priority"]:
        if grp not in groups:
            continue
        sub = plot_df[plot_df["status_label"] == grp]
        
        # Area sizing follows Stevens' law: scaled by cvss_impact
        marker_sizes = np.clip(sub["cvss_impact"] * 3.5, 6, 22)
        
        customdata = np.stack((
            sub["cve_id"],
            sub["vendor"],
            sub["product"],
            sub["cwe_family"],
            sub["attack_vector"],
            sub["privileges_required"]
        ), axis=-1)
        
        fig.add_trace(go.Scatter(
            x=sub["cvss_base"],
            y=sub["epss_score"],
            mode="markers",
            name=grp,
            marker=dict(
                size=marker_sizes,
                color=color_palette[grp],
                opacity=0.85 if "Active" in grp or "High" in grp else 0.45,
                line=dict(width=1, color="#ffffff" if "Active" in grp else "#334155")
            ),
            customdata=customdata,
            hovertemplate=(
                "<b>%{customdata[0]}</b> (%{customdata[1]} %{customdata[2]})<br>"
                "• CVSS Base: %{x:.1f}<br>"
                "• EPSS Exploit Prob: %{y:.2%}<br>"
                "• Weakness: %{customdata[3]}<br>"
                "• Attack Vector: %{customdata[4]} (Privs: %{customdata[5]})"
                "<extra></extra>"
            )
        ))
        
    # Add operational quadrant threshold lines
    fig.add_vline(
        x=cvss_thresh, line_dash="dash", line_color="#475569", line_width=1.5,
        annotation_text=f"CVSS Triage Threshold ({cvss_thresh:.1f})",
        annotation_position="top left", annotation_font=dict(size=10, color="#94a3b8")
    )
    fig.add_hline(
        y=epss_thresh, line_dash="dash", line_color="#475569", line_width=1.5,
        annotation_text=f"EPSS Weaponization Cutoff ({epss_thresh:.2f})",
        annotation_position="bottom right", annotation_font=dict(size=10, color="#94a3b8")
    )
    
    # Quadrant Alert Background Rectangles
    fig.add_shape(
        type="rect", xref="x", yref="y",
        x0=cvss_thresh, x1=10.0, y0=epss_thresh, y1=1.0,
        fillcolor="rgba(239, 68, 68, 0.08)", line_width=0, layer="below"
    )
    fig.add_shape(
        type="rect", xref="x", yref="y",
        x0=0.0, x1=cvss_thresh, y0=epss_thresh, y1=1.0,
        fillcolor="rgba(245, 158, 11, 0.08)", line_width=0, layer="below"
    )
    
    fig.update_layout(
        title=dict(
            text="<b>Idiom 1: Threat Prioritization Quadrant</b> (CVSS vs EPSS Exploit Probability)",
            font=dict(size=15, color="#f8fafc")
        ),
        xaxis=dict(
            title="Theoretical Severity (CVSS v3.1 Base Score)",
            range=[1.0, 10.2],
            gridcolor="#1e293b",
            zerolinecolor="#334155"
        ),
        yaxis=dict(
            title="Empirical Exploit Likelihood (FIRST.org EPSS 0-100%)",
            range=[-0.02, 1.05],
            tickformat=".0%",
            gridcolor="#1e293b",
            zerolinecolor="#334155"
        ),
        template="plotly_dark",
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0b1120",
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=11, color="#cbd5e1")
        ),
        margin=dict(l=60, r=30, t=60, b=50),
        hovermode="closest"
    )
    
    return fig
