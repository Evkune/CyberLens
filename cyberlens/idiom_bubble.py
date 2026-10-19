import plotly.graph_objects as go
import pandas as pd
import numpy as np

def create_prioritization_bubble_plot(
    df: pd.DataFrame,
    cvss_thresh: float = 7.0,
    epss_thresh: float = 0.30,
    color_by: str = "threat_status"
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
    
    # Calibrated CIE HCL Palette & 3-Tier Discrete Opacity (Topic 8 Compliance)
    style_spec = {
        "Dormant / Low Priority": {
            "color": "#94A3B8",
            "opacity": 0.20,
            "line_width": 0,
            "line_color": "transparent",
            "zorder": 1
        },
        "Theoretical High (Paper Tiger)": {
            "color": "#3B7DD8",
            "opacity": 0.25,
            "line_width": 0,
            "line_color": "transparent",
            "zorder": 2
        },
        "High Threat (Imminent Weaponization)": {
            "color": "#E69F00",
            "opacity": 0.65,
            "line_width": 0.8,
            "line_color": "#B45309",
            "zorder": 3
        },
        "Active In-The-Wild (CISA KEV)": {
            "color": "#D92B2B",
            "opacity": 0.92,
            "line_width": 1.2,
            "line_color": "#FFFFFF",
            "zorder": 4
        }
    }
    
    # Stevens' Power Law Calibration: Area = A_min + k * (CVSS Impact)^0.7
    # Ensures 2D mark area scales with human perceptual power law (Topic 8, Slide 27)
    A_min = 28.27   # Minimum clickable target area (r_min = 3px)
    k_scale = 167.61
    plot_df["impact_area"] = A_min + k_scale * np.power(plot_df["cvss_impact"].clip(lower=0.0), 0.7)
    
    # Plotly sizeref calibration for maximum bubble diameter D_max = 28px
    D_max = 28.0
    max_area = plot_df["impact_area"].max()
    sizeref_val = (2.0 * max_area) / (D_max ** 2) if max_area > 0 else 1.0

    # Render traces following painter's algorithm: background density first, focal pop-out last
    ordered_groups = sorted(style_spec.keys(), key=lambda g: style_spec[g]["zorder"])
    
    for grp in ordered_groups:
        sub = plot_df[plot_df["status_label"] == grp]
        if len(sub) == 0:
            continue
            
        cfg = style_spec[grp]
        
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
                size=sub["impact_area"],
                sizemode="area",
                sizeref=sizeref_val,
                sizemin=3.0,
                color=cfg["color"],
                opacity=cfg["opacity"],
                line=dict(width=cfg["line_width"], color=cfg["line_color"])
            ),
            customdata=customdata,
            hovertemplate=(
                "<b>%{customdata[0]}</b> (%{customdata[1]} %{customdata[2]})<br>"
                "CVSS Base: %{x:.1f} | EPSS: %{y:.2%}<br>"
                "Weakness: %{customdata[3]}<br>"
                "Vector: %{customdata[4]} (Privs: %{customdata[5]})<br>"
                f"Status: <i>{grp}</i><extra></extra>"
            )
        ))
        
    # Crosshair Triage Threshold Boundaries
    fig.add_vline(
        x=cvss_thresh, 
        line=dict(color="#64748b", dash="dash", width=1.5),
        annotation_text=f"CVSS Cutoff ({cvss_thresh:.1f})",
        annotation_position="top left",
        annotation_font=dict(size=10, color="#94a3b8")
    )
    fig.add_hline(
        y=epss_thresh, 
        line=dict(color="#64748b", dash="dash", width=1.5),
        annotation_text=f"EPSS Cutoff ({epss_thresh:.0%})",
        annotation_position="bottom right",
        annotation_font=dict(size=10, color="#94a3b8")
    )
    
    # Locked coordinate frame to preserve spatial constancy (Stevens' law a=1.0)
    fig.update_layout(
        title=dict(
            text="Threat Prioritization: Theoretical Severity vs Empirical Weaponization",
            font=dict(size=14, color="#f8fafc")
        ),
        xaxis=dict(
            title="Theoretical Technical Severity (NVD CVSS v3.1 Base Score)",
            range=[0.0, 10.3],
            gridcolor="#1e293b",
            zerolinecolor="#334155"
        ),
        yaxis=dict(
            title="Empirical Exploit Likelihood (FIRST.org EPSS v3 30-Day Probability)",
            range=[-0.03, 1.05],
            gridcolor="#1e293b",
            zerolinecolor="#334155"
        ),
        template="plotly_dark",
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=10)
        ),
        margin=dict(l=50, r=30, t=60, b=50)
    )
    
    return fig
