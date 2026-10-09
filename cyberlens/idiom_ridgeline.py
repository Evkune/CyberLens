import plotly.graph_objects as go
import pandas as pd
import numpy as np
from scipy.stats import gaussian_kde

def create_velocity_ridgeline_plot(
    df: pd.DataFrame,
    max_days: int = 120
) -> go.Figure:
    fig = go.Figure()
    
    # Filter to weaponized vulnerabilities with valid lag observations
    kev_df = df[df["is_kev"] & df["days_to_exploit"].notnull()].copy()
    
    if len(kev_df) < 5:
        fig.add_annotation(
            text="Insufficient weaponization event data for selected cohorts (min 5 events required).",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color="#94a3b8")
        )
        fig.update_layout(template="plotly_dark", paper_bgcolor="#0f172a", plot_bgcolor="#0f172a")
        return fig
        
    vendors = sorted(kev_df["vendor"].unique())
    x_grid = np.linspace(2, max_days, 250)
    
    # Palette per vendor cohort
    colors = [
        "#ef4444", "#f97316", "#f59e0b", "#10b981",
        "#06b6d4", "#38bdf8", "#818cf8", "#c084fc"
    ]
    
    for i, v_name in enumerate(vendors):
        subset = kev_df[kev_df["vendor"] == v_name]["days_to_exploit"].values
        if len(subset) < 3:
            continue
            
        color = colors[i % len(colors)]
        
        try:
            kde = gaussian_kde(subset, bw_method=0.35)
            density = kde(x_grid)
            # Scale density for vertical spacing (baseline offset)
            density_scaled = (density / density.max()) * 0.85
        except Exception:
            density_scaled = np.zeros_like(x_grid)
            
        baseline = i * 1.0
        curve_y = baseline + density_scaled
        
        # Area fill under the density curve
        fig.add_trace(go.Scatter(
            x=np.concatenate([x_grid, x_grid[::-1]]),
            y=np.concatenate([curve_y, np.full_like(x_grid, baseline)]),
            fill="toself",
            fillcolor=f"rgba({int(color[1:3], 16)}, {int(color[3:5], 16)}, {int(color[5:7], 16)}, 0.45)",
            line=dict(color=color, width=2),
            name=f"{v_name} (n={len(subset)})",
            customdata=np.full_like(x_grid, v_name),
            hovertemplate=(
                f"<b>{v_name}</b><br>"
                "• Days to Weaponization: %{x:.0f} days<br>"
                "• Relative Threat Velocity Density: %{y:.2f}"
                "<extra></extra>"
            )
        ))
        
        # Baseline reference line
        fig.add_trace(go.Scatter(
            x=[0, max_days],
            y=[baseline, baseline],
            mode="lines",
            line=dict(color="#334155", width=1),
            showlegend=False,
            hoverinfo="skip"
        ))
        
    fig.update_layout(
        title=dict(
            text="<b>Idiom 3: Exploitation Velocity Ridgeline Density</b> (Continuous Probability Distribution)",
            font=dict(size=15, color="#f8fafc")
        ),
        xaxis=dict(
            title="Elapsed Days from Disclosure to Active Weaponization (Continuous Scale)",
            range=[0, max_days],
            gridcolor="#1e293b",
            zerolinecolor="#334155"
        ),
        yaxis=dict(
            title="Technology Cohort (Separated Baseline)",
            tickmode="array",
            tickvals=[i * 1.0 for i in range(len(vendors))],
            ticktext=vendors,
            gridcolor="#1e293b",
            showticklabels=True
        ),
        template="plotly_dark",
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0b1120",
        margin=dict(l=80, r=30, t=50, b=50),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=10, color="#94a3b8")
        )
    )
    
    return fig
