import plotly.graph_objects as go
import pandas as pd
import numpy as np
from scipy.stats import gaussian_kde, iqr

def compute_reflected_kde(days_array: np.ndarray, t_grid: np.ndarray) -> np.ndarray:
    """
    Computes boundary-corrected Gaussian KDE on [0, +inf) using Schuster-Silverman
    mirror reflection to preserve zero-day weaponization spikes (0 <= t < 7 days).
    """
    t_clean = np.asarray(days_array, dtype=float)
    t_clean = t_clean[(t_clean >= 0) & (~np.isnan(t_clean))]
    n = len(t_clean)
    if n < 3:
        return np.zeros_like(t_grid)

    # Robust Silverman bandwidth factor using IQR to handle right-skewed lag
    std_dev = np.std(t_clean, ddof=1)
    iqr_scale = iqr(t_clean) / 1.34
    sigma_robust = min(std_dev, iqr_scale) if iqr_scale > 0 else std_dev
    h_opt = 0.9 * sigma_robust * (n ** (-0.2))
    
    bw_factor = max(h_opt / std_dev, 0.08) if std_dev > 0 else 0.25

    # Fit standard Gaussian KDE and evaluate mirror reflection: f_hat(t) + f_hat(-t)
    kde = gaussian_kde(t_clean, bw_method=bw_factor)
    density_reflected = kde.evaluate(t_grid) + kde.evaluate(-t_grid)
    density_reflected[t_grid < 0] = 0.0
    return density_reflected

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
    x_grid = np.linspace(0.0, max_days, 300)
    
    # Perceptually calibrated CIE HCL palette across cohorts
    palette = [
        "#ef4444", "#f97316", "#f59e0b", "#10b981",
        "#06b6d4", "#38bdf8", "#818cf8", "#c084fc"
    ]
    
    for i, v_name in enumerate(vendors):
        subset = kev_df[kev_df["vendor"] == v_name]["days_to_exploit"].values
        if len(subset) < 3:
            continue
            
        color = palette[i % len(palette)]
        density = compute_reflected_kde(subset, x_grid)
        
        # Normalize density height per baseline for clear vertical comparison
        max_d = density.max()
        density_scaled = (density / max_d * 0.85) if max_d > 0 else np.zeros_like(x_grid)
            
        baseline = i * 1.0
        curve_y = baseline + density_scaled
        
        # Density area fill (closed polygon)
        fig.add_trace(go.Scatter(
            x=np.concatenate([x_grid, x_grid[::-1]]),
            y=np.concatenate([curve_y, np.full_like(x_grid, baseline)]),
            fill="toself",
            fillcolor=f"rgba({int(color[1:3], 16)}, {int(color[3:5], 16)}, {int(color[5:7], 16)}, 0.40)",
            line=dict(color=color, width=2),
            name=f"{v_name} (n={len(subset)})",
            customdata=np.full_like(x_grid, v_name),
            hovertemplate=(
                f"<b>{v_name}</b><br>" +
                "Exposure Lag: %{x:.1f} days<br>" +
                "<extra></extra>"
            )
        ))
        
    fig.update_layout(
        title=dict(
            text="Exploitation Velocity Density by Vendor Cohort (Schuster-Silverman Mirror-Reflected KDE)",
            font=dict(size=14, color="#f8fafc")
        ),
        xaxis=dict(
            title="Elapsed Days to Weaponization (t_KEV - t_Disclosure)",
            range=[0, max_days],
            gridcolor="#1e293b",
            zerolinecolor="#334155"
        ),
        yaxis=dict(
            showticklabels=False,
            gridcolor="transparent",
            zeroline=False
        ),
        template="plotly_dark",
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        margin=dict(l=40, r=30, t=50, b=40),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=10)
        )
    )
    
    return fig
