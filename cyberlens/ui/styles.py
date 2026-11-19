from __future__ import annotations

from shiny import ui

from cyberlens.config import SLA_TIER_ORDER
from cyberlens.viz.theme import SLA_TIER_COLORS

SWISS_LIGHT_CSS = """
:root, [data-bs-theme="light"] {
    --bs-body-bg: #FFFFFF;
    --bs-body-color: #09090B;
    --bs-emphasis-color: #09090B;
    --bs-secondary-color: #52525B;
    --bs-tertiary-bg: #FAFAFA;
    --bs-border-color: #E4E4E7;
    --bs-border-radius: 3px;
    --bs-box-shadow: none;
    --bs-focus-ring-color: rgba(9, 9, 11, 0.15);
    --bs-form-select-bg: #FFFFFF;
    --bs-form-select-color: #09090B;
    --bs-form-control-bg: #FFFFFF;
    --bs-form-control-color: #09090B;
}
body {
    background-color: #FFFFFF;
    color: #09090B;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    -webkit-font-smoothing: antialiased;
}
.mono-num {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-variant-numeric: tabular-nums;
}

/* Header */
.editorial-header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 12px;
    border-bottom: 1px solid #E4E4E7;
    padding: 12px 0 10px 0;
    margin-bottom: 0;
}
.editorial-title {
    margin: 0;
    color: #09090B;
    font-weight: 700;
    font-size: 20px;
    letter-spacing: -0.02em;
}
.editorial-subtitle {
    color: #52525B;
    font-size: 12px;
    margin: 2px 0 0 0;
}
.snapshot-pill {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-variant-numeric: tabular-nums;
    background: #FAFAFA;
    color: #52525B;
    border: 1px solid #E4E4E7;
    border-radius: 3px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
}

/* Sidebar & Controls */
.bslib-sidebar-layout {
    width: 100% !important;
}
.bslib-sidebar-layout > .sidebar {
    background-color: #FAFAFA !important;
    border-right: 1px solid #E4E4E7 !important;
    color: #09090B !important;
}
.bslib-sidebar-layout > .sidebar label,
.bslib-sidebar-layout > .sidebar .control-label,
.bslib-sidebar-layout > .sidebar .form-label,
.bslib-sidebar-layout > .sidebar .form-check-label,
.shiny-input-container label,
.shiny-input-container .control-label,
.form-check-label,
.radio label,
.checkbox label {
    color: #09090B !important;
    font-size: 12px;
}
.bslib-sidebar-layout > .sidebar .collapse-toggle {
    color: #52525B !important;
}
.sidebar-section-title {
    color: #09090B;
    font-size: 10.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 6px;
}
.sidebar-divider {
    border: 0;
    border-top: 1px solid #E4E4E7;
    opacity: 1;
    margin: 12px 0;
}
select.form-select,
select.shiny-input-select,
.form-select {
    background-color: #FFFFFF !important;
    color: #09090B !important;
    border: 1px solid #D4D4D8 !important;
    border-radius: 3px !important;
    box-shadow: none !important;
    min-height: 34px;
    height: auto;
    font-size: 12px !important;
    line-height: 1.4;
    appearance: none !important;
    -webkit-appearance: none !important;
    -moz-appearance: none !important;
}
select.form-select::picker-icon {
    display: none !important;
}
select.form-select:focus,
.form-control:focus {
    border-color: #09090B !important;
    box-shadow: none !important;
}
select.form-select option,
select.shiny-input-select option {
    background-color: #FFFFFF;
    color: #09090B;
}
.selectize-control.single .selectize-input {
    background-color: #FFFFFF !important;
    background-image: none !important;
    color: #09090B !important;
    border: 1px solid #D4D4D8 !important;
    border-radius: 3px !important;
    box-shadow: none !important;
}
.selectize-control.single .selectize-input::after {
    border-color: #52525B transparent transparent transparent !important;
}
.selectize-dropdown {
    background-color: #FFFFFF !important;
    color: #09090B !important;
    border: 1px solid #D4D4D8 !important;
    border-radius: 3px !important;
    box-shadow: none !important;
}
.selectize-dropdown .option,
.selectize-dropdown .active {
    color: #09090B !important;
}
.selectize-dropdown .active {
    background-color: #F4F4F5 !important;
}
.form-check-input {
    background-color: #FFFFFF;
    border-color: #A1A1AA;
    box-shadow: none !important;
}
.form-check-input[type="checkbox"]:not([role="switch"]) {
    border-radius: 3px !important;
}
.form-check-input:checked {
    background-color: #09090B !important;
    border-color: #09090B !important;
}
.btn-swiss {
    background-color: #FFFFFF !important;
    color: #09090B !important;
    border: 1px solid #D4D4D8 !important;
    border-radius: 3px !important;
    box-shadow: none !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    padding: 3px 9px !important;
}
.btn-swiss:hover {
    background-color: #F4F4F5 !important;
    border-color: #09090B !important;
}
.btn-swiss-dark {
    background-color: #09090B !important;
    color: #FFFFFF !important;
    border: 1px solid #09090B !important;
    border-radius: 3px !important;
    box-shadow: none !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    padding: 4px 11px !important;
}
.btn-swiss-dark:hover {
    background-color: #27272A !important;
    border-color: #27272A !important;
}

/* IonRangeSlider Light Calibration */
.irs--shiny .irs-min,
.irs--shiny .irs-max {
    background-color: #F4F4F5 !important;
    color: #52525B !important;
    border-radius: 3px !important;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-variant-numeric: tabular-nums;
}
.irs--shiny .irs-grid-text {
    color: #52525B !important;
    font-family: ui-monospace, SFMono-Regular, monospace;
}
.irs--shiny .irs-line {
    background: #E4E4E7 !important;
    border-color: #E4E4E7 !important;
}
.irs--shiny .irs-bar {
    background: #09090B !important;
    border-color: #09090B !important;
}
.irs--shiny .irs-single,
.irs--shiny .irs-from,
.irs--shiny .irs-to {
    background-color: #09090B !important;
    color: #FFFFFF !important;
    border-radius: 3px !important;
    font-weight: 600;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-variant-numeric: tabular-nums;
}
.irs--shiny .irs-handle {
    background-color: #FFFFFF !important;
    border: 2px solid #09090B !important;
    box-shadow: none !important;
}

/* Flat Editorial Sections (Anti-Card-Soup) */
.card, .soc-card, .soc-section {
    background-color: #FFFFFF !important;
    border: none !important;
    border-radius: 0 !important;
    box-shadow: none !important;
    margin-bottom: 0;
    padding: 14px 0;
}
.soc-section-bordered {
    border-bottom: 1px solid #E4E4E7 !important;
}
.editorial-two-col {
    border-bottom: 1px solid #E4E4E7;
}
@media (min-width: 992px) {
    .editorial-col-left {
        border-right: 1px solid #E4E4E7;
        padding-right: 18px !important;
    }
    .editorial-col-right {
        padding-left: 18px !important;
    }
}
/* Lock Plotly widget width inside responsive Bootstrap columns */
.soc-section .shiny-ipywidget-output,
.soc-section .js-plotly-plot,
.soc-section .plot-container,
.soc-section .svg-container,
.soc-card .shiny-ipywidget-output,
.soc-card .js-plotly-plot,
.soc-card .plot-container,
.soc-card .svg-container {
    width: 100% !important;
    max-width: 100% !important;
}
.card-header-bar {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: baseline;
    gap: 10px;
    margin-bottom: 8px;
    padding-bottom: 6px;
    border-bottom: 1px solid #E4E4E7;
}
.card-header-title {
    font-size: 12px;
    font-weight: 700;
    color: #09090B;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}
.card-header-hint {
    font-size: 11px;
    color: #52525B;
}

/* Single Horizontal KPI Strip with 1px Vertical Hairlines */
.kpi-strip {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    border-bottom: 1px solid #E4E4E7;
    background-color: #FFFFFF;
}
@media (max-width: 991.98px) {
    .kpi-strip {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
@media (max-width: 575.98px) {
    .kpi-strip {
        grid-template-columns: 1fr;
    }
}
.kpi-cell {
    padding: 14px 16px;
    border-right: 1px solid #E4E4E7;
    background-color: #FFFFFF;
}
.kpi-cell:first-child {
    padding-left: 0;
}
.kpi-cell:last-child {
    border-right: none;
    padding-right: 0;
}
@media (max-width: 991.98px) {
    .kpi-cell {
        padding: 12px;
        border-bottom: 1px solid #E4E4E7;
    }
    .kpi-cell:first-child {
        padding-left: 12px;
    }
    .kpi-cell:nth-child(2n) {
        border-right: none;
    }
}
.kpi-title {
    font-size: 10.5px;
    text-transform: uppercase;
    color: #52525B;
    font-weight: 700;
    letter-spacing: 0.05em;
    line-height: 1.3;
}
.kpi-val {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-variant-numeric: tabular-nums;
    font-size: 26px;
    font-weight: 700;
    margin-top: 4px;
    line-height: 1.15;
    color: #09090B;
}
.kpi-sub {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-variant-numeric: tabular-nums;
    font-size: 11px;
    color: #52525B;
    margin-top: 4px;
}

/* Policy Banner & Cross-Filter Strip */
.little-law-banner {
    background: #FFFFFF;
    border-bottom: 1px solid #E4E4E7;
    padding: 8px 0;
    margin-bottom: 0;
    font-size: 11.5px;
    color: #52525B;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
}
.filter-chips-bar {
    background: #FAFAFA;
    border-bottom: 1px solid #E4E4E7;
    padding: 7px 10px;
    margin-bottom: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    font-size: 11.5px;
    color: #52525B;
}
.filter-chip {
    display: inline-flex;
    align-items: center;
    background: #FFFFFF;
    color: #09090B;
    border: 1px solid #D4D4D8;
    border-radius: 3px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 600;
    margin-right: 6px;
}
.filter-chip.chip-preset {
    background: #FFFBEB;
    color: #B45309;
    border-color: #FCD34D;
}
.filter-chip.chip-pin {
    background: #FEF2F2;
    color: #B91C1C;
    border-color: #FECACA;
}
.sla-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 3px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-variant-numeric: tabular-nums;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.02em;
}

/* CVE Inspector */
.cve-inspector-card {
    background-color: #FAFAFA;
    border: 1px solid #E4E4E7;
    border-radius: 0;
    padding: 12px 14px;
    height: 100%;
}
.cve-meta-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
    margin: 10px 0;
}
.cve-meta-item {
    background: #FFFFFF;
    border: 1px solid #E4E4E7;
    border-radius: 0;
    padding: 6px 9px;
    min-width: 0;
    overflow: hidden;
}
.cve-meta-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #52525B;
    font-weight: 600;
}
.cve-meta-val {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-variant-numeric: tabular-nums;
    font-size: 11.5px;
    font-weight: 600;
    color: #09090B;
    margin-top: 2px;
    line-height: 1.3;
    overflow-wrap: anywhere;
}
.cve-action-box {
    background: #FEF2F2;
    border: 1px solid #FECACA;
    border-left: 3px solid #B91C1C;
    border-radius: 0;
    padding: 8px 10px;
    margin-top: 8px;
    font-size: 11.5px;
    color: #7F1D1D;
}
.external-link-btn {
    display: inline-block;
    background: #FFFFFF;
    color: #09090B !important;
    border: 1px solid #D4D4D8;
    border-radius: 3px;
    padding: 4px 9px;
    font-size: 11px;
    font-weight: 600;
    text-decoration: none !important;
    margin-right: 4px;
}
.external-link-btn:hover {
    background: #F4F4F5;
    border-color: #09090B;
}
.ml-summary-box {
    background: #FFFFFF;
    border: 1px solid #E4E4E7;
    border-radius: 0;
    padding: 8px 10px;
    margin-top: 8px;
    font-size: 11px;
    color: #52525B;
}

/* Light Calibration for Bootstrap Accordion & Shiny DataGrid */
.accordion,
.accordion-item {
    background-color: #FFFFFF !important;
    border-color: #E4E4E7 !important;
    border-radius: 0 !important;
    color: #09090B !important;
    box-shadow: none !important;
}
.accordion-button {
    background-color: #FAFAFA !important;
    color: #09090B !important;
    font-weight: 600;
    font-size: 12px;
    border-radius: 0 !important;
    box-shadow: none !important;
}
.accordion-button:not(.collapsed) {
    background-color: #F4F4F5 !important;
    color: #09090B !important;
    box-shadow: inset 0 -1px 0 #E4E4E7 !important;
}
.accordion-button::after {
    filter: none !important;
}
.accordion-body {
    background-color: #FFFFFF !important;
    color: #52525B !important;
    font-size: 12.5px;
    line-height: 1.55;
}
.accordion-body strong {
    color: #09090B;
}
shiny-data-frame {
    --bs-body-bg: #FFFFFF;
    --bs-body-color: #09090B;
    --bs-emphasis-color: #09090B;
    --bs-secondary-color: #52525B;
    --bs-tertiary-bg: #FAFAFA;
    --bs-border-color: #E4E4E7;
    --bs-table-bg: #FFFFFF;
    --bs-table-color: #09090B;
    --bs-table-border-color: #E4E4E7;
    --bs-table-hover-bg: #F4F4F5;
    --bs-table-striped-bg: #FAFAFA;
    --shiny-datagrid-grid-header-bgcolor: #FAFAFA;
    --shiny-datagrid-grid-body-hover-bgcolor: #F4F4F5;
    --shiny-datagrid-grid-body-selected-bgcolor: #EFF6FF;
    --shiny-datagrid-grid-body-selected-color: #09090B;
    --shiny-datagrid-grid-gridlines-color: #E4E4E7;
    --shiny-datagrid-grid-header-gridlines-color: #E4E4E7;
    color: #09090B;
    font-size: 12px;
    border-top: 1px solid #E4E4E7;
    border-bottom: 1px solid #E4E4E7;
}
shiny-data-frame table {
    color: #09090B !important;
    background-color: #FFFFFF !important;
}
shiny-data-frame thead th {
    background-color: #FAFAFA !important;
    color: #09090B !important;
    border-bottom: 1px solid #E4E4E7 !important;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    white-space: nowrap;
}
shiny-data-frame tbody td {
    white-space: nowrap;
    color: #09090B !important;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-variant-numeric: tabular-nums;
    font-size: 11.5px;
}
shiny-data-frame input,
shiny-data-frame select,
shiny-data-frame .form-control {
    background-color: #FFFFFF !important;
    color: #09090B !important;
    border: 1px solid #D4D4D8 !important;
    border-radius: 3px !important;
    box-shadow: none !important;
    font-size: 11px !important;
}
shiny-data-frame input::placeholder {
    color: #71717A !important;
}
shiny-data-frame .shiny-data-grid-summary,
.shiny-data-grid-summary {
    color: #52525B !important;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-variant-numeric: tabular-nums;
    font-size: 11px;
}
shiny-data-frame tbody tr[aria-selected="true"],
shiny-data-frame tbody tr.selected {
    background-color: #EFF6FF !important;
    color: #09090B !important;
}

/* Minimalist Footer */
.editorial-footer {
    border-top: 1px solid #E4E4E7;
    margin-top: 18px;
    padding: 12px 0 16px 0;
    font-size: 11px;
    color: #52525B;
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
}
"""

SOC_DARK_CSS = SWISS_LIGHT_CSS


def get_soc_styles() -> ui.Tag:
    return ui.tags.head(
        ui.tags.script("document.documentElement.setAttribute('data-bs-theme', 'light');"),
        ui.tags.style(SWISS_LIGHT_CSS),
    )


def get_sla_badge_style(sla_tier: str) -> str:
    color = SLA_TIER_COLORS.get(str(sla_tier), SLA_TIER_COLORS[SLA_TIER_ORDER[-1]])
    text_color = "#52525B" if str(sla_tier) == SLA_TIER_ORDER[-1] else color
    return (
        f"background: {color}14; color: {text_color}; border: 1px solid {color}55; "
        "padding: 2px 7px; border-radius: 3px; font-size: 11px; font-weight: 700; "
        "font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; "
        "font-variant-numeric: tabular-nums;"
    )
