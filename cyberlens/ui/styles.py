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

/* Native Progressive Disclosure (<details>) in Sidebar */
.swiss-disclosure {
    border-top: 1px solid #E4E4E7;
    padding: 8px 0;
}
.swiss-disclosure:last-of-type {
    border-bottom: 1px solid #E4E4E7;
}
.swiss-disclosure-summary {
    list-style: none;
    display: flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    user-select: none;
    padding: 2px 0;
    color: #09090B;
    font-size: 10.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
.swiss-disclosure-summary::-webkit-details-marker {
    display: none;
}
.swiss-disclosure-summary::before {
    content: "";
    display: inline-block;
    width: 10px;
    height: 10px;
    flex-shrink: 0;
    background-color: #52525B;
    -webkit-mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.25L6 7.5L9 4.25' fill='none' stroke='black' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") no-repeat center / contain;
    mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.25L6 7.5L9 4.25' fill='none' stroke='black' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") no-repeat center / contain;
    rotate: -90deg;
}
.swiss-disclosure[open] > .swiss-disclosure-summary::before {
    rotate: 0deg;
}
@media (prefers-reduced-motion: no-preference) {
    .swiss-disclosure-summary::before {
        transition: rotate 0.16s ease-out;
    }
    .swiss-disclosure::details-content {
        interpolate-size: allow-keywords;
        overflow: clip;
        contain: layout;
        transition: block-size 0.2s ease-out, content-visibility 0.2s ease-out allow-discrete;
    }
    .swiss-disclosure:not([open])::details-content {
        block-size: 0;
    }
}
.disclosure-label {
    flex: 1 1 auto;
}
.disclosure-badge {
    font-size: 10px;
    font-weight: 600;
    color: #52525B;
    background: #FFFFFF;
    border: 1px solid #E4E4E7;
    border-radius: 3px;
    padding: 1px 5px;
    letter-spacing: 0.02em;
    text-transform: none;
}
.disclosure-badge-warn {
    color: #B45309;
    background: #FFFBEB;
    border-color: #FCD34D;
}
.swiss-disclosure-body {
    padding-top: 8px;
}
.vendor-checkbox-grid .shiny-options-group {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 2px 6px;
}
.vendor-checkbox-grid .checkbox {
    margin: 0;
}
.vendor-checkbox-grid label {
    font-size: 11.5px !important;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

/* Main Workspace Container Query Context */
.editorial-main {
    container-type: inline-size;
    container-name: workspace;
    min-width: 0;
}

/* Numbered Editorial Section Headers & Micro-Cues */
.card-header-left {
    display: inline-flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 7px;
    min-width: 0;
}
.card-header-right {
    display: inline-flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
}
.section-step-num {
    font-size: 10px;
    font-weight: 700;
    color: #52525B;
    border: 1px solid #E4E4E7;
    background: #FAFAFA;
    border-radius: 2px;
    padding: 0px 4px;
    line-height: 1.45;
}
.shape-micro-key {
    font-size: 10.5px;
    color: #71717A;
    margin: -2px 0 4px 0;
    letter-spacing: 0.01em;
}
.btn-reset-zoom,
.btn-clear-selection {
    background-color: #FFFFFF !important;
    color: #09090B !important;
    border: 1px solid #09090B !important;
    border-radius: 3px !important;
    font-size: 10.5px !important;
    font-weight: 600 !important;
    padding: 1px 7px !important;
    line-height: 1.5;
    cursor: pointer;
    white-space: nowrap;
}
.btn-reset-zoom:hover,
.btn-clear-selection:hover {
    background-color: #F4F4F5 !important;
}
.btn-clear-selection {
    border-color: #B91C1C !important;
    color: #B91C1C !important;
    background-color: #FEF2F2 !important;
}
.btn-clear-selection:hover {
    background-color: #FEE2E2 !important;
}
.btn-reset-zoom[hidden] {
    display: none !important;
}

/* Container-Aware Patch Queue + Inspector Split */
.queue-controls-inline {
    display: flex;
    flex-wrap: nowrap;
    align-items: center;
    gap: 10px;
}
.queue-controls-inline .shiny-input-container {
    margin-bottom: 0 !important;
}
.queue-controls-inline .shiny-options-group {
    display: flex;
    flex-wrap: nowrap;
    gap: 10px;
    align-items: center;
}
.queue-controls-inline .radio-inline,
.queue-controls-inline .form-check-inline {
    margin-right: 0 !important;
    white-space: nowrap;
}
.queue-split-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 14px;
    align-items: start;
}
@container workspace (min-width: 1040px) {
    .queue-split-grid {
        grid-template-columns: minmax(0, 1.85fr) minmax(320px, 1fr);
        gap: 16px;
    }
}
@container workspace (max-width: 1039px) {
    .cve-meta-grid {
        grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .queue-controls-inline {
        flex-wrap: wrap;
    }
}
.queue-grid-pane,
.queue-inspector-pane {
    min-width: 0;
}

/* Clean Monochrome Plotly Modebar (suppress marketing/cloud buttons) */
.js-plotly-plot .plotly .modebar-btn[data-title*="Share"],
.js-plotly-plot .plotly .modebar-btn[data-title*="Chart Studio"],
.js-plotly-plot .plotly .modebar-btn[data-title*="Edit chart"],
.js-plotly-plot .plotly .plotly-logomark,
.js-plotly-plot .plotly a.modebar-btn--logo {
    display: none !important;
}
.js-plotly-plot .plotly .modebar {
    background: transparent !important;
    opacity: 0;
    transition: opacity 0.15s ease-out;
}
.js-plotly-plot:hover .plotly .modebar {
    opacity: 1;
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

CYBERLENS_INTERACTION_JS = """
(function() {
    const DEFAULT_X = [0.0, 10.3];
    const DEFAULT_Y_LINEAR = [-0.04, 1.06];
    const DEFAULT_Y_LOG = [-4.05, 0.08];

    function getBubbleGd() {
        const root = document.getElementById('plot_bubble');
        return root ? root.querySelector('.js-plotly-plot') : null;
    }

    function isEmptyCartesian(gd) {
        const fl = gd && gd._fullLayout;
        if (!fl || !fl.xaxis || !fl.yaxis) return true;
        return fl.xaxis.visible === false || fl.yaxis.visible === false;
    }

    function isBubbleZoomed(gd) {
        if (!gd || isEmptyCartesian(gd)) return false;
        const fl = gd._fullLayout;
        const xr = fl.xaxis.range;
        const yr = fl.yaxis.range;
        if (!xr || !yr) return false;
        const isLog = fl.yaxis.type === 'log';
        const defY = isLog ? DEFAULT_Y_LOG : DEFAULT_Y_LINEAR;
        const epsX = 0.08;
        const epsY = isLog ? 0.04 : 0.015;
        return (
            Math.abs(Number(xr[0]) - DEFAULT_X[0]) > epsX ||
            Math.abs(Number(xr[1]) - DEFAULT_X[1]) > epsX ||
            Math.abs(Number(yr[0]) - defY[0]) > epsY ||
            Math.abs(Number(yr[1]) - defY[1]) > epsY
        );
    }

    function syncResetButton(gd) {
        const btn = document.getElementById('btn_reset_bubble_zoom');
        if (!btn) return;
        const zoomed = isBubbleZoomed(gd || getBubbleGd());
        btn.hidden = !zoomed;
        btn.setAttribute('aria-hidden', String(!zoomed));
    }

    function resetBubbleZoom() {
        const btn = document.getElementById('btn_reset_bubble_zoom');
        if (btn) {
            btn.hidden = true;
            btn.setAttribute('aria-hidden', 'true');
        }
        if (window.Shiny && typeof window.Shiny.setInputValue === 'function') {
            window.Shiny.setInputValue('bubble_zoom_reset_req', Date.now(), { priority: 'event' });
        }
        setTimeout(function() { syncResetButton(); }, 250);
    }

    function clearBubbleSelectionVisuals(gd) {
        const target = gd || getBubbleGd();
        if (!target) return;
        target.querySelectorAll('.select-outline, .select-outline-1, .select-outline-2').forEach(function(el) {
            el.remove();
        });
        if (target.layout && Array.isArray(target.layout.selections)) {
            target.layout.selections = [];
        }
    }

    function clearBubbleSelection() {
        const gd = getBubbleGd();
        clearBubbleSelectionVisuals(gd);
        if (window.Shiny && typeof window.Shiny.setInputValue === 'function') {
            window.Shiny.setInputValue('bubble_clear_selection_req', Date.now(), { priority: 'event' });
        }
    }

    function bindBubblePlot(gd) {
        if (!gd || gd._clZoomBound) return;
        gd._clZoomBound = true;
        if (typeof gd.on === 'function') {
            gd.on('plotly_relayout', function() { syncResetButton(gd); });
            gd.on('plotly_afterplot', function() {
                syncResetButton(gd);
                if (!document.getElementById('btn_clear_bubble_selection')) {
                    clearBubbleSelectionVisuals(gd);
                }
            });
            gd.on('plotly_deselect', function() {
                clearBubbleSelection();
            });
            gd.on('plotly_doubleclick', function() {
                if (document.getElementById('btn_clear_bubble_selection')) {
                    clearBubbleSelection();
                }
                setTimeout(function() { syncResetButton(gd); }, 40);
            });
        }
        syncResetButton(gd);
    }

    // Strict plot-area-scoped wheel zoom on #plot_bubble:
    // Outside the inner plotting rectangle (margins, legend, axes, or empty state),
    // stop propagation before Plotly's scrollZoom handler runs so the page scrolls naturally.
    document.addEventListener('wheel', function(e) {
        const bubbleRoot = e.target && e.target.closest ? e.target.closest('#plot_bubble') : null;
        if (!bubbleRoot) return;
        const gd = bubbleRoot.querySelector('.js-plotly-plot');
        if (!gd || !gd._fullLayout || !gd._fullLayout._size || isEmptyCartesian(gd)) {
            e.stopPropagation();
            return;
        }
        const rect = gd.getBoundingClientRect();
        const sz = gd._fullLayout._size;
        const insidePlot = (
            e.clientX >= rect.left + sz.l &&
            e.clientX <= rect.left + sz.l + sz.w &&
            e.clientY >= rect.top + sz.t &&
            e.clientY <= rect.top + sz.t + sz.h
        );
        if (!insidePlot) {
            e.stopPropagation();
        }
    }, { capture: true });

    // Attach listeners whenever Plotly FigureWidget finishes initial render
    document.addEventListener('plotlywidget-after-render', function(ev) {
        const el = ev && ev.detail && ev.detail.element;
        if (el && el.closest && el.closest('#plot_bubble')) {
            bindBubblePlot(el);
        }
    });

    // Reset Zoom, Clear Selection, Reset All Filters & Escape key synchronization
    document.addEventListener('click', function(e) {
        if (!e.target || !e.target.closest) return;
        if (e.target.closest('#btn_clear_bubble_selection')) {
            e.preventDefault();
            clearBubbleSelection();
            return;
        }
        if (e.target.closest('#btn_reset_bubble_zoom')) {
            e.preventDefault();
            resetBubbleZoom();
            return;
        }
        if (e.target.closest('[id$="btn_reset_cross_filters"]')) {
            clearBubbleSelectionVisuals();
            setTimeout(function() {
                clearBubbleSelectionVisuals();
                syncResetButton();
            }, 220);
        }
    });

    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape') return;
        const gd = getBubbleGd();
        const hasVisualOutline = Boolean(gd && gd.querySelector('.select-outline'));
        if (document.getElementById('btn_clear_bubble_selection') || hasVisualOutline) {
            clearBubbleSelection();
        }
    });

    document.addEventListener('change', function(e) {
        if (e.target && e.target.closest && e.target.closest('[id$="y_scale"]')) {
            setTimeout(function() { syncResetButton(); }, 180);
        }
    });

    // Keep all responsive FigureWidgets synced on sidebar collapse/expand & container resize
    function initResizeSync() {
        const main = document.querySelector('.editorial-main');
        if (!main || typeof ResizeObserver === 'undefined') return;
        let lastWidth = Math.round(main.getBoundingClientRect().width);
        let rafId = null;
        const ro = new ResizeObserver(function(entries) {
            const w = Math.round(entries[0].contentRect.width);
            if (w <= 0 || Math.abs(w - lastWidth) < 2) return;
            lastWidth = w;
            if (rafId) cancelAnimationFrame(rafId);
            rafId = requestAnimationFrame(function() {
                window.dispatchEvent(new Event('resize'));
            });
        });
        ro.observe(main);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initResizeSync);
    } else {
        initResizeSync();
    }
})();
"""


def get_soc_styles() -> ui.Tag:
    return ui.tags.head(
        ui.tags.script("document.documentElement.setAttribute('data-bs-theme', 'light');"),
        ui.tags.style(SWISS_LIGHT_CSS),
        ui.tags.script(CYBERLENS_INTERACTION_JS),
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
