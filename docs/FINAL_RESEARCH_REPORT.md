# CyberLens: Threat-Informed Visual Analytics for Risk-Based Vulnerability Management (RBVM)

**Academic Research & Engineering Report**  
**Course:** Data Visualization (103001004) — Master Universitario en Software e Inteligencia Artificial  
**Institution:** Escuela Técnica Superior de Ingenieros Informáticos (ETSIINF), Universidad Politécnica de Madrid (UPM)  
**Coordinator:** Prof. Pablo Toharia Rabasco  
**Date:** October 2026  

**Project Authors & Contributions:**
- **Evan Gendrot** — *Lead Software Architect & Cyber Threat Intelligence Lead* (Erasmus / INSA Rennes & ETSIINF UPM)
- **Minerva Nayeli Rosas Sanchez** — *Process Integration & Enterprise Reporting Lead* (Mechatronics & Systems Engineering, ETSIINF UPM)

**Project Resources:**
- **Public GitHub Repository:** [https://github.com/Evkune/CyberLens](https://github.com/Evkune/CyberLens)
- **Core Technology Stack:** Python 3.12, Shiny for Python, Plotly, Scikit-Learn, SciPy, Pandas.
- **Reference Dataset:** Unified correlation of NIST NVD (CVSS v3.1), FIRST.org EPSS v3, and CISA KEV (4,500+ records).

---

## Abstract

Enterprise Security Operations Centers (SOCs) are overwhelmed by alert fatigue: with more than 28,000 Common Vulnerabilities and Exposures (CVEs) published annually, compliance mandates force teams to patch every vulnerability scoring High or Critical ($\text{CVSS} \ge 7.0$). However, empirical threat telemetry shows that **fewer than 4.5% of published CVEs are ever exploited in real-world attacks**. Simultaneously, threat actors routinely chain Medium-severity vulnerabilities ($4.0 \le \text{CVSS} \le 6.9$) for local privilege escalation (LPE) and lateral movement, knowing these flaws bypass static compliance filters.

**CyberLens** is an interactive Visual Analytics system designed to solve this prioritization dilemma through **Tamara Munzner’s Four-Level Nested Model**. By correlating theoretical technical severity (NVD CVSS v3.1), empirical exploitation probability (FIRST.org EPSS v3), and confirmed in-the-wild exploitation (CISA KEV), CyberLens delivers three coordinated visual idioms:
1. **A Bivariate Prioritization Bubble Plot:** Maps CVSS against EPSS using the highest-accuracy spatial channels, with mark sizes scaled by area to reflect technical impact without visual exaggeration, and a 3-tier opacity hierarchy that highlights active threats.
2. **An Architectural Weakness Treemap:** Uses a 100% space-filling squarified containment hierarchy (Layer $\to$ CWE Family $\to$ Vendor) to display expected risk ($\sum \text{CVSS} \times \text{EPSS}$) and remote network exposure via monotonic luminance.
3. **A Multi-Cohort Ridgeline Plot:** Compares exploitation velocity across vendor cohorts using a mirror-reflected Kernel Density Estimation (KDE) at $t = 0$ days to eliminate artificial boundary spillover.

The system is augmented by an unsupervised 4D K-Means clustering engine operating on logit-scaled EPSS to categorize vulnerabilities into four operational threat archetypes. In real-world validation, CyberLens **reduces emergency patching ticket volume by 75.1%** while maintaining **100% capture of confirmed active exploits**, bridging the gap between compliance requirements and true threat exposure.

---

## 1. Domain Problem Characterization (Munzner Level 1)

### 1.1 The Vulnerability Prioritization Crisis
Modern enterprise IT environments operate across complex, heterogeneous stacks combining operating systems, networking equipment, cloud services, and database clusters. Vulnerability scanners continuously audit these environments and produce thousands of alerts. Historically, remediation workflows have followed rigid regulatory mandates (PCI-DSS, ISO 27001, NIST SP 800-53) requiring teams to patch any flaw rated High or Critical ($\text{CVSS} \ge 7.0$) within 14 to 30 days.

This approach suffers from a fundamental structural flaw: **CVSS base scores measure intrinsic technical severity in a theoretical vacuum, not real-world exploitation probability**. Threat intelligence research shows that less than 4.5% of all cataloged vulnerabilities are ever weaponized. By treating every High-CVSS flaw as an emergency, organizations waste up to 80% of their maintenance windows fixing flaws that pose no practical risk, leading to severe developer fatigue and operational friction.

```
                              THE VULNERABILITY TRIAGE LANDSCAPE
                   Theoretical Severity (CVSS) vs. Real-World Risk (EPSS)
    
       High EPSS ^ ─────────────────────────────────────────────────────────────
                 │  [QUADRANT II: SILENT THREATS]       │ [QUADRANT I: CRITICAL WEAPONS]
                 │  Moderate CVSS (4.0 - 6.9)           │ High CVSS (7.0 - 10.0)
                 │  High EPSS / Active CISA KEV         │ High EPSS & Active CISA KEV
                 │  * Bypasses standard CVSS rules *    │ * Legitimate emergency queue *
                 │  (Local Privilege Escalation)        │ (Zero-click remote code execution)
                 │──────────────────────────────────────┼───────────────────────────────
                 │  [QUADRANT III: DORMANT BACKLOG]     │ [QUADRANT IV: PAPER TIGERS]
                 │  Low CVSS (< 4.0)                    │ High CVSS (7.0 - 10.0)
                 │  Near-zero exploit probability       │ Near-zero exploit probability
                 │  * Routine lifecycle updates *       │ * Primary cause of alert fatigue *
                 │  (Non-exploitable low-risk flaws)    │ (Theoretical flaws without exploits)
        Low EPSS v ─────────────────────────────────────────────────────────────
                   Low CVSS <──────────────────────────────────────────> High CVSS
```

### 1.2 Two Major Operational Blind Spots
When teams rely strictly on CVSS thresholding (`SELECT * WHERE cvss >= 7.0`), they encounter two dangerous failure modes:
1. **Paper Tigers (Quadrant IV):** Flaws scoring between $7.0$ and $8.8$ due to theoretical crash or exposure potential, but which lack exploit tools and require unrealistic preconditions. These account for nearly three-quarters of emergency alerts.
2. **Silent Threats (Quadrant II):** Flaws scoring between $4.0$ and $6.9$ because they require local machine access or basic user credentials. In real attack campaigns, ransomware groups acquire initial access through phishing, then rely on these exact "Medium" flaws for local privilege escalation (LPE) to take over domain controllers. Under CVSS-only policies, these actively exploited flaws remain unpatched.

### 1.3 Why Visual Analytics is Necessary
Security teams cannot solve this trade-off with static database queries. Every organization has distinct infrastructure and varying risk tolerance. An interactive visual interface is needed to explore the continuous bivariate frontier between severity and probability, filter views to specific technology stacks, identify systemic weaknesses across architectural layers, and understand how quickly different vendor products are exploited after disclosure.

---

## 2. Data Abstraction (Munzner Level 2: WHAT)

### 2.1 Data Sources & Synthesis
CyberLens unifies three authoritative cybersecurity feeds into a normalized dataset of 4,500+ vulnerabilities:
- **NIST NVD:** Provides standardized CVSS v3.1 scores (base, impact), access prerequisites (attack vector, privileges required), and MITRE Common Weakness Enumeration (CWE) classifications.
- **FIRST.org EPSS v3:** Supplies a continuous daily probability ($0.000$ to $1.000$) estimating the likelihood of exploitation within 30 days.
- **CISA KEV:** Provides ground-truth confirmation of confirmed active exploitation in real-world attacks, alongside official disclosure and weaponization dates.

### 2.2 Munzner Data Classification Table
Every attribute is classified following Tamara Munzner’s taxonomy:

| Attribute | Role | Munzner Type | Direction | Scale / Domain | Description & Analytical Role |
|---|---|---|---|---|---|
| `cve_id` | Key | Categorical | — | String (`CVE-YYYY-NNNN`) | Unique standardized vulnerability identifier. |
| `vendor` | Key | Categorical | — | Discrete (`Microsoft`, `Cisco`, etc.) | Software publisher or appliance manufacturer. |
| `layer` | Key | Categorical | — | 4 Tiers (`OS`, `Network`, `Web`, `DB`) | Architectural tier defining system boundary. |
| `cwe_family` | Key | Categorical | — | Discrete (`Memory`, `Injection`, etc.) | MITRE weakness taxonomy family. |
| `cvss_base` | Value | Ordered $\to$ Quantitative | Sequential | Continuous: $[0.0, 10.0]$ | Theoretical technical severity. |
| `cvss_impact` | Value | Ordered $\to$ Quantitative | Sequential | Continuous: $[0.0, 6.0]$ | Destructive technical impact sub-score. |
| `epss_score` | Value | Ordered $\to$ Quantitative | Sequential | Probability: $[0.000, 1.000]$ | Empirical 30-day weaponization probability. |
| `is_kev` | Value | Categorical | — | Boolean: $\{\text{True}, \text{False}\}$ | Ground-truth active exploitation confirmation. |
| `attack_vector` | Value | **Ordered $\to$ Ordinal** | **Sequential** | $\text{Network} > \text{Adjacent} > \text{Local} > \text{Physical}$ | Access barrier required; ordered by attacker ease. |
| `privileges_required` | Value | **Ordered $\to$ Ordinal** | **Sequential** | $\text{None} < \text{Low} < \text{High}$ | Authentication level; ordered by prerequisite barrier. |
| `days_to_exploit` | Derived | Ordered $\to$ Quantitative | Sequential | Continuous days: $[0, 120]$ | Elapsed time from disclosure to KEV weaponization. |

> [!NOTE]
> Following course principles, `attack_vector` and `privileges_required` are explicitly modeled as **Ordered $\to$ Ordinal** attributes with a **Sequential** direction. Network access is objectively easier for an attacker than physical access; they are not arbitrary unordered categories.

### 2.3 Derived Metrics
- **Expected Risk Weight ($w_i$):** $w_i = \text{CVSS}_{\text{base}, i} \times \text{EPSS}_i$, capturing the classic actuarial definition of risk ($\text{Severity} \times \text{Probability}$).
- **Weaponization Delay ($t$):** Elapsed days between NVD publication and CISA KEV listing ($t = \max(0, \text{Date}_{\text{KEV}} - \text{Date}_{\text{NVD}})$).
- **Access Ease Index:** Continuous score ($0$ to $10$) derived from CVSS v3.1 attack vector and privilege weights ($8.22 \times W_{\text{AV}} \times W_{\text{PR}}$).

---

## 3. Task Abstraction (Munzner Level 2: WHY)

All analytical workflows are anchored at the top level to **`Consume → Discover`**, supporting interactive hypothesis generation rather than static lookups:

### Task 1: Bivariate Risk Profiling & Discrepancy Discovery
- **High-Level Goal:** `Consume → Discover` (Explore risk trade-offs).
- **Mid/Low-Level Actions:** `{Explore, Identify, Outliers & Correlation}` across quantitative `cvss_base`, quantitative `epss_score`, and categorical `is_kev`.
- **User Need:** Identify discrepancies between theoretical severity and real exploitation. Isolate High-EPSS Silent Threats in the upper-left quadrant and separate them from low-probability Paper Tigers in the lower-right quadrant.

### Task 2: Architectural Weakness Taxonomy Decomposition
- **High-Level Goal:** `Consume → Discover` (Understand system vulnerabilities structurally).
- **Mid/Low-Level Actions:** `{Browse, Compare, Summarize, Hierarchical Distribution}` across `layer`, `cwe_family`, `vendor`, and aggregate expected risk.
- **User Need:** Browse the 3-level hierarchy to determine which technology layers concentrate the highest threat volume, and evaluate whether flaws are remotely accessible from the network.

### Task 3: Continuous Weaponization Velocity Modeling
- **High-Level Goal:** `Consume → Discover` (Analyze longitudinal hazard distributions).
- **Mid/Low-Level Actions:** `{Locate, Compare, Continuous Density / Distribution}` across vendor cohorts and elapsed days.
- **User Need:** Move beyond misleading discrete queries (such as `MIN(days_to_exploit)`, which is zero for almost all vendors due to isolated outliers). Model the continuous density of time-to-exploit to distinguish immediate zero-day spikes from delayed exploitation waves.

---

## 4. Visual Encoding & Interaction Design (Munzner Level 3: HOW)

```
                     CYBERLENS THREE-IDIOM COORDINATED ARCHITECTURE
    
    ┌───────────────────────────────────────────┬───────────────────────────────────────────┐
    │ IDIOM 1: BIVARIATE BUBBLE PLOT            │ IDIOM 2: SQUARIFIED TREEMAP               │
    │ • X: CVSS Base (Position, Aligned)        │ • Enclosure: Layer -> CWE -> Vendor       │
    │ • Y: EPSS Score (Position, Aligned)       │ • Area: Expected Risk (CVSS x EPSS)       │
    │ • Size: CVSS Impact (Area-scaled)         │ • Color: % Network Exploitable (Luminance)│
    │ • Color: Threat Tier (HCL Okabe-Ito)      │                                           │
    │ • Opacity: 3-Tier Layered Z-Order         │ • Squarified packing -> 1:1 aspect ratios │
    └───────────────────────────────────────────┴───────────────────────────────────────────┘
                                      ▲                              ▲
                                      └──────────────┬───────────────┘
                                                     ▼
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │ IDIOM 3: MULTI-COHORT RIDGELINE DENSITY PLOT                                          │
    │ • X: Elapsed Days to Exploit [0, 120] (Shared Common Scale)                           │
    │ • Y: Vendor Cohorts (Separated Baselines, List Alignment)                             │
    │ • Height: Mirror-Reflected KDE Density (Boundary-corrected at t = 0)                   │
    │ • Fill: Cohort-specific pastel tones with 25% vertical ridge overlap                  │
    └───────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Idiom 1: Bivariate Prioritization Bubble Plot
- **Spatial Positioning (X/Y):** Position on a common aligned scale is the most accurate visual channel for quantitative data (Cleveland & McGill, 1984). We dedicate the $X$-axis to `cvss_base` ($[0, 10]$) and the $Y$-axis to `epss_score` ($[0, 1]$). Interactive crosshair sliders partition the space into four operational quadrants.
- **Mark Area Calibration:** Rather than mapping destructive impact (`cvss_impact`) to circle radius—which causes an artificial quadratic area inflation ($A \propto r^2$)—we lock Plotly’s area mode (`sizemode="area"`). This ensures that mark size accurately represents technical severity without visually overwhelming neighboring points.
- **3-Tier Opacity Hierarchy & Z-Ordering:** Because over 85% of vulnerabilities have low EPSS scores, uniform opacity would produce an unreadable cloud near the bottom axis. We establish three discrete layers:
  1. *Foreground (`zorder=3`, $\alpha = 0.92$):* Active CISA KEV threats in bold crimson (`#D92B2B`) with a white border, ensuring immediate visual pop-out.
  2. *Midground (`zorder=2`, $\alpha = 0.65$):* High-EPSS Silent Threats in amber (`#E69F00`) with a dark perimeter.
  3. *Background (`zorder=1`, $\alpha = 0.20$):* Low-probability flaws in desaturated slate without borders, forming a smooth contextual density field without clutter.

### 4.2 Idiom 2: Architectural Weakness Squarified Treemap
- **Space-Filling Containment Hierarchy:** Node-link diagrams waste up to 70% of screen space on background margins. A Treemap provides **100% pixel utilization**, displaying three nested levels: $\text{Layer} \to \text{CWE Family} \to \text{Vendor}$.
- **Expected Risk Sizing Metric:** In a space-filling treemap, tile areas must be additive. Raw vulnerability count treats minor bugs as equal to wormable exploits. CyberLens sizes tiles by aggregate expected risk:
  $$\text{Area} \propto \sum (\text{CVSS}_{\text{base}} \times \text{EPSS})$$
  This automatically expands architectural zones harboring active threats while compressing zones filled with dormant compliance noise.
- **Squarified Packing Algorithm:** Standard slice-and-dice layouts produce thin, elongated rectangles that are hard to compare visually. We enforce the squarified layout algorithm (*Bruls et al., 2000*), optimizing rectangle aspect ratios toward $1:1$ to maximize human area estimation accuracy.
- **Sequential Luminance Encoding:** Within each weakness tile, the proportion of network-accessible flaws ($p_{\text{net}}$) is mapped to a monotonically decreasing luminance ramp (from light slate for local flaws to deep navy for remotely accessible flaws), avoiding problematic rainbow palettes.

### 4.3 Idiom 3: Multi-Cohort Weaponization Velocity Ridgeline Plot
- **List-Aligned Baselines:** Overlaying multiple vendor hazard curves on a single baseline creates an unreadable "spaghetti" plot. Conversely, standard boxplots hide multimodality (such as a zero-day spike followed by a secondary exploit wave). The ridgeline plot assigns each vendor its own horizontal baseline, allowing effortless comparison of peak positions and distribution shapes.
- **Boundary-Corrected Kernel Density Estimation:** Standard Gaussian KDE assumes data exists across $(-\infty, +\infty)$. Because time-to-exploit cannot be negative ($t \ge 0$), standard KDE leaks probability mass into negative time, cutting the apparent height of zero-day spikes ($t < 7$ days) by almost half. CyberLens applies a **mirror reflection at $t = 0$** ($\hat{f}_{\text{refl}}(t) = \hat{f}_h(t) + \hat{f}_h(-t)$ for $t \ge 0$), conserving total probability mass and faithfully capturing rapid zero-day exploitation dynamics.

### 4.4 Color Design & Universal Accessibility
- **Daltonism-Safe Palette:** To accommodate color vision deficiencies (protanopia and deuteranopia, which affect ~8% of male users), we avoid the conventional Red-Yellow-Green traffic light scheme. The palette follows an Okabe–Ito inspired trajectory along the blue-yellow opponent axis: Crimson (`#D92B2B`), Amber (`#E69F00`), Cerulean Blue (`#3B7DD8`), and Neutral Slate (`#94A3B8`).
- **Monotonic Luminance Steps:** Each priority tier maintains a distinct perceptual lightness difference ($\Delta L^* \ge 12$). Even on a black-and-white printout, active KEV threats appear darkest ($L^* = 48$) while dormant flaws recede into light background tones ($L^* = 82$).
- **Dual-Chroma Principle (Topic 8):** Small marks (scatter bubbles) require high chroma/saturation to trigger pre-attentive attention. Large area fills (treemap tiles, ridgeline areas) use desaturated pastel companion tones to prevent visual fatigue and optical illusions.

### 4.5 Coordinated Interaction & Shneiderman's Mantra
The interface follows Ben Shneiderman’s principle: *"Overview first, zoom and filter, then details-on-demand"*:
- **Overview:** The default view presents the full 4,500+ CVE frontier, the complete corporate hierarchy, and baseline vendor velocity curves.
- **Zoom:** Clicking a layer in the Treemap zooms smoothly into child weakness families and vendors.
- **Filter (Focus+Context):** Filtering by technology stack or selecting a Treemap container highlights focused items in full color while dimming non-selected records into semi-transparent slate ghosts ($\alpha = 0.05$). Crucially, **the scatterplot coordinate axes remain strictly locked** ($[0, 10] \times [0, 1]$), ensuring that filtering does not alter the spatial mental map.
- **Details-on-Demand:** Hovering over any bubble reveals an inspection card with the CVE ID, software vendor, CVSS metrics, EPSS percentile, attack vector, and assigned threat cluster.

---

## 5. Empirical Case Studies & Operational Validation

We evaluated CyberLens on three real-world analytical scenarios using the unified enterprise dataset:

### 5.1 Case Study 1: The "Silent Threat" Lateral Movement Trap
- **Scenario:** A SOC team relies on a standard $\text{CVSS} \ge 7.0$ patching rule.
- **Visual Discovery:** In Idiom 1, the upper-left quadrant ($4.0 \le \text{CVSS} \le 6.9, \text{EPSS} \ge 0.30$) clearly displays **38 distinct vulnerabilities** rendered in high-chroma crimson and amber, suspended high above the low-risk baseline.
- **Root Cause Analysis:** Inspecting these flaws reveals critical Windows Kernel and Win32k local privilege escalation (LPE) vulnerabilities (e.g., scoring CVSS 6.5 to 6.8 because they require local access). Despite moderate base scores, they have high EPSS probabilities ($> 0.65$) and confirmed active exploitation in ransomware campaigns.
- **Outcome:** CyberLens rescues 38 actively weaponized vulnerabilities from being overlooked by conventional compliance rules.

### 5.2 Case Study 2: Eliminating "Paper Tiger" Alert Fatigue
- **Scenario:** Across a filtered enterprise stack of 1,840 CVEs, a traditional compliance query (`cvss >= 7.0`) flags **1,124 urgent tickets**.
- **Visual Discovery:** In Idiom 1, the lower-right quadrant shows a dense band of 882 vulnerabilities scoring High CVSS ($7.0 - 8.8$) but with near-zero EPSS ($\overline{\text{EPSS}} = 0.008$). In the Treemap (Idiom 2), the Database layer contains 310 High-CVSS flaws but occupies less than 6.2% of expected risk area, signaling that these flaws lack active exploit code and require administrative local privileges.
- **Surgical Inspection:** Drilling down into `OS & Firmware` $\to$ `Memory Corruption` highlights **`CVE-2024-38063`** (Windows TCP/IP Remote Code Execution, CVSS 9.8, EPSS 0.942, unauthenticated network vector, confirmed KEV), identifying it as a true emergency.
- **Triage Comparison:**

| Triage Strategy | Rule Applied | Flagged Tickets | Active KEV Captured | False Urgency Rate | Bandwidth Savings |
|---|---|---|---|---|---|
| **Traditional Compliance** | `CVSS >= 7.0` | 1,124 | 142 / 180 (78.9%) | **78.5% (882 Paper Tigers)** | Baseline (0%) |
| **CyberLens RBVM** | **Cluster A (Weapons) + B (Silent)** | **280** | **180 / 180 (100.0%)** | **0.0% (Tigers deferred)** | **-75.1% Emergency Tickets** |

CyberLens **reduces emergency patching workload by 75.1%** while increasing active exploit capture from 78.9% to **100%**.

### 5.3 Case Study 3: Network Appliances vs. Application Stacks
- **Scenario:** A CISO mandates a uniform 14-day patching SLA for all Critical vulnerabilities.
- **Visual Discovery in Idiom 3:** Toggling the 7-day threshold line across vendor ridges reveals two distinct hazard regimes:
  1. *Perimeter Network Appliances (`Cisco`, `Fortinet`, `Ivanti`):* Display an extreme **L-shaped distribution peaking at $t \in [0, 4]$ days**, with **over 64% of weaponization occurring within the first week**. Because edge devices sit directly on the internet without EDR agents, threat actors weaponize them immediately. A 14-day SLA fails completely because the attack wave has already peaked.
  2. *Application & OS Stacks (`Apache`, `Microsoft`, `Oracle`):* Display a **bimodal distribution** with a minor initial mode followed by a major public PoC wave peaking between **18 and 35 days**.
- **Actionable CISO Governance Matrix:**
  - **Tier 0 (Perimeter Network Appliances):** Emergency hotfix within **< 24 Hours**.
  - **Tier 1 (Critical Enterprise Software):** Patch deployed within **< 72 Hours** (ahead of the 18-day PoC peak).
  - **Tier 2 (Silent Threats / Local Privilege Escalation):** Remediate within **7 Days** to block ransomware lateral movement.
  - **Tier 3 (Paper Tigers):** Defer to scheduled **30–60 Day** maintenance windows.
  - **Tier 4 (Dormant Backlog):** Address organically during standard version upgrades.

---

## 6. Algorithmic Machine Learning Integration & Discussion

### 6.1 Unsupervised 4D Threat Clustering
To assist visual exploration without imposing rigid manual cutoffs, CyberLens integrates an unsupervised K-Means clustering model operating in a 4-dimensional normalized feature space:
$$\mathbf{x} = [\text{CVSS}_{\text{base}}, \,\, \text{logit}(\text{EPSS}), \,\, \text{CVSS}_{\text{impact}}, \,\, \text{access\_ease}]$$

```
                   WHY LOGIT SCALING MATTERS FOR THREAT CLUSTERING
    
    [RAW EPSS SPACE]
    Many points compressed near 0: [ ••••••••••••••••••••••                  •  • ]
    (Naive K-Means lumps 85% of flaws into identical, uninformative clusters)
    
    [LOGIT TRANSFORMED SPACE: ln(p / (1 - p))]
    Values stretched smoothly:     [ •••   ••••   •••••   ••••   ••••   •••   •  • ]
    (K-Means cleanly isolates Silent Threats from Paper Tigers and Dormant Backlog)
```

- **Why the Logit Transform is Essential:** Over 85% of EPSS values lie below $0.02$. In raw probability space, Euclidean distance treats values between $0.001$ and $0.02$ as practically identical, causing standard clustering to lump them together. The logit transform ($\ln(\frac{p}{1-p})$) linearizes log-odds, allowing the algorithm to cleanly distinguish moderate, actively exploited flaws from dormant background noise.
- **Four Operational Archetypes:**
  - *Cluster A (Critical Weapons):* High CVSS ($\overline{8.14}$), elevated EPSS ($\overline{0.149}$), high KEV ratio ($8.8\%$).
  - *Cluster B (Silent Threats):* Moderate CVSS ($\overline{5.38}$), restricted access vectors, elevated real-world exploit probability.
  - *Cluster C (Paper Tigers):* High CVSS ($\overline{8.10}$), negligible EPSS ($\overline{0.0098}$), compliance noise.
  - *Cluster D (Dormant Backlog):* Low severity, low exploitability, minimal operational risk.

### 6.2 System Limitations & Scalability
- **Temporal EPSS Dynamics:** CVSS scores are mostly static once published, whereas EPSS scores update daily based on real-world threat telemetry. In production, CyberLens runs daily batch refreshes to update positions and trigger alerts when vulnerabilities cross risk thresholds.
- **Rendering Performance:** WebGL acceleration (`scattergl`) is used for the scatterplot to maintain 60 fps interactivity when rendering thousands of items.
- **Hierarchy Depth:** Treemap nesting is intentionally constrained to three levels (`Layer → CWE → Vendor`) to prevent sub-pixel tile fragmentation and preserve visual legibility.

---

## 7. Conclusion & Reproducibility

CyberLens demonstrates how structured visual analytics—grounded in Tamara Munzner’s Nested Model, psychophysical encoding principles, and boundary-corrected statistical modeling—can solve the enterprise vulnerability triage dilemma. By replacing simplistic SQL thresholding with coordinated multi-view exploration, the platform empowers security leaders to eliminate alert fatigue, protect against stealthy lateral movement threats, and allocate remediation resources based on empirical evidence.

The complete codebase, documentation, unit tests, and reference datasets are openly accessible:
- **Repository:** [https://github.com/Evkune/CyberLens](https://github.com/Evkune/CyberLens)
- **Validation:** Automated test suite runnable via `pytest tests/`.
- **Advanced Technical Notes:** Mathematical proofs and statistical derivations are documented in [`docs/TECHNICAL_NOTES.md`](file:///home/evan/Documents/ETSIINF/07_Data_Visualization/docs/TECHNICAL_NOTES.md).

---

## References

1. **Munzner, T.** (2014). *Visualization Analysis and Design*. CRC Press / AK Peters Visualization Series.
2. **Cleveland, W. S., & McGill, R.** (1984). Graphical Perception: Theory, Experimentation, and Application to the Development of Graphical Methods. *Journal of the American Statistical Association*, 79(387), 531–554.
3. **Stevens, S. S.** (1957). On the Psychophysical Law. *Psychological Review*, 64(3), 153–181.
4. **Shneiderman, B.** (1996). The Eyes Have It: A Task by Data Type Taxonomy for Information Visualizations. In *Proceedings of the IEEE Symposium on Visual Languages*, 336–343.
5. **Bruls, M., Huizing, K., & van Wijk, J. J.** (2000). Squarified Treemaps. In *Data Visualization 2000: Proceedings of Eurographics and IEEE TCVG*, 33–42.
6. **Silverman, B. W.** (1986). *Density Estimation for Statistics and Data Analysis*. Chapman & Hall / CRC.
7. **Schuster, E. F.** (1985). Incorporating Support Constraints into Nonparametric Estimators of Densities. *Communications in Statistics - Theory and Methods*, 14(5), 1123–1136.
8. **Okabe, M., & Ito, K.** (2008). Color Universal Design (CUD): How to Make Figures and Presentations That Are Friendly to Colorblind People. *Jfly Data Repository*.
9. **Borland, D., & Russell, R. M.** (2007). Rainbow Color Map (Still) Considered Harmful. *IEEE Computer Graphics and Applications*, 27(2), 14–17.
10. **FIRST.org.** (2019). *Common Vulnerability Scoring System v3.1: Specification Document*.
11. **Jacobs, J., Romanosky, S., Edwards, B., & Roytman, M.** (2021). Exploit Prediction Scoring System (EPSS). *Digital Threats: Research and Practice*, 2(3), 1–17.
12. **CISA.** (2024). *Known Exploited Vulnerabilities (KEV) Catalog*. Cybersecurity and Infrastructure Security Agency.
