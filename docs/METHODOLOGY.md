# Methodological Architecture & Abstraction Framework

## 1. Context & Research Problem

Modern enterprise security organizations face acute alert fatigue, with over 28,000 Common Vulnerabilities and Exposures (CVEs) published annually. Traditional compliance and vulnerability management policies rely primarily on the **Common Vulnerability Scoring System (CVSS v3.1)** base score, mandating remediation for all flaws scoring High or Critical ($\ge 7.0$).

However, empirical security studies indicate that **under 4.5% of all published CVEs ever experience active in-the-wild exploitation**. Meanwhile, several vulnerabilities rated as Moderate ($4.0 \le \text{CVSS} \le 6.9$) due to local execution prerequisites are actively leveraged in weaponized attack chains for privilege escalation and lateral movement.

**CyberLens** implements a Threat-Informed Visual Analytics paradigm to resolve this prioritization dilemma, mapping the trade-off space across:
1. **Theoretical Technical Severity:** NIST NVD CVSS v3.1 (Base & Impact metrics)
2. **Empirical Weaponization Likelihood:** FIRST.org EPSS v3 (30-day exploitation probability)
3. **Confirmed Active Exploitation:** CISA KEV (Known Exploited Vulnerabilities catalog)

---

## 2. Four-Level Nested Model (Tamara Munzner Framework)

### Level 1: Domain Problem Characterization
* **Target Persona:** Enterprise Vulnerability Manager, Security Operations Center (SOC) Lead, and Cyber Threat Intelligence (CTI) Analyst.
* **Core Question:** Given an organization's specific software inventory, how should limited patching bandwidth be allocated to remediate vulnerabilities that present real, imminent exploitation danger rather than compliance paper tigers?

### Level 2: Data & Task Abstraction

#### Data Abstraction (WHAT)
The unified dataset comprises 4,500+ standardized CVE items with multidimensional attributes:

| Attribute | Role | Munzner Type | Direction | Scale / Domain |
|---|---|---|---|---|
| `cve_id` | Key | Categorical | — | Unique identifier (e.g., `CVE-2024-38063`) |
| `vendor` | Key | Categorical | — | Software publisher |
| `layer` | Key | Categorical | — | Enterprise architectural tier (OS, Network, Web, DB) |
| `cwe_family` | Attribute | Categorical | — | MITRE Weakness classification |
| `cvss_base` | Value | Ordered → Quantitative | Sequential | Continuous: [0.0, 10.0] |
| `cvss_impact` | Value | Ordered → Quantitative | Sequential | Continuous: [0.0, 6.0] |
| `epss_score` | Value | Ordered → Quantitative | Sequential | Probability: [0.000, 1.000] (Heavy-tailed) |
| `is_kev` | Value | Categorical | — | Boolean (Observed in-the-wild) |
| `attack_vector` | Value | Ordered → Ordinal | Sequential | Network > Adjacent > Local > Physical |
| `privileges_required` | Value | Ordered → Ordinal | Sequential | None < Low < High |
| `days_to_exploit` | Derived | Ordered → Quantitative | Sequential | Elapsed days from disclosure to weaponization |

#### Task Abstraction (WHY)
The analytical workflow follows Munzner's three-tier action hierarchy:

* **Task 1: Bivariate Risk Profiling & Discrepancy Discovery**
  * *High-level:* `Consume → Discover` (Formulate and verify risk hypotheses)
  * *Mid/Low-level:* `{Explore, Identify, Outliers & Correlation}` on quantitative CVSS, quantitative EPSS, and categorical KEV status.
  * *Operational objective:* Isolate high-probability/moderate-severity threats and separate them from theoretical high-severity flaws with negligible exploit probability.

* **Task 2: Architectural Weakness Taxonomy Decomposition**
  * *High-level:* `Consume → Discover` (Explore structural dependencies)
  * *Mid/Low-level:* `{Browse, Compare, Summarize, Hierarchical Distribution}` on architectural layer, CWE family, and aggregated risk.
  * *Operational objective:* Detect systemic architectural weaknesses across enterprise tiers.

* **Task 3: Continuous Weaponization Velocity Modeling**
  * *High-level:* `Consume → Discover` (Analyze longitudinal survival trends)
  * *Mid/Low-level:* `{Locate, Compare, Continuous Density / Distribution}` across vendor cohorts.
  * *Operational objective:* Model Kernel Density Estimation (KDE) curves to identify zero-day weaponization spikes ($t < 7$ days) versus prolonged vulnerability decay.

---

## 3. Visual Encoding & Idiom Design (HOW)

Visual channel assignments adhere strictly to **Mackinlay's Expressiveness & Effectiveness criteria** and **Stevens' Law of Psychophysics** ($S = k \cdot I^a$):

1. **Idiom 1: Multi-Channel Bivariate Bubble Plot**
   * *Spatial Position (X/Y):* Encodes `cvss_base` ($X$) and `epss_score` ($Y$). Spatial position is the most accurately perceived channel for quantitative data ($a \approx 1.0$).
   * *Mark Area:* Encodes destructive technical impact (`cvss_impact`), scaled area-proportionally to mitigate 2D visual area underestimation.
   * *Color Hue:* Encodes categorical exploitation ground truth (Red: Active CISA KEV; Amber: High EPSS; Gray: Low priority) leveraging pre-attentive pop-out.

2. **Idiom 2: Hierarchical Weakness Treemap**
   * *Spatial Containment:* Implements a space-filling hierarchy (Layer → CWE Family → Vendor) without visual occlusion.
   * *Cell Area:* Encodes aggregate corporate threat weight ($\text{CVSS} \times \text{EPSS}$).

3. **Idiom 3: Multi-Cohort Ridgeline Density Distribution**
   * *Continuous Baseline Alignment:* Avoids overlapping clutter by providing separated horizontal density tracks.
   * *Kernel Density Estimation (Gaussian KDE):* Models continuous weaponization probability density over elapsed exposure days, replacing simplistic discrete SQL min/max queries.

---

## 4. Algorithmic Machine Learning Integration

To enhance visual exploration without imposing rigid manual thresholds, the pipeline includes an **unsupervised 4D K-Means clustering engine** operating on normalized feature space:
$$\mathbf{x} = [\text{CVSS}_{\text{base}}, \text{EPSS}, \text{CVSS}_{\text{impact}}, \text{Complexity}_{\text{num}}]$$

This autonomously discovers 4 operational threat archetypes:
* **Cluster A (Critical Weapons):** High theoretical severity + high weaponization velocity.
* **Cluster B (Silent Threats):** Moderate CVSS + active in-the-wild exploitation.
* **Cluster C (Paper Tigers):** High CVSS + near-zero exploit probability.
* **Cluster D (Dormant Backlog):** Low impact + low exploitability.
