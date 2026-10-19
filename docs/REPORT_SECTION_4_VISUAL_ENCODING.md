# Section 4: Visual Encoding & Coordinated Interaction Design (Munzner Level 3: HOW)

Translating the domain problem characterization (Level 1) and the data/task abstractions (Level 2) into an actionable visual analytics environment requires rigorous adherence to **Mackinlay’s Expressiveness and Effectiveness principles**, **Cleveland and McGill’s perceptual accuracy hierarchy**, and **Stevens’ Psychophysical Power Law** ($S = k \cdot I^a$). Rather than relying on arbitrary chart templates or single-variable SQL filters (`SELECT * WHERE cvss >= 7.0`), **CyberLens** orchestrates three custom-calibrated visual idioms within a reactive multi-view architecture:

| Visual Idiom | Primary Analytical Task (WHY) | Data Attributes Encoded (WHAT) | Visual Channels Assigned (HOW) | Theoretical & Perceptual Justification |
|---|---|---|---|---|
| **Idiom 1: Multi-Channel Bivariate Bubble Plot** | **Task 1:** `{Explore, Identify, Outliers & Correlation}` | `cvss_base` (Quant.)<br>`epss_score` (Quant.)<br>`cvss_impact` (Quant.)<br>`is_kev` / Cluster (Cat.) | Planar Position $X$<br>Planar Position $Y$<br>2D Mark Area (Size)<br>CIE HCL Hue + 3-Tier $\alpha$ | Planar position maximizes quantitative accuracy ($a \approx 1.0$); area is power-law calibrated ($a = 0.7$); high-chroma hue isolates KEV threats via pre-attentive pop-out. |
| **Idiom 2: Squarified Containment Treemap** | **Task 2:** `{Browse, Compare, Summarize, Hierarchical Distribution}` | `layer` $\rightarrow$ `cwe_family` $\rightarrow$ `vendor` (Keys)<br>$\sum (\text{CVSS} \times \text{EPSS})$ (Quant.)<br>`attack_vector` % (Quant.) | Nested Spatial Enclosure<br>2D Squarified Tile Area<br>Sequential Luminance ($L^*$) | Enclosures encode 3-tier hierarchy with 100% space-filling efficiency and zero occlusion; squarified tiling optimizes aspect ratios toward $1:1$; monotonic luminance encodes network exposure. |
| **Idiom 3: Multi-Cohort Ridgeline Density Plot** | **Task 3:** `{Locate, Compare, Continuous Density / Distribution}` | `days_to_exploit` (Quant.)<br>`vendor` Cohort (Cat. Key)<br>Reflected KDE $\hat{f}_{\text{refl}}(t)$ (Quant.) | Aligned Position $X$<br>Vertical List Alignment $Y$<br>Curve Height + Area Fill | List-aligned vertical baselines prevent multi-series spaghetti overplotting while preserving multimodal density morphology; mirror reflection corrects $t=0$ boundary bias. |

---

## 4.1 Idiom 1: Bivariate Prioritization Multi-Channel Bubble Plot

### 4.1.1 Planar Spatial Positioning & Cleveland–McGill Channel Dominance
To execute **Task 1 (`Consume → Discover` $\rightarrow$ `{Explore, Identify, Outliers & Correlation}`)**, the analyst must simultaneously evaluate theoretical technical severity against empirical exploitation likelihood across 4,500+ CVEs. Following **Mackinlay’s Effectiveness criterion** and the **Cleveland–McGill perceptual ranking**, **Position on a Common Aligned Scale** is the most accurately decoded visual channel for `Ordered → Quantitative` attributes. Under **Stevens’ Psychophysical Power Law**:
$$S = k \cdot I^a$$
human perception of planar spatial length/position exhibits an exponent of $a \approx 1.0$, providing a strictly linear correspondence between physical pixel displacement and perceived cognitive magnitude. Consequently, CyberLens dedicates planar spatial coordinates exclusively to the two primary prioritization variables—mapping `cvss_base` ($\in [0.0, 10.0]$) to the horizontal $X$-axis and `epss_score` ($\in [0.000, 1.000]$) to the vertical $Y$-axis—rather than wasting spatial coordinates on arbitrary geographical maps or non-quantitative keys. This orthogonal parameterization partitions the viewport into four operational risk quadrants bounded by interactive crosshair sliders ($X_{\text{thresh}}, Y_{\text{thresh}}$), enabling immediate geometric separation of **Silent Threats** (upper-left) from **Paper Tigers** (lower-right).

### 4.1.2 Psychophysical Mark Area Calibration ($a = 0.7$)
The third quantitative dimension, destructive technical impact (`cvss_impact` $\in [0.0, 6.0]$), is encoded via circular mark size. Naive visualization implementations frequently bind quantitative values to circle *radius* or *diameter* (`sizemode="diameter"`), which scales physical area quadratically ($A = \pi r^2 \propto I^2$) and induces severe visual distortion where high-impact flaws appear $36\times$ larger than low-impact flaws. Conversely, empirical psychophysics demonstrates that human observers systematically underestimate 2D area differences, governed by a compressive Stevens’ Law exponent of $a = 0.7$.

To balance perceptual differentiation against mutual bubble occlusion across 4,500+ dense marks, CyberLens calibrates the rendered target pixel area $A_i$ for each vulnerability $i$ using a bounded power-law transformation:
$$A_i = A_{\min} + k \cdot \left(\text{CVSS}_{\text{impact}, i}\right)^{0.7}$$
where:
* $A_{\min} = \pi r_{\min}^2 = \pi (3.0\text{ px})^2 \approx 28.27\text{ px}^2$ establishes a strict minimum retinal footprint (`sizemin = 3.0`), ensuring that vulnerabilities with low technical impact remain visually discernible and interactive via cursor hover.
* Constraining the maximum rendered mark diameter to $D_{\max} = 28.0\text{ px}$ ($A_{\max} = \pi (14.0\text{ px})^2 \approx 615.75\text{ px}^2$) at the theoretical upper bound $\text{CVSS}_{\text{impact}, \max} = 6.0$ yields the exact scaling constant $k$:
  $$k = \frac{A_{\max} - A_{\min}}{(6.0)^{0.7}} = \frac{615.75 - 28.27}{3.5051} \approx 167.61\text{ px}^2$$

In Plotly’s rendering engine (`cyberlens/idiom_bubble.py`), area-proportional rendering is strictly enforced by locking `sizemode="area"` and calibrating the internal normalization divisor `sizeref`:
$$\text{sizeref} = \frac{2.0 \cdot \max_i(A_i)}{D_{\max}^2} = \frac{2.0 \cdot 615.75}{(28.0)^2} \approx 1.5708$$

### 4.1.3 Three-Tier Discrete Opacity ($\alpha$) & Painter’s Algorithm Z-Ordering
Because `epss_score` follows an extreme heavy-tailed distribution where over $85\%$ of published CVEs cluster near the horizontal axis ($\text{EPSS} < 0.02$), uniform mark opacity produces catastrophic overplotting in which thousands of dormant records occlude active weaponized flaws. Because human vision cannot accurately decode continuous opacity ramps, CyberLens restricts alpha encoding to **three discrete perceptual tiers**, combined with explicit **Painter’s Algorithm z-index trace stratification** and border stroke modulation:
1. **Foreground Layer (`zorder = 3`, $\alpha_1 = 0.92$) — Active CISA KEV (`is_kev = True`):** Rendered last on the WebGL/SVG canvas with near-solid opacity ($\alpha_1 = 0.92$), high chroma (`#D92B2B`), and a $1.2\text{ px}$ high-contrast white ring stroke (`#FFFFFF`). This guarantees that every confirmed exploited vulnerability remains 100% unoccluded and triggers pre-attentive visual pop-out ($< 200\text{ ms}$ visual search latency) regardless of local point density.
2. **Midground Layer (`zorder = 2`, $\alpha_2 = 0.65$) — High-EPSS Silent Threats (`is_kev = False`, $\text{EPSS} \ge 0.30$):** Rendered in the intermediate layer with medium-high opacity ($\alpha_2 = 0.65$) and a $0.5\text{ px}$ dark amber perimeter stroke (`#B45309`). Semi-transparency allows overlapping unexploited high-probability flaws to accumulate additively into darker optical hotspots without masking Foreground Layer 3 marks.
3. **Background Layer (`zorder = 1`, $\alpha_3 = 0.20$) — Paper Tigers & Dormant Backlog ($\text{EPSS} < 0.30$):** Rendered first at the base of the visual stack with low opacity ($\alpha_3 = 0.20$) and **zero border stroke (`line.width = 0`)**. Eliminating border strokes on background marks prevents the formation of opaque wireframe clutter, transforming 4,000+ low-priority CVEs into a smooth, non-intrusive bivariate density field.

---

## 4.2 Idiom 2: Architectural Weakness Squarified Treemap

### 4.2.1 Space-Filling Containment Hierarchy
To satisfy **Task 2 (`Consume → Discover` $\rightarrow$ `{Browse, Compare, Summarize, Hierarchical Distribution}`)** across enterprise infrastructure tiers, **Idiom 2** implements a nested **Space-Filling Containment (Enclosure) Treemap** (`cyberlens/idiom_treemap.py`). Whereas Node-Link tree diagrams waste up to $70\%$ of screen pixels on background whitespace and become illegible when branching across dozens of CWE classifications and software vendors, a containment layout achieves **100% pixel utilization** without visual occlusion. The hierarchy is structured strictly across three structural keys:  
$$\text{Level 1: Architectural Layer (`layer`)} \longrightarrow \text{Level 2: Weakness Taxonomy (`cwe\_family`)} \longrightarrow \text{Level 3: Publisher (`vendor`)}$$
Enclosing outer margins and hierarchical header breadcrumbs visually enforce parent-child containment across `OS & Firmware`, `Network`, `Web/App`, and `Database` tiers.

### 4.2.2 Actuarial Justification of the Additive Expected Risk Metric
A fundamental mathematical requirement of space-filling treemaps is that the size-encoding variable must be a strictly non-negative, **additive ratio-scale measure** so that the area of any parent container $P$ equals the exact sum of its enclosed child tiles $c \in \text{Children}(P)$. Using raw vulnerability count ($\sum 1$) treats a dormant low-severity bug as equivalent to a wormable remote code execution flaw, while summing raw CVSS base scores ($\sum \text{CVSS}_{\text{base}}$) severely inflates layers populated by thousands of unexploited **Paper Tigers**.

To align visual tile area with true operational exposure, CyberLens defines the atomic threat weight $w_i$ of each vulnerability $i$ using the classical actuarial expected-loss formulation ($\text{Risk} = \text{Severity} \times \text{Probability}$):
$$w_i = \text{CVSS}_{\text{base}, i} \times \text{EPSS}_i \in [0.0, 10.0]$$
Because both `cvss_base` and `epss_score` are `Ordered → Quantitative` attributes with a `Sequential` direction and an absolute zero origin ($w_i = 0$ when exploitation probability or severity is zero), the aggregate hierarchical area $A(N)$ of any node $N$ (Layer, CWE Family, or Vendor) satisfies exact conservation of measure:
$$A(N) \propto W(N) = \sum_{i \in N} \left(\text{CVSS}_{\text{base}, i} \times \text{EPSS}_i\right) = \sum_{c \in \text{Children}(N)} W(c)$$
This formulation dynamically suppresses noise from high-CVSS/near-zero-EPSS compliance flaws while expanding architectural tiers that harbor high-probability threats.

### 4.2.3 Squarified Tiling Algorithm vs. Slice-and-Dice
Early treemap algorithms (such as Shneiderman’s original *Slice-and-Dice* layout) partition rectangles using alternating horizontal and vertical cuts, producing elongated, high-aspect-ratio slivers ($L/W \gg 10$). Psychophysical studies by Cleveland and McGill and Kong et al. demonstrate that human area judgment accuracy degrades severely as rectangle aspect ratios deviate from a square ($1:1$).

To minimize area estimation error, CyberLens enforces the **Squarified Treemap Algorithm** (*Bruls, Huizing, and van Wijk, 2000*) via `tiling=dict(packing="squarify")` in Plotly. Given a container rectangle of width $W$ and height $H$, the algorithm greedily adds child nodes to the current layout row only as long as doing so decreases the maximum aspect ratio penalty across the row:
$$\rho_{\max}(R) = \max_{c \in R} \max\left(\frac{w_c}{h_c}, \frac{h_c}{w_c}\right) \longrightarrow 1.0$$
By driving tile aspect ratios toward $1:1$, squarified packing maximizes perceptual accuracy during cross-layer and cross-CWE area comparisons and ensures sufficient interior width for readable typography.

### 4.2.4 Sequential Luminance Encoding for Remote Network Exposure
While tile area encodes expected risk volume $W(N)$, the analyst must also assess the structural accessibility of flaws within each CWE partition (`attack_vector`: $\text{Network} > \text{Adjacent} > \text{Local} > \text{Physical}$). For every node $N$, CyberLens computes the empirical proportion of remotely exploitable network vulnerabilities:
$$p_{\text{net}}(N) = \frac{1}{\vert{}N\vert{}} \sum_{i \in N} \mathbb{I}\left(\text{attack\_vector}_i = \text{Network}\right) \in [0\%, 100\%]$$
In strict compliance with **Mackinlay’s Expressiveness principle**—which dictates that quantitative magnitudes must be mapped to ordered magnitude channels rather than unordered multi-hue rainbow scales (*Borland & Russell, 2007*)—$p_{\text{net}}(N)$ is encoded via a **perceptually uniform, monotonically decreasing CIE HCL Luminance ($L^*$) ramp**. Tiles with predominantly local/physical prerequisites ($p_{\text{net}} \to 0\%$) render in high-luminance pastel slate ($L^* = 92$, `#F1F5F9`), whereas CWE families dominated by unauthenticated remote network vectors ($p_{\text{net}} \to 100\%$) progress monotonically to deep low-luminance navy-slate ($L^* = 32$, `#1E3A5F`), allowing the analyst to decouple aggregate risk volume (Area) from remote attack surface exposure (Luminance) at a glance.

---

## 4.3 Idiom 3: Multi-Cohort Weaponization Velocity Ridgeline Density Plot

### 4.3.1 List-Aligned Vertical Baselines vs. Boxplots and Overlapping Histograms
**Task 3 (`Consume → Discover` $\rightarrow$ `{Locate, Compare, Continuous Density / Distribution}`)** requires modeling the longitudinal distribution of elapsed weaponization time (`days_to_exploit` $= t_{\text{KEV}} - t_{\text{disclosure}} \in [0, 120]$ days) across major enterprise vendor cohorts (`Microsoft`, `Cisco`, `Linux`, `Apache`, `Fortinet`, `Oracle`, etc.). Standard visual idioms fail this task for two structural reasons:
1. **Failure of Tukey Boxplots (Loss of Multimodality):** Boxplots compress an entire probability distribution into five summary quantiles (median, quartiles, and whiskers). When a vendor cohort exhibits a **bimodal hazard regime**—such as an immediate zero-day exploitation wave ($t < 7$ days) followed by a secondary patch-diffing PoC wave ($t \in [18, 35]$ days)—a boxplot collapses both modes into a single wide interquartile box, masking the underlying threat dynamics.
2. **Failure of Overlapping Histograms / Line Charts (Spaghetti Clutter):** Plotting 6 to 10 vendor density curves on a single shared baseline produces severe visual intersection and occlusion, violating separability.

**Idiom 3** resolves both limitations by implementing a **Multi-Cohort Ridgeline Density Plot** (`cyberlens/idiom_ridgeline.py`). Each vendor cohort $m \in \{1, \dots, M\}$ is assigned a dedicated horizontal baseline at vertical offset $Y_m = m \cdot \Delta y$ (**List Alignment**), while sharing a strictly aligned horizontal quantitative axis $t \in [0, 120]$ days. Controlled partial vertical overlap ($\approx 25\%$) with opaque baseline occlusion outlines maximizes vertical space efficiency while enabling instantaneous parallel scanning of modal peaks, skewness, and tail decay across cohorts.

### 4.3.2 Mathematical Formulation of Schuster–Silverman Mirror-Reflected KDE
Because `days_to_exploit` measures elapsed duration from public NVD disclosure to confirmed exploitation, its physical domain is bounded on the left by zero ($T \in [0, +\infty)$). Given a cohort sample $\{t_1, t_2, \dots, t_n\}$ with $t_i \ge 0$, the standard Rosenblatt–Parzen Gaussian Kernel Density Estimator:
$$\hat{f}_h(t) = \frac{1}{n h} \sum_{i=1}^n K\left(\frac{t - t_i}{h}\right), \quad K(u) = \frac{1}{\sqrt{2\pi}} e^{-u^2 / 2}$$
suffers from severe **Zero-Boundary Spillover Bias**. Because the symmetric Gaussian kernel $K(\cdot)$ has infinite support $(-\infty, +\infty)$, observations near $t_i = 0$ (zero-day exploits) allocate up to half of their probability weight to negative times $t < 0$. Expanding $\mathbb{E}[\hat{f}_h(t)]$ in a Taylor series at $t = 0$ reveals an $O(1)$ asymptotic downward bias:
$$\lim_{n \to \infty} \mathbb{E}[\hat{f}_h(0)] = \frac{1}{2} f(0) - \frac{h}{\sqrt{2\pi}} f'(0^+) + O(h^2) \approx 0.5 \cdot f(0)$$
Thus, uncalibrated Gaussian KDE artificially suppresses zero-day weaponization spikes ($t < 7$ days) by nearly **50%**.

To restore exact boundary consistency at $t = 0$ without distorting the linear time scale via logarithmic axis warping, CyberLens implements the **Schuster–Silverman Mirror Reflection Estimator** (*Schuster, 1985; Silverman, 1986*). For every observed duration $t_i \ge 0$, a reflected virtual point is generated at $-t_i \le 0$, yielding the boundary-corrected density estimator on $t \ge 0$:
$$\hat{f}_{\text{refl}}(t) = \begin{cases} \displaystyle \frac{1}{n h} \sum_{i=1}^n \left[ K\left(\frac{t - t_i}{h}\right) + K\left(\frac{t + t_i}{h}\right) \right] = \hat{f}_h(t) + \hat{f}_h(-t), & \text{for } t \ge 0 \\ 0, & \text{for } t < 0 \end{cases}$$

This estimator guarantees three essential statistical properties for our analytical defense:
1. **Unbiased Zero-Boundary Recovery:** At $t = 0$, the first-derivative linear error terms cancel by symmetry ($\hat{f}'_{\text{refl}}(0^+) = 0$), yielding $\mathbb{E}[\hat{f}_{\text{refl}}(0)] = f(0) + O(h^2)$ and preserving the true amplitude of $t \in [0, 4]$ day zero-day spikes.
2. **Exact Conservation of Probability Mass:** By folding the spilled negative density $\hat{f}_h(-t)$ back onto $[0, +\infty)$, the integral over the physical domain equals unity:
   $$\int_0^\infty \hat{f}_{\text{refl}}(t)\,dt = \int_0^\infty \hat{f}_h(t)\,dt + \int_{-\infty}^0 \hat{f}_h(u)\,du = \int_{-\infty}^\infty \hat{f}_h(u)\,du = 1$$
3. **Outlier-Resistant Bandwidth Selection:** Because weaponization durations exhibit heavy right tails, the smoothing bandwidth $h$ is computed strictly on the unreflected non-negative sample using **Silverman’s Rule of Thumb with Interquartile Range (IQR)** scaling:
   $$h = 0.9 \cdot \min\left(\hat{\sigma}_t, \frac{\text{IQR}(t)}{1.34}\right) \cdot n^{-\frac{1}{5}}$$
   preventing extreme long-tail outliers ($t > 100$ days) from over-smoothing sharp zero-day spikes near $t = 0$.

---

## 4.4 Colorimetry & Universal Accessibility (Topic 8 Compliance)

### 4.4.1 Perceptually Uniform CIE HCL Specification & Dual-Chroma Calibration
Standard RGB/HSL color spaces are perceptually non-uniform: equal numerical steps in RGB produce drastic, unintended jumps in perceived brightness. To guarantee perceptual uniformity, CyberLens specifies all categorical and sequential palettes directly in cylindrical **CIE $L^*C^*h^\circ$ (HCL)** coordinates—controlling **Hue ($H^\circ \in [0^\circ, 360^\circ)$)**, **Chroma / Saturation ($C^* \in [0, 100+]$)**, and **Perceptual Luminance ($L^* \in [0, 100]$)**.

Crucially, human chromatic perception depends heavily on the visual angle (retinal subtense) of the mark (**Course Topic 8, Slide 3**):
* **Small Marks (Idiom 1 Scatter Bubbles, $r \in [3, 14]\text{ px}$):** Require **high chroma ($C^* \in [55, 82]$)** and strong luminance contrast so that small point targets stimulate cone photoreceptors sufficiently for pre-attentive chromatic identification.
* **Large Contiguous Areas (Idiom 2 Treemap Tiles & Idiom 3 Ridgeline Fills):** Rendering large enclosing rectangles at maximum saturation induces retinal afterimages, visual vibration, and simultaneous contrast illusions. Therefore, CyberLens pairs every high-chroma scatter color with an **isohue, desaturated pastel/moderate companion tone ($C^* \in [6, 38], L^* \in [80, 92]$) for large area fills, preserving effortless cross-view semantic linking without ocular fatigue.

| Semantic Threat Tier / 4D K-Means Cluster | Idiom 1: Small Marks CIE HCL ($H^\circ, C^*, L^*$) | Idiom 1 Hex & Calibrated $\alpha$ | Idiom 2/3: Large Area Companion HCL ($H^\circ, C^*, L^*$) | Idiom 2/3 Pastel Companion Hex | Monochromatic Grayscale ($L^*$) | CVD (Protanopia / Deuteranopia) Perceived Appearance |
|---|---|---|---|---|---|---|
| **Active CISA KEV / Cluster A (Critical Weapons)** | $(22^\circ, 82, 48)$ | `#D92B2B`<br>($\alpha_1 = 0.92$) | $(22^\circ, 32, 80)$ | `#F2B8B5` | **$L^* = 48$**<br>*(Darkest anchor)* | Deep Warm Umber / Dark Bronze (Unambiguous dark focal point) |
| **High EPSS / Cluster B (Silent Threats)** | $(72^\circ, 78, 72)$ | `#E69F00`<br>($\alpha_2 = 0.65$) | $(75^\circ, 38, 89)$ | `#F9DF99` | **$L^* = 72$**<br>*(Bright mid-high)* | Vibrant Golden Ochre (Orthogonal yellow channel) |
| **Paper Tigers / Cluster C (Compliance Noise)** | $(245^\circ, 55, 60)$ | `#3B7DD8`<br>($\alpha_3 = 0.20$) | $(245^\circ, 28, 85)$ | `#BFD7F5` | **$L^* = 60$**<br>*(Intermediate)* | Clear Cerulean Blue (Stimulates intact S-cones) |
| **Dormant Backlog / Cluster D (Low Risk)** | $(255^\circ, 8, 82)$ | `#94A3B8`<br>($\alpha_3 = 0.20$) | $(255^\circ, 6, 92)$ | `#E2E8F0` | **$L^* = 82$**<br>*(Lightest context)* | Neutral Cool Silver-Gray (Recedes into background) |

### 4.4.2 Universal Accessibility: Daltonism (CVD) & Monochromatic Grayscale Validation
Approximately $8\%$ of male analysts experience inherited color vision deficiency (CVD), predominantly **Protanopia** (absent L-cones) and **Deuteranopia** (absent M-cones). Conventional "Traffic Light" (Red–Yellow–Green) security dashboards fail under protan/deuteran vision because pure red ($H^\circ \approx 0^\circ, L^* \approx 53$) and pure green ($H^\circ \approx 120^\circ, L^* \approx 53$) project onto identical coordinates along the red-green confusion axis.

CyberLens guarantees universal accessibility through a dual defense (**Topic 8, Slide 25**):
1. **Orthogonal Yellow–Blue Opponent Axis Selection:** By completely eliminating green from the categorical encoding and positioning the four threat classes along the **Crimson-Vermilion ($22^\circ$) – Golden Amber ($72^\circ$) – Cerulean Blue ($245^\circ$) – Achromatic Slate ($255^\circ$)** trajectory (inspired by the psychophysically validated *Okabe–Ito* colorblind-safe specification), the palette relies primarily on the blue–yellow opponent channel, which remains fully functional in both protanopes and deuteranopes.
2. **Strict Monotonic Luminance Separation ($\Delta L^* \ge 12$):** Even under complete achromatopsia (monochromatic grayscale printing or total cone failure), the four priority tiers maintain distinct, non-overlapping perceptual lightness levels:
   $$L^*_{\text{KEV}} (48) < L^*_{\text{PaperTiger}} (60) < L^*_{\text{HighEPSS}} (72) < L^*_{\text{Backlog}} (82)$$
   Combined with redundant visual channels in **Idiom 1** (high-contrast white border rings on KEV marks and spatial quadrant position), zero analytical information is lost under any form of color vision deficiency.

---

## 4.5 Coordinated Multi-View Architecture & Shneiderman’s Mantra

### 4.5.1 Reactive Execution of Shneiderman’s Visual Information-Seeking Mantra
Implemented in **Python 3.12**, **Shiny for Python**, and **Plotly** (`cyberlens/app.py`), the coordinated interface operationalizes **Ben Shneiderman’s (1996) Visual Information-Seeking Mantra** (*"Overview first, zoom and filter, then details-on-demand"*) across a single-screen, zero-scrolling workspace:

| Shneiderman Stage | User Interaction Trigger in CyberLens | Coordinated System Response Across Idioms 1, 2, and 3 | Munzner Action Taxonomy |
|---|---|---|---|
| **1. Overview First** | Initial application load or Global Stack Reset. | Renders the complete 4,500+ CVE risk frontier in **Idiom 1**, the full 3-tier corporate containment hierarchy in **Idiom 2**, and baseline multi-vendor KDE ridges in **Idiom 3**. | `Consume → Discover` $\rightarrow$ `{Explore, Summarize}` |
| **2. Zoom** | Clicking an enclosing container (`Layer` or `CWE Family`) in **Idiom 2**. | Smoothly animates a hierarchical drill-down in the Squarified Treemap, expanding child CWE families and software vendors to fill the container viewport with an interactive breadcrumb path bar. | `Navigate → Zoom` (Hierarchical Drill-Down) |
| **3. Filter** | Modifying the **Global Enterprise Asset Filter**, dragging CVSS/EPSS crosshair sliders, or selecting an architectural tier for Focus+Context. | Propagates reactive state changes (`reactive.calc`) across the directed acyclic graph (DAG): updates **Idiom 1** via Focus+Context ghosting, recalculates **Idiom 2** expected risk areas, and filters **Idiom 3** vendor cohorts. | `Manipulate → Select / Filter` (Cross-View Brushing & Linking) |
| **4. Details-on-Demand** | Hovering or clicking an individual vulnerability mark in **Idiom 1**. | Displays a structured telemetry overlay containing `cve_id`, `vendor`, `layer`, `cwe_family`, exact `cvss_base`, `cvss_impact`, `epss_score`, `attack_vector`, `privileges_required`, `days_to_exploit`, and 4D K-Means archetype. | `Query → Identify` (Single-Target Inspection) |

### 4.5.2 Focus+Context Brushing & Spatial Mental Map Preservation
A critical pitfall in multi-view visual analytics occurs when cross-filtering dynamically autoscales scatterplot axes. If an analyst clicks a specific weakness family in **Idiom 2** (e.g., `Database → SQL Injection`) whose vulnerabilities span $\text{CVSS}_{\text{base}} \in [6.5, 8.8]$ and $\text{EPSS} \in [0.001, 0.04]$, allowing Plotly to autoscale the $Y$-axis to $[0.0, 0.045]$ causes a low-risk flaw ($\text{EPSS} = 0.04$) to jump visually to the top of the chart. Because planar spatial position dominates human risk perception ($a \approx 1.0$), dynamic axis rescaling shatters **spatial constancy** (the analyst’s cognitive mental map) and induces severe false-positive triage errors.

To preserve absolute spatial constancy during bidirectional cross-filtering between **Idiom 2 (Treemap)** and **Idiom 1 (Bubble Plot)**, CyberLens implements a **Locked Coordinate Frame + Focus+Context Attenuation Architecture**:
1. **Invariant Spatial Reference Frame:** Across all reactive filter states, the planar coordinate axes of **Idiom 1** remain strictly locked to the global domain (`xaxis.range = [0.0, 10.3]`, `yaxis.range = [-0.03, 1.05]`), and the interactive quadrant crosshair lines ($X_{\text{thresh}}, Y_{\text{thresh}}$) remain stationary.
2. **Contextual Ghosting Attenuation ($\alpha_{\text{ghost}} = 0.05$):** When an analyst selects a hierarchical node $N_{\text{sel}}$ in **Idiom 2** (such as `Layer: Network` or `CWE-787: Out-of-Bounds Write`), the reactive engine partitions the active dataset $D$ into a focused subset $D_{\text{focus}} = \{i \in D \mid i \in N_{\text{sel}}\}$ and a contextual complement $D_{\text{context}} = D \setminus D_{\text{focus}}$.
   * Marks in $D_{\text{context}}$ are retained in their exact $(X_i, Y_i)$ spatial coordinates on the bottom canvas layer (`zorder = 0`), but their chromatic channels are desaturated to neutral cool slate (`#CBD5E1`, $C^* = 6, L^* = 85$) and their opacity is attenuated to $\alpha_{\text{ghost}} = 0.05$.
   * Marks in $D_{\text{focus}}$ are elevated to the foreground layers (`zorder = 2, 3`) at full calibrated CIE HCL chroma and opacity ($\alpha_1 = 0.92$ for KEV, $\alpha_2 = 0.65$ for High EPSS), surrounded by high-contrast border strokes.
3. **Cognitive Benefit:** This Focus+Context design allows the analyst to immediately evaluate the selected architectural weakness *relative to the global corporate risk distribution* without losing spatial orientation, while an optional binary isolation switch (`Hide non-selected context`) sets $\alpha_{\text{ghost}} = 0.0$ when pure subset inspection is desired.
