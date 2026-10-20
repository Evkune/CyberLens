# Appendix: Mathematical Formulations & Statistical Foundations
**CyberLens Project — Technical Reference Notes**  
*Complementary documentation to the main research report.*

---

## 1. Boundary-Corrected Kernel Density Estimation (Idiom 3)

### 1.1 The Boundary Spillover Problem
Let $\{t_1, t_2, \dots, t_n\}$ be observed elapsed durations from vulnerability disclosure to confirmed in-the-wild exploitation ($t_i \ge 0$). The standard Gaussian Kernel Density Estimator is defined as:
$$\hat{f}_h(t) = \frac{1}{n h} \sum_{i=1}^n K\left(\frac{t - t_i}{h}\right), \quad K(u) = \frac{1}{\sqrt{2\pi}} e^{-u^2 / 2}$$

Because the Gaussian kernel $K(u)$ has support on $(-\infty, +\infty)$, probability mass leaks into the negative domain $t < 0$ for points near zero. Near $t = 0$:
$$\lim_{n \to \infty} \mathbb{E}[\hat{f}_h(0)] \approx 0.5 \cdot f(0)$$
This artificially suppresses zero-day weaponization spikes ($t < 7$ days) by approximately 50%.

### 1.2 Schuster–Silverman Mirror Reflection Formulation
To enforce the physical boundary $t \ge 0$ without arbitrary domain truncations or logarithmic warping, CyberLens implements the Schuster–Silverman mirror reflection estimator:
$$\hat{f}_{\text{refl}}(t) = \begin{cases} \displaystyle \frac{1}{n h} \sum_{i=1}^n \left[ K\left(\frac{t - t_i}{h}\right) + K\left(\frac{t + t_i}{h}\right) \right] = \hat{f}_h(t) + \hat{f}_h(-t), & t \ge 0 \\ 0, & t < 0 \end{cases}$$

**Key Mathematical Properties:**
1. **First-Order Derivative Cancellation:** By reflection symmetry, $\hat{f}'_{\text{refl}}(0^+) = 0$, eliminating the linear boundary bias term ($O(h)$ error vanishes).
2. **Exact Mass Conservation:**
   $$\int_0^\infty \hat{f}_{\text{refl}}(t)\,dt = \int_{-\infty}^\infty \hat{f}_h(u)\,du = 1$$
3. **Bandwidth Selection:** Computed on the unreflected sample using Silverman's robust rule with Interquartile Range (IQR):
   $$h = 0.9 \cdot \min\left(\hat{\sigma}_t, \frac{\text{IQR}(t)}{1.34}\right) \cdot n^{-1/5}$$

---

## 2. Psychophysical Mark Area Scaling (Idiom 1)

### 2.1 Stevens' Power Law & Sizing Constants
Human perception of 2D area exhibits compressive scaling governed by Stevens' Law:
$$S = k \cdot I^a \quad (a \approx 0.7)$$
To prevent bubble occlusion while ensuring visual differentiability across destructive impact scores ($I \in [0.0, 6.0]$), target mark area $A_i$ is mapped as:
$$A_i = A_{\min} + k \cdot \left(\text{CVSS}_{\text{impact}, i}\right)^{0.7}$$

With bounds $r_{\min} = 3.0\text{ px}$ ($A_{\min} \approx 28.27\text{ px}^2$) and $D_{\max} = 28.0\text{ px}$ ($A_{\max} \approx 615.75\text{ px}^2$):
$$k = \frac{A_{\max} - A_{\min}}{(6.0)^{0.7}} = \frac{615.75 - 28.27}{3.5051} \approx 167.61\text{ px}^2$$

In Plotly's rendering engine (`cyberlens/idiom_bubble.py`), area mode is locked via:
$$\text{sizeref} = \frac{2 \cdot A_{\max}}{D_{\max}^2} = \frac{2 \cdot 615.75}{28.0^2} \approx 1.5708$$

---

## 3. Unsupervised 4D Logit K-Means Clustering Engine

### 3.1 Feature Space Construction
To cluster vulnerabilities across severity, empirical risk, and accessibility:
$$\mathbf{x}_i = \left[ \text{CVSS}_{\text{base}, i}, \,\, \text{logit}(\text{EPSS}_i), \,\, \text{CVSS}_{\text{impact}, i}, \,\, \text{access\_ease}_i \right]$$
where:
* $\text{logit}(p) = \ln\left(\frac{p}{1 - p}\right)$ with $p$ clipped to $[10^{-4}, 1 - 10^{-4}]$.
* $\text{access\_ease}_i = 8.22 \times W_{\text{AV}} \times W_{\text{PR}}$ using official CVSS v3.1 exploitability weights:
  - $W_{\text{AV}} \in \{0.85\text{ (Network)}, 0.62\text{ (Adjacent)}, 0.55\text{ (Local)}, 0.20\text{ (Physical)}\}$
  - $W_{\text{PR}} \in \{0.85\text{ (None)}, 0.62\text{ (Low)}, 0.27\text{ (High)}\}$

### 3.2 Standardization & Centroid Optimization
Each feature dimension is standardized via Z-score:
$$z_{i,j} = \frac{x_{i,j} - \mu_j}{\sigma_j}$$
Clustering is performed using K-Means++ with $k=4$, yielding robust convergence (Davies–Bouldin Index = $1.299$, Calinski–Harabasz Index = $1522.9$, Silhouette Score = $0.237$).
