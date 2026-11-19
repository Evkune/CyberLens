# Defense Brief: CyberLens (Visual Analytics for Vulnerability Management)
**Course:** Data Visualization (103001004) — Master Innovación Digital (UPM)  
**Authors:** Evan Gendrot (Lead Software Architect & CTI Lead) & Minerva Nayeli Rosas Sanchez (Process Integration & Enterprise Systems Lead)  
**Target Reading Time:** 4 minutes

---

### 1. Pitch Express (3 phrases)
CyberLens is a threat-informed visual analytics platform that resolves the enterprise vulnerability triage bottleneck by confronting theoretical severity (CVSS v3.1) with empirical exploit prediction (FIRST EPSS v3) and real-world weaponization telemetry (CISA KEV) across **3,092 live enterprise CVEs (521 KEVs, 114 Ransomware, 27 EPSS 30d Surges)**. Built with Python and Shiny for Python using deep modular engineering (`ingestion/`, `domain/`, `viz/`, `ui/`), persistent WebGL `FigureWidget` views, and a bidirectional Cross-Filter Bus, the system allows corporate security leads to filter their specific software stack, drill down into structural weaknesses via space-filling squarified treemaps, and analyze longitudinal weaponization velocity distributions across technology cohorts. By combining calibrated multi-channel visual encodings with unsupervised **5D Logit K-Means** threat clustering (`Silhouette = 0.570`), CyberLens compresses the actionable SOC queue by **-64.4%** while maintaining **100% CISA KEV recall** (vs. **85.8%** under CVSS-only triage, which misses **74** active KEVs).

---

### 2. Les 4 Choix Techniques Structurants (Alignement Topics 5 à 8)

1. **Python + Shiny for Python (vs Streamlit ou Dash) :**
   - *Pourquoi :* Shiny implémente un véritable modèle de graphe de réactivité dynamique (`reactive.calc`, `@reactive.effect`, `FigureWidget` persistants via `batch_update()`). Contrairement à Streamlit qui ré-exécute l'intégralité du script à chaque clic (latence inacceptable pour 3 000+ items WebGL), Shiny isole les recalculs au composant modifié (ex. basculer le switch `K-Means 5D` n'invalide ni le Treemap, ni les KDE SciPy du Ridgeline, ni la Patch Queue). Cela permet d'offrir une expérience 60fps tout en restant dans l'écosystème Python de cybersécurité (Pandas, Scikit-learn, SciPy) validée par 37 tests `pytest`.
2. **Treemap Hiérarchique Squarified (*Topic 7, Slides 34–36*) :**
   - *Pourquoi :* Un diagramme en barres 1D saturerait en scrolling avec des dizaines de feuilles hiérarchiques, et un graphe Nœuds-Liens (*Node-Link*) gaspillerait l'espace. Le Treemap optimise 100 % de l'espace d'affichage (*space-filling*). L'algorithme *Squarified* force des ratios d'aspect proches de 1:1, où l'œil humain estime le plus précisément les surfaces.
3. **Ridgeline Plot avec Réflexion Miroir de Schuster-Silverman (*Topic 6 & 8*) :**
   - *Pourquoi :* Élimine le piège des requêtes SQL ponctuelles (min/max) et la perte d'information des boxplots (qui masquent la multimodalité des attaques). La réflexion miroir $\hat{f}(t) + \hat{f}(-t)$ élimine la fuite de masse vers $t < 0$ et préserve le pic des *zero-days* ($t < 7$ jours).
4. **Calibration Psychophysique de Stevens ($a = 0.7$) & Palette CIE HCL (*Topic 8*) :**
   - *Pourquoi :* Respect strict du principe d'efficacité de Mackinlay. La position spatiale X/Y encode les deux métriques reines. La taille des bulles encode l'impact CVSS calibrée en surface ($S = A_{\min} + k \cdot I^{0.7}$, $D_{\max}=28\text{px}$) pour annuler la sous-estimation perceptive. La palette Okabe-Ito / CIE HCL garantit une séparation de luminance monotone ($\Delta L^* \ge 12$) et une hiérarchie d'opacité graduée ($\alpha_{\text{P0}}=0.94, \alpha_{\text{P1}}=0.84, \alpha_{\text{P2}}=0.68, \alpha_{\text{P3}}=0.25, \alpha_{\text{P4}}=0.20$) avec formes pré-attentives (`diamond` pour Ransomware KEV, `triangle-up` pour EPSS Surge) pour éliminer l'overplotting tout en préservant le pop-out sous daltonisme (protanopie/deutéranopie).

---

### 3. Les Questions Pièges d'Examen Écrit / Oral & Réponses Clés

#### Q1. Dans le Treemap, vous encodez la surface par le risque actuariel $\sum (\text{CVSS} \times P_{\text{eff}})$. Comment justifiez-vous la multiplication d'une probabilité $[0, 1]$ et d'un score synthétique $[0, 10]$ ? (Topics 5 & 7)
> **Réponse :** « Un Treemap à remplissage d'espace requiert une métrique strictement additive et non négative à échelle de ratio pour que la surface de chaque conteneur parent égale exactement la somme de ses enfants. En gestion du risque actuariel, le risque attendu suit la formule classique $\text{Risque} = \text{Probabilité} \times \text{Gravité}$, où $P_{\text{eff}} = 1.0$ pour les KEV confirmées et $P_{\text{eff}} = \text{EPSS}$ sinon, et où le CVSS fournit le poids de sévérité. Ces deux attributs étant quantitatifs séquentiels avec un zéro absolu ($0.0 = \text{aucun risque}$), leur produit forme une mesure d'espérance de perte valide représentant fidèlement l'empreinte de menace de chaque couche. »

#### Q2. Selon le classement de Cleveland & McGill, la position alignée (diagramme en barres) est plus précise que la surface 2D (Treemap). Pourquoi avoir choisi un Treemap ? (Topics 6 & 7)
> **Réponse :** « Si un diagramme en barres permet des comparaisons par paires plus précises, notre hiérarchie à 3 niveaux (`Couche → CWE → Vendeur`) génère des dizaines de partitions à travers 3 092 CVEs (13 vendeurs canoniques), provoquant une fragmentation par défilement vertical ou un gaspillage d'espace blanc en arbre nœuds-liens. Le Treemap garantit une efficacité spatiale de 100 % en révélant simultanément la composition architecturale globale et les anomalies structurelles sans occlusion. De plus, nous utilisons l'agencement *Squarified* pour optimiser les rectangles vers des carrés $1:1$, où l'erreur d'estimation des surfaces par l'œil humain est minimale. »

#### Q3. Dans l'Idiome 1 vous utilisez la Teinte de couleur pour le statut KEV, et dans l'Idiome 2 la Luminance pour la part d'exposition réseau. Pourquoi ne pas inverser ? (Topic 8)
> **Réponse :** « Selon le principe d'expressivité de Mackinlay, les canaux d'identité comme la teinte (*hue*) n'ont pas d'ordre perceptif naturel et correspondent donc aux attributs catégoriques (statut booléen CISA KEV), tandis que les canaux de magnitude comme la luminance possèdent un ordre naturel (du clair au foncé) adapté aux données quantitatives continues (pourcentage d'exposition réseau). Inverser ces canaux violerait l'expressivité : encoder un pourcentage continu par des teintes multiples recréerait une carte arc-en-ciel trompeuse (*Borland & Russell 2007*), tandis qu'encoder le statut KEV uniquement par la luminance ferait perdre le pop-out pré-attentif indispensable pour repérer immédiatement une menace critique dans un nuage dense. »

#### Q4. Pourquoi `attack_vector` et `privileges_required` sont-ils classés en `Ordered → Ordinal` (Sequential) plutôt qu'en `Categorical` ? (Topic 5)
> **Réponse :** « Dans le modèle de Munzner, l'abstraction de données découle de la sémantique métier et des opérations valides, pas du type de stockage en base (`string`). `Network > Adjacent > Local > Physical` définit une topologie d'accessibilité réseau strictement monotone, tout comme `None < Low < High` définit une barrière d'authentification croissante. Comme les intervalles entre ces échelons ne sont pas métriquement égaux, ce ne sont pas des données quantitatives de ratio mais des variables strictement **Ordered → Ordinal** avec une progression **Sequential** (du plus exposé au plus restreint). »

#### Q5. Pourquoi garder un axe Y linéaire par défaut pour l'EPSS dans l'Idiome 1 alors que vous utilisez une transformation Logit dans le K-Means 5D ? (Topics 6 & 8)
> **Réponse :** « Parce que la tâche visuelle et le modèle algorithmique n'ont pas les mêmes objectifs. Dans l'Idiome 1 (Bubble Plot), un axe logarithmique allouerait 75% de l'espace vertical à distinguer des probabilités négligeables entre 0.0001 et 0.01, propulsant le bruit de fond au centre de l'écran (nous offrons tout de même le switch `Log10` à la demande pour inspecter la queue de distribution). Pour l'analyste exécutant la tâche de triage, toute valeur $< 0.05$ sans signal KEV/Surge mène à la même décision (maintenance différée). L'axe linéaire ($[0, 1]$) respecte la perception directe des probabilités ($a \approx 1.0$) et tasse intentionnellement le bruit en bas. En revanche, dans le K-Means 5D (`[cvss_base, logit(epss), epss_delta_30d, cvss_impact, access_ease]`, Silhouette `0.570`), la transformation logit est indispensable pour éviter que la distance euclidienne ne soit faussée par l'asymétrie extrême de l'EPSS. »

#### Q6. Pourquoi accepter un chevauchement partiel (25%) dans le Ridgeline plutôt que d'utiliser des Small Multiples strictement séparés ? (Topic 6)
> **Réponse :** « Diviser l'écran en 8 à 10 small multiples indépendants réduirait tellement la hauteur allouée à chaque série que les courbes de densité s'aplatiraient en lignes horizontales illisibles, masquant la bimodalité des vagues d'attaque. Le Ridgeline Plot avec 25% de chevauchement contrôlé et contour contrasté offre +40% de résolution d'amplitude par série. Comme la tâche consiste à comparer la position des modes le long de l'axe temporel partagé ($X = \text{days\_to\_exploit}$), cette disposition maximise la lisibilité des formes sans perte d'alignement temporel. »

---

### 4. Synergie Génie Industriel & Gestion des Processus (Contribution de Minerva)

Minerva apporte une lecture issue du **génie des systèmes industriels et de la théorie des files d'attente**, transformant CyberLens en un régulateur de flux opérationnel pour le SOC :

1. **Loi de Little ($L = \lambda W$) et Stabilité du SOC :**
   - Un centre d'opérations de sécurité est un atelier à capacité de traitement limitée ($\mu$).
   - Sous les règles classiques (`CVSS >= 7.0`), le flux d'arrivée des fausses urgences ($\lambda_{\text{compliance}} = 1\,521$ tickets sur les 3 092 CVE) dépasse la capacité de l'équipe ($\rho = \frac{\lambda}{\mu} > 1$), saturant la file d'attente (*alert fatigue*), tout en ne capturant que **85,8 % des KEV** (**74 KEV ratées**).
   - CyberLens agit comme un **filtre signal/bruit** : en déviant les **1 054 *Paper Tigers*** (tier `P3`, EPSS moyen $0.0098$) vers un traitement par lots à 60 jours et en sauvant les **75 *Silent Threats*** (`Q2`), la file actionnable (`P0–P2`) chute à **542 tickets** (**-64,4 % de charge SOC**) avec **100 % de capture KEV** (521/521, dont **CVE-2024-3400** sur PAN-OS en `P0 < 24h`, et **CVE-2024-38063** sur Windows TCP/IP identifiée en `P2` via EPSS `73.6%`). Le système retrouve sa stabilité ($\rho < 1$) et le délai moyen de résolution ($W = \text{MTTR}$) s'effondre.

2. **Marge de Sécurité en Boucle Fermée ($\Delta t_{\text{safety}} > 0$) :**
   - En fiabilité industrielle, un système est stable si le temps de réaction de l'actionneur ($\text{SLA}$) est plus court que le temps d'apparition de la panne ($t_{\text{exploit}}$) : $\Delta t_{\text{safety}} = t_{\text{KDE}} - \text{SLA} > 0$.
   - Sur notre snapshot réel, la médiane globale d'exploitation est de **13,0 jours**, mais les politiques classiques appliquent un SLA uniforme de 14 jours, produisant une **marge négative** pour les équipements réseau périmétriques dont la médiane s'effondre à **1–6 jours** (`Fortinet` $P_{50}=1\text{j}$, `Ivanti` $P_{50}=3\text{j}$, `Cisco` $P_{50}=5\text{j}$, `Palo Alto Networks` $P_{50}=6\text{j}$, avec $>53\%$ d'armement $\le 7\text{j}$).
   - La matrice de gouvernance à 5 paliers restaure une marge positive : $\text{SLA} < 24\text{h}$ (`P0`, 356 CVEs) pour les KEV réseau/ransomware, `< 72h` (`P1`, 167 CVEs) pour les Silent Threats/Surges, et `< 14j` (`P2`, 19 CVEs) pour les risques EPSS élevés hors KEV.

---

### 5. Positionnement CVSS v4.0 & Argument Portfolio (Entretien PFE / CISO)

Pour tes entretiens de stage de fin d'études (PFE) en CTI / Recherche de Vulnérabilités :
- **L'avance sur le marché :** La spécification CVSS v4.0 pousse le paradigme **CVSS-BTE** (*Base, Threat, Environmental*) pour remplacer le score de base isolé. Mais comme le NVD ne publie que le Base score (`CVSS-B`), les entreprises ont du mal à l'adopter.
- **CyberLens comme pionnier :** CyberLens est déjà une **implémentation opérationnelle du modèle CVSS-BTE** :
  - **Base (B) :** NVD CVSS v3.1 (sévérité intrinsèque).
  - **Threat (T) :** FIRST EPSS v3 + CISA KEV (probabilité dynamique et armement réel).
  - **Environmental (E) :** Filtre d'inventaire d'actifs et Treemap architectural.
- **Évolution vers CVSS v4.0 :** Le passage à CVSS v4.0 se fera sans rupture grâce à notre typologie ordonnée de Munzner : le nouveau paramètre *Attack Requirements (AT)* enrichira directement notre variable d'accessibilité (`access_ease` intégrant déjà `attack_complexity`) dans le K-Means 5D, et l'impact sur les systèmes subséquents (*Subsequent System Impact*) sera directement encodé par la surface des bulles de l'Idiome 1.
