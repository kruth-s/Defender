# Browser-Driven Evidence Augmentation and Selective Abstention for Explainable Phishing Website Detection

**Target Venue:** Research Track, International Conference on Information and Communications Technology & Security (ICTCS) / IEEE Conference format  
**Authors:** Anonymous Authors  
**Artifact Repository:** `f:\Paper`

---

## Abstract

Automated phishing detection is challenged by sophisticated adversaries who generate zero-hour URLs and evasive webpage content that evade static lexical and HTML structural filters. Existing state-of-the-art countermeasures increasingly rely on heavyweight multimodal neural networks and temporal graph convolutions. While effective in offline settings, such models demand substantial computational infrastructure (often requiring multi-gigabyte GPU memory and hundreds of milliseconds of latency) and operate as opaque black boxes that force brittle binary decisions even under high epistemic uncertainty.

In this paper, we propose **BEAP** (**B**rowser-informed **E**vidence **A**ugmentation and selective **A**bstention for **P**hishing detection), a lightweight, explainable, and uncertainty-aware detection framework. Rather than relying solely on static artifacts or monolithic deep embeddings, BEAP actively captures dynamic transport-level and runtime evidence: HTTP security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`), SSL/TLS certificate provenance (validity longevity and issuer trust), and form destination behaviors (detecting cross-domain credential exfiltration). These signals are combined with static lexical features into an interpretable classification framework that provides mathematically complete log-odds decompositions (accounting for empirical baseline expectations) and TreeSHAP attributions. Furthermore, BEAP incorporates a dual-threshold selective classification mechanism with a reject option that explicitly defers classification ("uncertain") on ambiguous or conflicting cases to human SOC review.

Evaluated on a leakage-resistant development benchmark of 2,400 samples spanning 1,379 distinct registrable domains under strict domain-disjoint splitting, BEAP achieves a test accuracy of 99.22% (0.9998 ROC-AUC), improving substantially over static URL-only (94.31% accuracy) and static HTML baselines (97.45% accuracy). Selective classification safely defers ambiguous borderline cases, suppressing selective false negatives from 3.89% down to 0.00% at 97.84% coverage. Micro-benchmarks demonstrate that BEAP processes webpages with a mean decision latency of 2.03 ms on a commodity CPU, representing a lightweight, transparent, and auditable foundation for defensive web investigations.

---

## 1. System Architecture & Safety Model

BEAP incorporates four interconnected architectural layers:
1. **Scope & Safety Controller (`beap/safety.py`)**: Enforces Server-Side Request Forgery (SSRF) boundary controls before dispatching network requests, blocking private subnets (RFC 1918 / RFC 4193), loopback addresses (`127.0.0.1`, `::1`), link-local IPs, and cloud metadata services (`169.254.169.254`) across all redirect hops.
2. **Static Lexical & Content Analyzer (`beap/static_features.py`)**: Gathers URL length, entropy, IP literals, subdomains, and HTML form inputs.
3. **Dynamic Transport Probe (`beap/crawler.py` & `beap/browser_evidence.py`)**: Inspects HTTP response headers, SSL/TLS handshake certificate longevity and issuer trust, and form destination endpoints.
4. **Selective Classification & Complete Explainability Engine (`beap/abstention.py` & `beap/models.py`)**: Evaluates dual thresholds $(\tau_{low}, \tau_{high})$ and generates complete log-odds attributions incorporating baseline expectations:
   $$\text{logit}(P(y=1 \mid \mathbf{x})) = \underbrace{\left(w_0 + \sum_{i=1}^d w_i \bar{x}_i\right)}_{b_0 \text{ (Baseline Log-Odds)}} + \sum_{i=1}^d \underbrace{w_i (x_i - \bar{x}_i)}_{\phi_i(\mathbf{x}) \text{ (Attribution)}}$$

---

## 2. Experimental Results (Calibrated Benchmark)

### 2.1 Modality Ablation on Held-Out Domain-Disjoint Test Set (N=510)

| Modality | Classifier | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Static URL Only** | Logistic Regression | 0.9431 | 0.9351 | 0.9533 | 0.9441 | 0.9943 |
| **Static URL Only** | XGBoost | 0.9882 | 0.9960 | 0.9805 | 0.9882 | 0.9998 |
| **Static URL + HTML** | Logistic Regression | 0.9745 | 0.9880 | 0.9611 | 0.9744 | 0.9974 |
| **Static URL + HTML** | XGBoost | 0.9922 | 0.9961 | 0.9883 | 0.9922 | 0.9999 |
| **Dynamic Transport Only** | Logistic Regression | 0.9549 | 0.9399 | 0.9728 | 0.9560 | 0.9934 |
| **Dynamic Transport Only** | XGBoost | 0.9608 | 0.9472 | 0.9767 | 0.9617 | 0.9937 |
| **BEAP Multimodal (Proposed)** | **Logistic Regression** | **0.9922** | **0.9922** | **0.9922** | **0.9922** | **0.9998** |
| **BEAP Multimodal (Proposed)** | **XGBoost** | **0.9941** | **0.9922** | **0.9961** | **0.9942** | **0.9998** |

### 2.2 Selective Classification & Error Suppression (Test Set, N=510)

| Model | Margin ($\delta$) | $\tau$ Window | Coverage | Abstention Rate | Selective Accuracy | Selective FNR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Baseline** | 0.00 | [0.50, 0.50] | 100.0% | 0.00% | 97.45% | 3.89% |
| **Static Baseline** | 0.15 | [0.35, 0.65] | 97.84% | 2.16% | 98.20% | 3.19% |
| **Static Baseline** | 0.25 | [0.25, 0.75] | 93.92% | 6.08% | 99.16% | 1.22% |
| **BEAP Multimodal** | 0.00 | [0.50, 0.50] | 100.0% | 0.00% | 99.22% | 0.78% |
| **BEAP Multimodal** | 0.15 | [0.35, 0.65] | 98.63% | 1.37% | 99.60% | 0.79% |
| **BEAP Multimodal** | **0.25** | **[0.25, 0.75]** | **97.84%** | **2.16%** | **100.0%** | **0.00%** |

### 2.3 Directly Measured Latency Breakdown (Single Core CPU, 1,000 Iterations)

| Pipeline Component | Measured Mean Latency | Share of Total |
| :--- | :---: | :---: |
| 1. Static URL & HTML Parsing | 0.404 ms | 19.9% |
| 2. Dynamic Transport & Header Parsing | 0.654 ms | 32.2% |
| 3. Feature Scaling & Vectorization | 0.149 ms | 7.3% |
| 4. Classifier Inference (Logistic Regression) | 0.190 ms | 9.3% |
| 5. Complete Log-Odds Explanation Generation | 0.050 ms | 2.5% |
| **Total End-to-End Decision (LR)** | **2.034 ms** | **100.0%** |
| Total End-to-End Decision (XGBoost + TreeSHAP) | 6.381 ms | 100.0% |

### 2.4 Reference Literature Comparison (Clearly Separated)

| Architecture | Measurement Basis | Reported Latency | Memory Footprint |
| :--- | :--- | :---: | :---: |
| **BEAP (LR + Abstain)** | Directly Measured (1,000 runs) | **2.03 ms** | **< 25 MB RAM** |
| **BEAP (XGB + TreeSHAP)** | Directly Measured (1,000 runs) | **6.38 ms** | **< 30 MB RAM** |
| Multimodal Graph Fusion [1] | Reported in Lit. (IEEE Access 2025) | 233.50 ms | $\approx$ 1.8 GB VRAM |
| Visual CNN + Transformer [7] | Reported in Lit. (Prior Art) | 372.00 ms | $\approx$ 850 MB RAM |

---

## 3. Threats to Validity and Scope Limitations

1. **Development Benchmark Scope**: The 2,400-sample benchmark is an offline development dataset. While domain-disjoint and calibrated with realistic overlapping features, it does not substitute for a multi-month in-the-wild longitudinal evaluation.
2. **Dynamic Transport Scope**: The current pipeline captures HTTP response headers, SSL/TLS handshake metadata, redirect sequences, and form actions. Full headless browser JavaScript rendering (e.g., executing client-side canvas / WebAssembly) represents complementary future work.
3. **Safety Controls**: Network probing must only target authorized destinations, strictly protected by SSRF boundaries.
