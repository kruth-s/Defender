# Browser-Driven Evidence Augmentation and Selective Abstention for Explainable Phishing Website Detection

**Target Venue:** ICTCS 2026 (Springer LNNS)  
**Authors:** Atreyaa AVS (✉), Kruthik S, C Athish Kiran Kumar, Ayushman Patel, and Monesh N  
**Affiliation:** RV University, Bengaluru, India (`atreyaaavs.btech23@rvu.edu.in`)  
**Artifact Repository:** `f:\Defender`

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

### 1.1 Empirical SSRF Boundary Validation

| Target Category | Candidate Input Target | Resolved Scope | Enforcement Layer | Verdict |
| :--- | :--- | :--- | :--- | :---: |
| **Loopback IPv4** | `http://127.0.0.1:8080/admin` | 127.0.0.1 | Pre-flight Host Filter | **BLOCKED** |
| **Loopback Hostname** | `http://localhost:3000/api` | 127.0.0.1 | DNS Pre-resolution | **BLOCKED** |
| **Loopback IPv6** | `http://[::1]/status` | ::1 | Host Parser Filter | **BLOCKED** |
| **Private RFC 1918 (Class A)** | `http://10.0.1.5/internal-auth` | 10.0.1.5 | Subnet Range Validator | **BLOCKED** |
| **Private RFC 1918 (Class B)** | `http://172.16.5.20/db-admin` | 172.16.5.20 | Subnet Range Validator | **BLOCKED** |
| **Private RFC 1918 (Class C)** | `http://192.168.1.1/setup.cgi` | 192.168.1.1 | Subnet Range Validator | **BLOCKED** |
| **Cloud Instance Metadata** | `http://169.254.169.254/latest/` | 169.254.169.254 | Link-Local / Metadata Blacklist | **BLOCKED** |
| **GCP Cloud Metadata** | `http://metadata.google.internal/` | Metadata Scope | Prohibited Host Filter | **BLOCKED** |
| **Disallowed Scheme (file)** | `file:///etc/passwd` | Local Filesystem | Scheme Whitelist Guard | **BLOCKED** |
| **Disallowed Scheme (gopher)** | `gopher://127.0.0.1:6379/_` | Legacy Protocol | Scheme Whitelist Guard | **BLOCKED** |
| **Unsafe Redirect Cascade** | `https://pub.site/r` &rarr; `192.168.1.50` | 192.168.1.50 | Hop-by-Hop Redirect Check | **BLOCKED** |
| **Public Benign Domain** | `https://example.com/login` | 93.184.216.34 | Validated Public Host | **ALLOWED** |
| **Public Secured DNS** | `https://1.1.1.1/dns-query` | 1.1.1.1 | Validated Public Host | **ALLOWED** |

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

### 2.5 Feature-Wise Contribution & Threat Rationale Analysis

| Feature Identifier | Modality | Log-Odds Weight | Impact Direction | Security / Threat Rationale |
| :--- | :--- | :---: | :---: | :--- |
| `suspicious_keyword_count` | Static URL | $+2.7127$ | Phishing Risk ($+$) | Presence of credential-harvesting tokens (*login*, *verify*, *auth*). |
| `cert_longevity_days` | Dynamic Transport | $-2.1606$ | Benign Trust ($-$) | Multi-year certificates characteristic of vetted enterprise domains. |
| `csp_blocks_eval_inline` | Dynamic Transport | $-1.8361$ | Benign Trust ($-$) | Strict CSP mitigates script injection and credential-harvesting overlays. |
| `hostname_length` | Static URL | $+1.3782$ | Phishing Risk ($+$) | Extended hostname length typical of deceptive sub-domain masking. |
| `x_frame_options_strict` | Dynamic Transport | $-1.3075$ | Benign Trust ($-$) | Anti-framing policy (`DENY`/`SAMEORIGIN`) blocks clickjacking lures. |
| `has_iframe` | Static HTML | $+1.3027$ | Phishing Risk ($+$) | Hidden iframes frequently embed secondary credential harvesting forms. |
| `script_reflection_detected` | Dynamic Behavioral | $+1.2900$ | Phishing Risk ($+$) | Active probe reflection unmasks client-side parameter tampering. |
| `has_csp` | Dynamic Transport | $+1.2599$ | Contextual Risk ($+$) | Superficial CSP presence without strict execution boundaries. |
| `has_ip_address` | Static URL | $+1.1509$ | Phishing Risk ($+$) | Raw IP literals bypass DNS domain reputation mechanisms. |
| `has_x_frame_options` | Dynamic Transport | $+0.9650$ | Contextual Risk ($+$) | Permissive framing policies often copied by automated cloning kits. |
| `cert_valid` | Dynamic Transport | $-0.6876$ | Benign Trust ($-$) | Valid cryptographic handshake confirms baseline TLS compliance. |
| `has_x_content_type_options`| Dynamic Transport | $-0.6770$ | Benign Trust ($-$) | `nosniff` directive blocks MIME-type confusion attacks. |
| `has_referrer_policy` | Dynamic Transport | $-0.6155$ | Benign Trust ($-$) | Strict referrer controls protect sensitive tokens from leaking. |
| `hsts_max_age_adequate` | Dynamic Transport | $-0.5205$ | Benign Trust ($-$) | Persistent HSTS headers prevent SSL-stripping downgrades. |
| `form_action_cross_domain` | Dynamic Behavioral | $+0.1711$ | Phishing Risk ($+$) | Forms transmitting credentials to an unrelated external domain. |
| `cert_is_free_or_short_lived`| Dynamic Transport | $-0.1771$ | Contextual Neutral | Free automated TLS issuance (Let's Encrypt); contextual signal. |
| `entropy` | Static URL | $+0.0605$ | Phishing Risk ($+$) | High Shannon entropy characteristic of algorithmically generated domains. |

*Contextual Handling of Free Certificates:* Free automated certificates (Let's Encrypt / ZeroSSL) are treated as contextual signals rather than deterministic phishing indicators. BEAP never blocks a site solely due to a free certificate. Instead, cross-modal conjunction (e.g., cross-domain form action + missing security headers vs. same-domain form action + valid HSTS/CSP) discriminates malicious from legitimate usage, while ambiguous configurations safely trigger selective abstention.

---

## 3. Operational Deployment & SOC Workload Management

### 3.1 SOC Analyst Workload Management
At $\delta = 0.25$, BEAP achieves 97.84% automated coverage and defers 2.16% of ambiguous traffic (22 per 1,000 URLs) to SOC analysts. To manage alert volume:
1. **Directional Risk-Prioritized Queueing:** Abstained cases are sorted descending by posterior risk $f(\mathbf{x})$, immediately escalating borderline threats leaning towards $\tau_{high}$ (e.g. $p \approx 0.70$) over low-risk ambiguities.
2. **Multi-Tier Severity Triage:** High-urgency cases (active credential fields + cross-domain targets) receive immediate human review; lower-urgency edge cases are queued for off-peak inspection.
3. **Pre-Compiled Diagnostic Dossiers:** Closed-form log-odds attributions and exact session evidence provide instant evidentiary clarity, avoiding slow manual script de-obfuscation.
4. **Safe Deferral Containment:** Deferred cases are never default-allowed; they are placed under provisional isolation (e.g., remote browser sandbox or cautionary interstitial banner).
5. **Adaptive Margin Modulation:** Under burst volume, $\delta$ can be dynamically narrowed (e.g., to 0.15), expanding automated coverage to 98.63% while maintaining 99.60% selective accuracy.

### 3.2 Threats to Validity and Scope Limitations

1. **Processing vs. Network Latency Separation:** The 2.03 ms figure represents computational decision pipeline latency (feature vectorization, inference, and log-odds calculation). Active network transport inspection requires socket connections and handshakes, with an unavoidable network latency floor of 0.5–2.0 s.
2. **Development Benchmark Scope & External Feeds:** The 2,400-sample benchmark is an offline development dataset with domain-disjoint splitting. Ongoing validation against live threat intelligence feeds (e.g., OpenPhish, PhishTank) is essential for longitudinal robustness.
3. **Safety Controls:** Network probing is strictly protected by pre-flight and hop-by-hop SSRF validation boundaries.
