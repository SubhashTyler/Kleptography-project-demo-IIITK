# Kleptography Cyber-Range: Breaking Trust in Cryptography

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-10b981)
![Netlify Ready](https://img.shields.io/badge/Netlify-Static%20Bundle%20Generator-00C7B7?logo=netlify&logoColor=white)
![Cryptography](https://img.shields.io/badge/RSA-1024--bit%20SETUP%20Backdoor-ef4444)
![License](https://img.shields.io/badge/Purpose-Educational%20Simulation-f59e0b)

An interactive cybersecurity and cryptography demonstration of a **Kleptographic SETUP (Secretly Embedded Trapdoor with Universal Protection)** attack against RSA key generation and TLS/PKI infrastructure.

Built with a **Dual-Engine Architecture**, this single Python script runs a local multi-threaded HTTP simulation server **and** automatically compiles a standalone static web application (`netlify_deploy/`) powered by a native browser `BigInt` cryptographic engine for instant deployment on **Netlify**.

---

## Table of Contents

1. [Overview & Threat Model](#overview--threat-model)
2. [Key Features](#key-features)
3. [Cryptographic Architecture (How It Works)](#cryptographic-architecture-how-it-works)
4. [Repository Structure](#repository-structure)
5. [Quick Start: Run Locally via CMD / Terminal](#quick-start-run-locally-via-cmd--terminal)
6. [Deploy to Netlify](#deploy-to-netlify)
7. [Step-by-Step Interactive Demo Walkthrough](#step-by-step-interactive-demo-walkthrough)
8. [Defense & Real-World PKI Mitigations](#defense--real-world-pki-mitigations)
9. [Security Notice](#security-notice)

---

## Overview & Threat Model

In standard Public Key Infrastructure (PKI), if a Man-in-the-Middle (MITM) attacker intercepts an HTTPS connection and presents a self-signed or mismatched certificate, the client's browser immediately blocks the connection with a certificate authority warning.

**Kleptography** (introduced by Adam Young and Moti Yung) changes this paradigm. If a Certificate Authority (CA), Hardware Security Module (HSM), or key-generation library is subverted, it can embed an **asymmetric cryptographic backdoor** inside newly generated keys:

* **Indistinguishable Output:** The generated $1024$-bit RSA public modulus $N = p \times q$ passes standard OpenSSL structure checks and Shannon entropy randomness tests.
* **No Browser Warnings During MITM:** The victim server deploys the genuine, CA-signed X.509 certificate. An attacker intercepting traffic presents this *exact same* valid certificate, keeping the browser's TLS padlock green and verified.
* **Exclusive Key Recovery:** By extracting a public nonce embedded in an X.509 certificate extension and combining it with the attacker's secret master passphrase, the attacker deterministically reconstructs the victim's private primes $p$ and $q$ and private exponent $d$ in milliseconds—without factoring $N$.

---

## Key Features

* **Dual-Engine Execution:**
  * **Local Python Engine (`127.0.0.1:8000`):** Executes all cryptographic operations in Python using only the standard library (`hashlib`, `hmac`, `secrets`, `http.server`).
  * **Browser Web Engine (Netlify Static Mode):** Automatically falls back to a pure JavaScript `BigInt` implementation of SHA-256, HMAC-SHA256, DRNG, and 24-round Miller-Rabin primality testing when hosted statically on Netlify.
* **Live 4-Node Network Topology HUD:** Real-time visual status tracking across the Root CA, Victim Production Host, BGP/ARP Network Routing Path, and Kleptographic Attacker Node.
* **X.509 v3 Certificate & PEM Inspector:** Generates realistic PEM blocks (`-----BEGIN CERTIFICATE-----`), ASN.1 metadata, SHA-256 thumbprints, Shannon entropy scores, and custom X.509 extension OIDs (`1.3.6.1.4.1.44924.1.9`).
* **Simulated Client Browser & Banking Portal:** Features an interactive HTTPS URL bar, clickable TLS certificate padlock inspector, and an online treasury portal (*ApexVault*) for encrypting and transmitting secrets.
* **MITM Packet Sniffer & Cryptanalysis Console:** Captures encrypted `TLS_RSA_WITH_AES_256_GCM_SHA384` records and displays the step-by-step mathematical reconstruction of $p, q, \phi(N),$ and $d$.
* **SIEM Audit Telemetry:** Millisecond-timestamped syslog console tracking every key generation, deployment, routing hijack, and decryption event.

---

## Cryptographic Architecture (How It Works)

### 1. Deterministic Trapdoor Key Generation (Subverted CA)
Instead of drawing independent random seeds from a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) for primes $p$ and $q$, the subverted CA generates a $16$-byte public $\text{Nonce}$ and derives a deterministic seed using the attacker's secret $\text{MasterKey}$ and the target $\text{Domain}$:

$$\text{MasterHash} = \text{SHA256}(\text{MasterKey})$$

$$\text{Seed} = \text{HMAC-SHA256}\left(\text{MasterHash},\ \text{Domain} \parallel \text{Nonce}\right)$$

The $\text{Seed}$ initializes a counter-mode Deterministic Random Bit Generator (DRNG), where each $256$-bit block $c \in \{0, 1, 2, \dots\}$ is computed as:

$$\text{Block}_c = \text{SHA256}\left(\text{Seed} \parallel c\right)$$

### 2. Prime Generation & RSA Parameters
Using the byte stream from $\text{Block}_c$, the engine generates two $512$-bit candidate integers and tests them with $24$ rounds of the **Miller-Rabin Primality Test** to obtain primes $p$ and $q$ ($p \neq q$):

$$N = p \times q, \quad \phi(N) = (p - 1)(q - 1), \quad e = 65537$$

$$d \equiv e^{-1} \pmod{\phi(N)}$$

The CA publishes $(N, e)$ and hides $\text{Nonce}$ inside the X.509 v3 extension field `authorityKeyNonce_OID_1_3_6_1_4_1_44924_1_9`.

### 3. Encryption & Kleptographic Recovery
When the client browser submits a secret message $m$ (padded using PKCS#1 v1.5 structure), it encrypts the payload using the server's public key:

$$c \equiv m^e \pmod{N}$$

To recover the private key $d$, the attacker reads $\text{Domain}$ and $\text{Nonce}$ from the public certificate, supplies $\text{MasterKey}$, re-runs the identical DRNG stream to regenerate $p$ and $q$, verifies that $p \times q = N$, computes $d$, and decrypts the captured ciphertext:

$$m \equiv c^d \pmod{N}$$

---

## Repository Structure

```text
.
├── klepto_demo.py           # Main script (Local HTTP Server + Static Bundle Generator)
├── README.md                # Project documentation
└── netlify_deploy/          # Auto-generated when klepto_demo.py runs
    ├── index.html           # Standalone Web App with built-in JS BigInt Crypto Engine
    └── netlify.toml         # Netlify deployment and security header configuration
```

---

## Quick Start: Run Locally via CMD / Terminal

### Prerequisites
* **Python $3.8$ or higher** (No external `pip` packages required; uses $100\%$ Python standard library).

### Step 1: Clone the Repository
```cmd
git clone https://github.com/your-username/kleptography-demo.git
cd kleptography-demo
```

### Step 2: Launch the Cyber-Range
```cmd
python klepto_demo.py
```
Upon execution, the script performs two actions automatically:
1. Generates the Netlify static deployment bundle inside `./netlify_deploy/`.
2. Starts the local web server at `http://127.0.0.1:8000`.

```text
[+] Netlify static bundle generated at: C:\kleptography-demo\netlify_deploy
[+] Local Kleptography Cyber-Range running at: http://127.0.0.1:8000
```

### Step 3: Open in Browser
Navigate to **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in any modern web browser.

---

## Deploy to Netlify

Because `klepto_demo.py` compiles a self-contained static bundle into `netlify_deploy/`, you can host the interactive demo on Netlify without needing a Python backend server.

### Option A: Netlify Drag & Drop (Fastest)
1. Run `python klepto_demo.py --build-only` to generate the `netlify_deploy/` directory.
2. Visit **[app.netlify.com/drop](https://app.netlify.com/drop)**.
3. Drag and drop the `netlify_deploy` folder onto the page to get an instant live HTTPS URL.

### Option B: Deploy via Command Prompt (`netlify-cli`)
```cmd
:: 1. Build the static bundle and exit immediately
python klepto_demo.py --build-only

:: 2. Authenticate with Netlify
npx netlify-cli login

:: 3. Deploy to production
npx netlify-cli deploy --prod --dir=netlify_deploy
```

---

## Step-by-Step Interactive Demo Walkthrough

Follow this 5-step flow during live demonstrations to showcase the full lifecycle of a kleptographic attack:

| Step | Tab | Action | What to Observe |
| :--- | :--- | :--- | :--- |
| **1. Inject Trapdoor** | `1. Subverted CA (Keygen)` | Click **`⚡ Issue Backdoored X.509 Certificate`** | Inspect the PEM block, the normal Shannon entropy ($\approx 7.19$ bits/byte), and the public `nonce` inside the X.509 extension. |
| **2. Victim Deployment** | `2. Victim Production Server` | Click **`🚀 Deploy Certificate & Start Nginx on :443`** | Observe `openssl rsa -check` returning `RSA key ok`. The administrator cannot detect any statistical anomaly. |
| **3. Arm MITM Clone** | `4. MITM Sniffer` $\rightarrow$ `3. Client Browser` | Click **`1. Spin Up Phishing/MITM Clone`** (Tab 4), then **`📡 Enable Active MITM Redirection`** & **`↻ Reload`** (Tab 3) | The Network HUD turns red (`HIJACKED`), and the URL bar shows traffic routed via the MITM clone—**yet the `🔒 Verified TLS` padlock remains green!** |
| **4. Transmit Secret** | `3. Client Browser & TLS Padlock` | Click **`🔐 Encrypt with Server Public Key & Transmit`** | A $1024$-bit RSA PKCS#1 v1.5 ciphertext is generated and intercepted in transit. |
| **5. Reconstruct Key** | `4. MITM Sniffer & Key Recovery` | Click **`🔓 Execute SETUP Private Key Recovery & Decrypt Traffic`** | Watch the math engine extract the certificate nonce, replay the HMAC-SHA256 DRNG, reconstruct $p, q,$ and $d$, and decrypt the wire transfer secret. |
| **6. Verify Defense** | `1. Subverted CA` $\rightarrow$ `4. MITM Sniffer` | Click **`🛡️ Issue Honest CSPRNG Certificate`** (Tab 1), then attempt recovery in Tab 4 | Recovery immediately aborts because true CSPRNG randomness contains no deterministic trapdoor seed. |

---

## Defense & Real-World PKI Mitigations

How do modern cryptographic systems protect against Kleptographic SETUP attacks?

1. **Local Key Generation (Strict CSR Workflow):** Subscribers must *never* allow a Certificate Authority or third-party service to generate their private keys. Private keys must be generated locally on trusted hardware, sending only a **Certificate Signing Request (CSR)** containing the public key $(N, e)$ to the CA.
2. **Forward Secrecy (ECDHE / TLS 1.3):** Modern TLS 1.3 mandates ephemeral Diffie-Hellman key exchange (`ECDHE`), ensuring that even if a server's long-term RSA signing key is compromised, past or passive session traffic cannot be decrypted purely from captured ciphertexts.
3. **Verifiable Randomness & Open-Source Audits:** Using open, reproducible hardware RNGs and mixing entropy from multiple independent sources prevents a single subverted component from deterministically controlling prime generation.

---

## Security Notice

> **Educational & Academic Use Only:** This project is a self-contained local and browser-based mathematical simulation designed for university cryptography courses, security demonstrations, and awareness training. It performs no real network ARP spoofing, BGP hijacking, or interception of external systems.