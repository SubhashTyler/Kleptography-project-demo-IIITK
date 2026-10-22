#!/usr/bin/env python3
"""
Kleptography: Breaking Trust in Cryptography
Dual-mode interactive demo (Local Python Server + Netlify Standalone Build Generator).
"""
import base64
import datetime
import hashlib
import hmac
import json
import math
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST, PORT = "127.0.0.1", 8000
RSA_BITS = 1024
E = 65537

STATE = {
    "victim": None,
    "clone_live": False,
    "mitm": False,
    "captured": [],
    "log": []
}


def sha256(b):
    return hashlib.sha256(b).digest()


def hmac256(k, d):
    return hmac.new(k, d, hashlib.sha256).digest()


def drng(seed):
    c = 0
    while True:
        block = hashlib.sha256(seed + c.to_bytes(8, "big")).digest()
        c += 1
        for b in block:
            yield b


def is_prime(n, rng):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(24):
        a = 2 + ((next(rng) << 8) | next(rng)) % (n - 4)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(rng, bits):
    while True:
        cand = 0
        rem = bits
        while rem > 0:
            cand = (cand << 8) | next(rng)
            rem -= 8
        cand |= (1 << (bits - 1)) | 1
        if is_prime(cand, rng):
            return cand


def rsa_from_primes(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    if phi % E == 0:
        return None
    return {"n": n, "e": E, "d": pow(E, -1, phi), "p": p, "q": q}


def honest_keygen(bits=RSA_BITS):
    while True:
        p = gen_prime(drng(secrets.token_bytes(32)), bits // 2)
        q = gen_prime(drng(secrets.token_bytes(32)), bits // 2)
        if p != q:
            k = rsa_from_primes(p, q)
            if k:
                return k


def backdoored_keygen(domain, master, bits=RSA_BITS):
    mk = sha256(master.encode())
    nonce = secrets.token_bytes(16)
    while True:
        seed = hmac256(mk, domain.encode() + nonce)
        rng = drng(seed)
        p = gen_prime(rng, bits // 2)
        q = gen_prime(rng, bits // 2)
        if p == q:
            nonce = secrets.token_bytes(16)
            continue
        k = rsa_from_primes(p, q)
        if k:
            k["nonce"] = nonce.hex()
            return k


def recover_key(domain, master, nonce_hex):
    mk = sha256(master.encode())
    seed = hmac256(mk, domain.encode() + bytes.fromhex(nonce_hex))
    rng = drng(seed)
    p = gen_prime(rng, RSA_BITS // 2)
    q = gen_prime(rng, RSA_BITS // 2)
    k = rsa_from_primes(p, q)
    if k:
        k["nonce"] = nonce_hex
    return k


def sign(key, msg):
    return pow(int.from_bytes(sha256(msg), "big"), key["d"], key["n"])


def encrypt(key, text):
    data = text.encode()
    if len(data) > RSA_BITS // 8 - 11:
        raise ValueError("Secret too long for demo RSA key (max ~100 chars).")
    padded = b"\x00\x02" + secrets.token_bytes(RSA_BITS // 8 - len(data) - 3).replace(b"\x00", b"\x01") + b"\x00" + data
    return pow(int.from_bytes(padded, "big"), key["e"], key["n"])


def decrypt(key, ct):
    m = pow(ct, key["d"], key["n"])
    padded = m.to_bytes(RSA_BITS // 8, "big")
    parts = padded.split(b"\x00", 2)
    if len(parts) >= 3:
        return parts[2].decode(errors="replace")
    return ""


def fingerprint(n):
    raw = sha256(str(n).encode()).hex().upper()
    return ":".join(raw[i:i+2] for i in range(0, 32, 2))


def shannon_entropy(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    counts = [0] * 256
    for byte in b:
        counts[byte] += 1
    ent = 0.0
    for c in counts:
        if c > 0:
            p = c / len(b)
            ent -= p * math.log2(p)
    return round(ent, 3)


def make_pem(label, raw_str):
    b64 = base64.b64encode(raw_str.encode()).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----"


def log(m):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    STATE["log"].insert(0, f"[{ts}] {m}")
    STATE["log"] = STATE["log"][:100]


def issue_cert(domain, master, honest):
    if honest:
        key = honest_keygen()
        nonce = ""
        bd = False
    else:
        key = backdoored_keygen(domain, master)
        nonce = key["nonce"]
        bd = True
    ca = honest_keygen()
    now = datetime.datetime.now(datetime.timezone.utc)
    serial = secrets.token_hex(10).upper()
    payload_obj = {
        "version": "X.509 v3 (0x2)",
        "serialNumber": ":".join(serial[i:i+2] for i in range(0, 20, 2)),
        "signatureAlgorithm": "sha256WithRSAEncryption (1.2.840.113549.1.1.11)",
        "issuer": "C=US, O=TrustCore Global Root CA G3, CN=TrustCore Issuing CA",
        "validity": {
            "notBefore": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "notAfter": (now + datetime.timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S UTC")
        },
        "subject": f"C=US, ST=California, O=ApexVault Financial Corp, CN={domain}",
        "domain": domain,
        "n": str(key["n"]),
        "n_hex": hex(key["n"])[2:].upper(),
        "e": key["e"],
        "fingerprint": fingerprint(key["n"]),
        "entropy": shannon_entropy(key["n"]),
        "extensions": {
            "basicConstraints": "CA:FALSE",
            "keyUsage": "Digital Signature, Key Encipherment",
            "extendedKeyUsage": "TLS Web Server Authentication",
            "authorityKeyNonce_OID_1_3_6_1_4_1_44924_1_9": nonce if nonce else "00" * 16
        },
        "nonce": nonce,
        "backdoor": bd
    }
    payload = json.dumps(payload_obj, sort_keys=True).encode()
    sig_hex = hex(sign(ca, payload))[2:]
    pem = make_pem("CERTIFICATE", json.dumps({"cert": payload_obj, "sig": sig_hex}))
    cert = {"payload": payload.decode(), "signature": sig_hex, "pem": pem}
    STATE["victim"] = {"domain": domain, "key": key, "cert": cert, "deployed": False}
    STATE["captured"] = []
    STATE["clone_live"] = False
    log(f"CA issued {'HONEST CSPRNG' if honest else 'SETUP BACKDOORED'} X.509v3 certificate for {domain} (Serial {payload_obj['serialNumber'][:11]}...).")
    return cert


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kleptography Cyber-Range: RSA SETUP Backdoor & TLS MITM Simulation</title>
<style>
:root {
  --bg: #070b12;
  --panel: #0f1623;
  --panel-alt: #141e30;
  --border: #22324d;
  --accent: #3b82f6;
  --accent-glow: rgba(59,130,246,0.25);
  --danger: #ef4444;
  --success: #10b981;
  --warn: #f59e0b;
  --text: #e2e8f0;
  --muted: #8b9bb4;
  --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: radial-gradient(circle at 50% 0%, #131f35 0%, var(--bg) 70%);
  color: var(--text);
  margin: 0;
  min-height: 100vh;
}
header {
  background: rgba(15, 22, 35, 0.9);
  backdrop-filter: blur(10px);
  padding: 14px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  position: sticky;
  top: 0;
  z-index: 100;
}
.brand { display: flex; align-items: center; gap: 12px; }
.shield {
  width: 38px; height: 38px; border-radius: 9px;
  background: linear-gradient(135deg, #2563eb, #dc2626);
  display: flex; align-items: center; justify-content: center;
  font-weight: 800; font-size: 18px; color: #fff;
  box-shadow: 0 0 16px rgba(220, 38, 38, 0.35);
}
h1 { margin: 0; font-size: 19px; letter-spacing: -0.3px; }
.sub { color: var(--muted); font-size: 12.5px; margin-top: 2px; }
.mode-pill {
  font-family: var(--mono);
  font-size: 11px;
  padding: 6px 11px;
  border-radius: 999px;
  background: #162238;
  border: 1px solid #2b426b;
  color: #93c5fd;
  display: flex;
  align-items: center;
  gap: 7px;
}
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); box-shadow: 0 0 8px var(--success); }

main { max-width: 1240px; margin: 18px auto; padding: 0 16px 40px; }

/* Live Network Topology HUD */
.topo-bar {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px 18px;
  margin-bottom: 18px;
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  position: relative;
}
@media (max-width: 820px) { .topo-bar { grid-template-columns: 1fr 1fr; } }
.node {
  background: var(--panel-alt);
  border: 1px solid #263859;
  border-radius: 9px;
  padding: 10px 12px;
  position: relative;
  transition: all 0.25s ease;
}
.node.active-danger { border-color: var(--danger); box-shadow: 0 0 14px rgba(239,68,68,0.22); }
.node.active-ok { border-color: var(--success); box-shadow: 0 0 14px rgba(16,185,129,0.18); }
.node-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px; color: var(--muted); display: flex; justify-content: space-between; }
.node-main { font-size: 13.5px; font-weight: 600; margin: 5px 0 3px; color: #f8fafc; }
.node-meta { font-family: var(--mono); font-size: 11px; color: #94a3b8; }

.tabs { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
button.tab {
  background: var(--panel);
  color: #cbd5e1;
  border: 1px solid var(--border);
  padding: 10px 16px;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  font-size: 13px;
  transition: all 0.15s;
}
button.tab:hover { border-color: #3b5988; color: #fff; }
button.tab.active {
  background: linear-gradient(135deg, #2563eb, #1d4ed8);
  color: #fff;
  border-color: #60a5fa;
  box-shadow: 0 4px 14px var(--accent-glow);
}

.grid-2 { display: grid; grid-template-columns: 1fr 1.15fr; gap: 16px; }
@media (max-width: 900px) { .grid-2 { grid-template-columns: 1fr; } }

.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px;
  margin-bottom: 16px;
}
.card h2 { margin: 0 0 6px; font-size: 17px; display: flex; align-items: center; justify-content: space-between; }
.badge {
  font-family: var(--mono);
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 5px;
  font-weight: 600;
}
.badge-red { background: rgba(239,68,68,0.16); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4); }
.badge-green { background: rgba(16,185,129,0.16); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.4); }
.badge-blue { background: rgba(59,130,246,0.16); color: #93c5fd; border: 1px solid rgba(59,130,246,0.4); }
.badge-warn { background: rgba(245,158,11,0.16); color: #fcd34d; border: 1px solid rgba(245,158,11,0.4); }

label { display: block; margin: 11px 0 5px; font-size: 12.5px; color: #94a3b8; font-weight: 500; }
input {
  width: 100%;
  background: #080d16;
  color: #f1f5f9;
  border: 1px solid #283a59;
  border-radius: 7px;
  padding: 9px 11px;
  font-family: var(--mono);
  font-size: 12.5px;
}
input:focus { outline: none; border-color: var(--accent); }

.btn-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
.btn {
  background: var(--accent);
  border: 1px solid rgba(255,255,255,0.12);
  color: #fff;
  padding: 9px 14px;
  border-radius: 7px;
  cursor: pointer;
  font-weight: 600;
  font-size: 12.5px;
  transition: transform 0.1s, opacity 0.15s;
}
.btn:hover { opacity: 0.93; }
.btn:active { transform: scale(0.98); }
.btn.red { background: #dc2626; }
.btn.green { background: #059669; }
.btn.gray { background: #26354d; }

pre, .terminal {
  background: #060a10;
  border: 1px solid #1e2d47;
  padding: 13px;
  border-radius: 8px;
  overflow: auto;
  font-family: var(--mono);
  font-size: 11.8px;
  line-height: 1.5;
  color: #cbd5e1;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 410px;
  margin: 10px 0 0;
}
.small { font-size: 12.5px; color: var(--muted); line-height: 1.45; margin: 4px 0 10px; }
.hidden { display: none !important; }

/* Simulated Web Browser UI */
.browser-window {
  border: 1px solid #2b3e5e;
  border-radius: 10px;
  overflow: hidden;
  background: #0b121e;
  box-shadow: 0 12px 32px rgba(0,0,0,0.45);
}
.browser-toolbar {
  background: #162033;
  padding: 9px 12px;
  display: flex;
  align-items: center;
  gap: 10px;
  border-bottom: 1px solid #253655;
}
.win-dots { display: flex; gap: 6px; }
.win-dots span { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
.url-bar {
  flex: 1;
  background: #090f1a;
  border: 1px solid #2b4066;
  border-radius: 6px;
  padding: 6px 11px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-family: var(--mono);
  font-size: 12px;
}
.lock-btn {
  cursor: pointer;
  padding: 2px 7px;
  border-radius: 4px;
  background: rgba(16,185,129,0.14);
  color: #34d399;
  border: 1px solid rgba(16,185,129,0.3);
  font-size: 11px;
  margin-right: 8px;
}
.browser-viewport {
  padding: 22px;
  background: linear-gradient(180deg, #0f192d 0%, #09101d 100%);
  min-height: 250px;
}
.bank-box {
  max-width: 420px;
  margin: 0 auto;
  background: #131f36;
  border: 1px solid #29406b;
  border-radius: 10px;
  padding: 18px;
}
.bank-header {
  display: flex; justify-content: space-between; align-items: center;
  border-bottom: 1px solid #23375c; padding-bottom: 10px; margin-bottom: 12px;
}
.packet-table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--mono);
  font-size: 11.5px;
  margin-top: 10px;
}
.packet-table th, .packet-table td {
  border-bottom: 1px solid #1e2d47;
  padding: 7px 8px;
  text-align: left;
}
.packet-table th { color: #93c5fd; background: #0b1220; }
.kv-grid {
  display: grid;
  grid-template-columns: 165px 1fr;
  gap: 6px 10px;
  font-size: 12px;
  margin-top: 8px;
  background: #080d16;
  padding: 12px;
  border-radius: 8px;
  border: 1px solid #1e2d47;
}
.kv-key { color: var(--muted); font-weight: 500; }
.kv-val { font-family: var(--mono); color: #e2e8f0; word-break: break-all; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="shield">K</div>
    <div>
      <h1>Kleptography Cyber-Range: SETUP Attack in RSA & TLS</h1>
      <div class="sub">Asymmetric Backdoor Simulation (Young & Yung SETUP Mechanism) • Real 1024-bit RSA Math</div>
    </div>
  </div>
  <div class="mode-pill">
    <span class="dot" id="engine_dot"></span>
    <span id="engine_label">Initializing Crypto Engine...</span>
  </div>
</header>

<main>
  <!-- Live Network Topology HUD -->
  <div class="topo-bar">
    <div class="node" id="hud_ca">
      <div class="node-title"><span>1. Root CA</span><span id="hud_ca_badge" class="badge badge-blue">IDLE</span></div>
      <div class="node-main">TrustCore Global CA</div>
      <div class="node-meta" id="hud_ca_meta">No X.509 cert issued</div>
    </div>
    <div class="node" id="hud_srv">
      <div class="node-title"><span>2. Victim Host</span><span id="hud_srv_badge" class="badge badge-warn">OFFLINE</span></div>
      <div class="node-main" id="hud_srv_domain">https://victim-site.com</div>
      <div class="node-meta" id="hud_srv_meta">Port 443 closed</div>
    </div>
    <div class="node" id="hud_mitm">
      <div class="node-title"><span>3. Network / BGP Path</span><span id="hud_mitm_badge" class="badge badge-green">DIRECT</span></div>
      <div class="node-main" id="hud_mitm_main">Clean TLS 1.3 Routing</div>
      <div class="node-meta" id="hud_mitm_meta">Interceptor: Disabled</div>
    </div>
    <div class="node" id="hud_att">
      <div class="node-title"><span>4. Klepto Attacker</span><span id="hud_att_badge" class="badge badge-blue">PASSIVE</span></div>
      <div class="node-main">SETUP Key Recovery</div>
      <div class="node-meta" id="hud_att_meta">Captures: 0 packets</div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('ca',this)">1. Subverted CA (Keygen)</button>
    <button class="tab" onclick="showTab('victim',this)">2. Victim Production Server</button>
    <button class="tab" onclick="showTab('user',this)">3. Client Browser & TLS Padlock</button>
    <button class="tab" onclick="showTab('attacker',this)">4. MITM Sniffer & Key Recovery</button>
    <button class="tab" onclick="showTab('log',this)">5. SIEM Audit Telemetry</button>
  </div>

  <!-- TAB 1: EVIL CA -->
  <div id="ca" class="tab-pane">
    <div class="grid-2">
      <div class="card">
        <h2><span>Subverted Certificate Authority</span><span class="badge badge-red">SETUP INJECTOR</span></h2>
        <p class="small">
          In a Young-Yung <b>SETUP (Secretly Embedded Trapdoor with Universal Protection)</b> attack, the CA or HSM hardware generates primes $p, q$ deterministically using $\text{HMAC-SHA256}(\text{SHA256}(\text{MasterKey}), \text{Domain} \parallel \text{Nonce})$. The nonce is embedded in a standard X.509 extension.
        </p>
        <label>Target Server Common Name (CN / Domain)</label>
        <input id="domain" value="victim-site.com">
        <label>Attacker Private Master Passphrase (Held only by Evil CA)</label>
        <input id="master" value="attacker-master-secret">
        <div class="btn-row">
          <button class="btn red" onclick="handleKeygen(false)">⚡ Issue Backdoored X.509 Certificate</button>
          <button class="btn gray" onclick="handleKeygen(true)">🛡️ Issue Honest CSPRNG Certificate</button>
        </div>
        <div id="ca_metrics" style="margin-top:14px"></div>
      </div>
      <div class="card">
        <h2><span>Issued X.509 v3 Certificate & PEM Inspector</span><span class="badge badge-blue">ASN.1 DER / PEM</span></h2>
        <pre id="ca_out">No certificate issued yet. Click "Issue Backdoored X.509 Certificate" to generate a 1024-bit RSA keypair.</pre>
      </div>
    </div>
  </div>

  <!-- TAB 2: VICTIM SERVER -->
  <div id="victim" class="tab-pane hidden">
    <div class="grid-2">
      <div class="card">
        <h2><span>Victim Linux Server (Nginx TLS 1.3)</span><span class="badge badge-green">PRODUCTION HOST</span></h2>
        <p class="small">
          The system administrator inspects the keypair before deploying to production. Because the primes $p, q$ come from a cryptographic HMAC-SHA256 stream, standard statistical randomness tests pass completely.
        </p>
        <div class="btn-row">
          <button class="btn green" onclick="handleDeploy()">🚀 Deploy Certificate & Start Nginx on :443</button>
        </div>
        <div id="victim_audit" style="margin-top:14px"></div>
      </div>
      <div class="card">
        <h2><span>root@prod-web-01:/etc/nginx/ssl#</span><span class="badge badge-blue">SSH CONSOLE</span></h2>
        <pre id="victim_out">Waiting for administrator deployment command...</pre>
      </div>
    </div>
  </div>

  <!-- TAB 3: USER BROWSER -->
  <div id="user" class="tab-pane hidden">
    <div class="grid-2">
      <div>
        <div class="browser-window">
          <div class="browser-toolbar">
            <div class="win-dots">
              <span style="background:#ef4444"></span>
              <span style="background:#f59e0b"></span>
              <span style="background:#10b981"></span>
            </div>
            <div class="url-bar">
              <div>
                <span class="lock-btn" onclick="inspectPadlock()" title="Click to inspect TLS certificate">🔒 Verified TLS</span>
                <span id="browser_url">https://victim-site.com/auth/login</span>
              </div>
              <span id="route_indicator" style="font-size:11px;color:#6ee7b7">Direct Route</span>
            </div>
            <button class="btn" style="padding:5px 10px;font-size:11.5px" onclick="handleVisit()">↻ Reload</button>
          </div>
          <div class="browser-viewport">
            <div class="bank-box">
              <div class="bank-header">
                <div>
                  <div style="font-weight:700;font-size:15px;color:#f8fafc">ApexVault Corporate Treasury</div>
                  <div style="font-size:11px;color:#94a3b8" id="bank_sub">Authenticated X.509 Session</div>
                </div>
                <span class="badge badge-green">RSA-1024 OAEP/PKCS1</span>
              </div>
              <label>Wire Transfer Authorization / Vault Secret</label>
              <input id="secret" value="SWIFT-AUTH: $250,000 -> Acct #88492019 (Pass: horse-battery-staple)">
              <div class="btn-row">
                <button class="btn green" style="width:100%" onclick="handleSendSecret()">🔐 Encrypt with Server Public Key & Transmit</button>
              </div>
            </div>
          </div>
        </div>
        <div class="card" style="margin-top:14px">
          <h2><span>Network Interception Switch (BGP / ARP Hijack)</span></h2>
          <p class="small">Toggle active MITM routing to redirect client traffic through the attacker's cloned node.</p>
          <div class="btn-row">
            <button class="btn red" onclick="handleMitm(true)">📡 Enable Active MITM Redirection</button>
            <button class="btn gray" onclick="handleMitm(false)">🔌 Restore Normal Routing</button>
          </div>
        </div>
      </div>
      <div class="card">
        <h2><span>Browser TLS Handshake & Ciphertext Inspector</span><span class="badge badge-blue">DEVTOOLS SECURITY</span></h2>
        <pre id="user_out">Click "Reload" or "Encrypt with Server Public Key" in the browser to inspect the TLS session.</pre>
      </div>
    </div>
  </div>

  <!-- TAB 4: ATTACKER -->
  <div id="attacker" class="tab-pane hidden">
    <div class="grid-2">
      <div class="card">
        <h2><span>Kleptographic Attack Console</span><span class="badge badge-red">APT INTERCEPTOR</span></h2>
        <p class="small">
          Unlike traditional MITM attacks that trigger browser certificate warnings with self-signed certificates, a kleptographic attacker reconstructs the victim's <b>exact private key $d$</b> exclusively from the public certificate and master passphrase.
        </p>
        <div class="btn-row">
          <button class="btn gray" onclick="handleClone()">1. Spin Up Phishing/MITM Clone Server</button>
        </div>
        <label>2. Enter Evil CA Master Passphrase to Reconstruct $p, q, d$</label>
        <input id="rmaster" value="attacker-master-secret">
        <div class="btn-row">
          <button class="btn red" onclick="handleRecover()">🔓 Execute SETUP Private Key Recovery & Decrypt Traffic</button>
        </div>
        <h2 style="margin-top:18px"><span>Intercepted TLS Payloads (TCP/443)</span></h2>
        <table class="packet-table">
          <thead><tr><th>#</th><th>CipherSuite</th><th>Route</th><th>RSA Ciphertext (Hex Prefix)</th></tr></thead>
          <tbody id="packet_tbody"><tr><td colspan="4" style="color:var(--muted)">No encrypted packets captured yet.</td></tr></tbody>
        </table>
      </div>
      <div class="card">
        <h2><span>Cryptanalysis & Decryption Output</span><span class="badge badge-warn">MATH ENGINE</span></h2>
        <pre id="attacker_out">Awaiting key recovery execution...</pre>
      </div>
    </div>
  </div>

  <!-- TAB 5: SIEM LOG -->
  <div id="log" class="tab-pane hidden">
    <div class="card">
      <h2><span>Real-Time Cryptographic & Network Telemetry</span><span class="badge badge-blue">SYSLOG</span></h2>
      <pre id="log_out">No activity recorded yet.</pre>
    </div>
  </div>
</main>

<script>
/* ============================================================================
   DUAL-MODE ENGINE:
   Automatically uses Python backend (/api/*) when running via `python klepto_demo.py`,
   or runs 100% natively in browser JS (BigInt RSA + SHA-256) when hosted on Netlify!
   ============================================================================ */
let USE_LOCAL_PYTHON = false;

const LOCAL_STATE = {
  victim: null,
  clone_live: false,
  mitm: false,
  captured: [],
  log: []
};

// Pure synchronous SHA-256 & HMAC-SHA256 (works on Netlify, localhost, and file://)
const SHA256_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

function rotr(n, x) { return (x >>> n) | (x << (32 - n)); }

function sha256Bytes(msgBytes) {
  const l = msgBytes.length;
  const bitLenHi = Math.floor((l * 8) / 0x100000000);
  const bitLenLo = (l * 8) >>> 0;
  const padLen = ((l + 9 + 63) & ~63);
  const buf = new Uint8Array(padLen);
  buf.set(msgBytes);
  buf[l] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, bitLenHi, false);
  dv.setUint32(padLen - 4, bitLenLo, false);

  let H0=0x6a09e667, H1=0xbb67ae85, H2=0x3c6ef372, H3=0xa54ff53a,
      H4=0x510e527f, H5=0x9b05688c, H6=0x1f83d9ab, H7=0x5be0cd19;
  const W = new Uint32Array(64);

  for (let i = 0; i < padLen; i += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(i + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(7, W[t-15]) ^ rotr(18, W[t-15]) ^ (W[t-15] >>> 3);
      const s1 = rotr(17, W[t-2]) ^ rotr(19, W[t-2]) ^ (W[t-2] >>> 10);
      W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
    }
    let a=H0, b=H1, c=H2, d=H3, e=H4, f=H5, g=H6, h=H7;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[t] + W[t]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d + temp1) >>> 0; d=c; c=b; b=a; a=(temp1 + temp2) >>> 0;
    }
    H0=(H0+a)>>>0; H1=(H1+b)>>>0; H2=(H2+c)>>>0; H3=(H3+d)>>>0;
    H4=(H4+e)>>>0; H5=(H5+f)>>>0; H6=(H6+g)>>>0; H7=(H7+h)>>>0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [H0,H1,H2,H3,H4,H5,H6,H7].forEach((v, idx) => odv.setUint32(idx * 4, v, false));
  return out;
}

function hmac256Bytes(keyBytes, dataBytes) {
  let k = keyBytes.length > 64 ? sha256Bytes(keyBytes) : keyBytes;
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const b = i < k.length ? k[i] : 0;
    ipad[i] = b ^ 0x36;
    opad[i] = b ^ 0x5c;
  }
  const inner = new Uint8Array(64 + dataBytes.length);
  inner.set(ipad); inner.set(dataBytes, 64);
  const innerHash = sha256Bytes(inner);
  const outer = new Uint8Array(64 + 32);
  outer.set(opad); outer.set(innerHash, 64);
  return sha256Bytes(outer);
}

const enc = new TextEncoder();
const dec = new TextDecoder();
function toHex(u8) { return Array.from(u8).map(b => b.toString(16).padStart(2,'0')).join(''); }
function fromHex(hex) {
  const u = new Uint8Array(hex.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(hex.substr(i*2, 2), 16);
  return u;
}

function* jsDrng(seedBytes) {
  let c = 0n;
  while (true) {
    const cBuf = new Uint8Array(8);
    let tmp = c;
    for (let i = 7; i >= 0; i--) { cBuf[i] = Number(tmp & 0xffn); tmp >>= 8n; }
    const combined = new Uint8Array(seedBytes.length + 8);
    combined.set(seedBytes); combined.set(cBuf, seedBytes.length);
    const block = sha256Bytes(combined);
    c += 1n;
    for (let i = 0; i < block.length; i++) yield block[i];
  }
}

function modPow(base, exp, mod) {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) res = (res * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return res;
}

function modInv(a, m) {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

const SMALL_PRIMES = [2n,3n,5n,7n,11n,13n,17n,19n,23n,29n,31n,37n];
function jsIsPrime(n, rng) {
  if (n < 2n) return false;
  for (const p of SMALL_PRIMES) {
    if (n % p === 0n) return n === p;
  }
  let d = n - 1n, r = 0;
  while ((d & 1n) === 0n) { d >>= 1n; r++; }
  for (let i = 0; i < 24; i++) {
    const hi = BigInt(rng.next().value);
    const lo = BigInt(rng.next().value);
    const a = 2n + (((hi << 8n) | lo) % (n - 4n));
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let passed = false;
    for (let j = 0; j < r - 1; j++) {
      x = (x * x) % n;
      if (x === n - 1n) { passed = true; break; }
    }
    if (!passed) return false;
  }
  return true;
}

function jsGenPrime(rng, bits) {
  while (true) {
    let cand = 0n, rem = bits;
    while (rem > 0) {
      cand = (cand << 8n) | BigInt(rng.next().value);
      rem -= 8;
    }
    cand |= (1n << BigInt(bits - 1)) | 1n;
    if (jsIsPrime(cand, rng)) return cand;
  }
}

function jsRsaFromPrimes(p, q) {
  const E = 65537n;
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  if (phi % E === 0n) return null;
  return { n, e: 65537, d: modInv(E, phi), p, q };
}

function jsAddLog(m) {
  const now = new Date();
  const ts = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3,'0');
  LOCAL_STATE.log.unshift(`[${ts}] ${m}`);
  LOCAL_STATE.log = LOCAL_STATE.log.slice(0, 100);
}

function jsFingerprint(nBig) {
  const h = toHex(sha256Bytes(enc.encode(nBig.toString()))).toUpperCase();
  const parts = [];
  for (let i = 0; i < 32; i += 2) parts.push(h.slice(i, i+2));
  return parts.join(':');
}

function jsIssueCert(domain, master, honest) {
  let key, nonceHex = "", bd = false;
  if (honest) {
    while (true) {
      const s1 = crypto.getRandomValues(new Uint8Array(32));
      const s2 = crypto.getRandomValues(new Uint8Array(32));
      const p = jsGenPrime(jsDrng(s1), 512);
      const q = jsGenPrime(jsDrng(s2), 512);
      if (p !== q) { key = jsRsaFromPrimes(p, q); if (key) break; }
    }
  } else {
    const mk = sha256Bytes(enc.encode(master));
    let nonce = crypto.getRandomValues(new Uint8Array(16));
    while (true) {
      const domBytes = enc.encode(domain);
      const data = new Uint8Array(domBytes.length + 16);
      data.set(domBytes); data.set(nonce, domBytes.length);
      const seed = hmac256Bytes(mk, data);
      const rng = jsDrng(seed);
      const p = jsGenPrime(rng, 512);
      const q = jsGenPrime(rng, 512);
      if (p === q) { nonce = crypto.getRandomValues(new Uint8Array(16)); continue; }
      key = jsRsaFromPrimes(p, q);
      if (key) { nonceHex = toHex(nonce); key.nonce = nonceHex; bd = true; break; }
    }
  }
  const serialRaw = toHex(crypto.getRandomValues(new Uint8Array(10))).toUpperCase();
  const serial = Array.from({length:10}, (_,i)=>serialRaw.slice(i*2,i*2+2)).join(':');
  const now = new Date();
  const nextYr = new Date(now.getTime() + 365*86400000);
  const payloadObj = {
    version: "X.509 v3 (0x2)",
    serialNumber: serial,
    signatureAlgorithm: "sha256WithRSAEncryption (1.2.840.113549.1.1.11)",
    issuer: "C=US, O=TrustCore Global Root CA G3, CN=TrustCore Issuing CA",
    validity: {
      notBefore: now.toISOString().replace('T',' ').slice(0,19) + ' UTC',
      notAfter: nextYr.toISOString().replace('T',' ').slice(0,19) + ' UTC'
    },
    subject: `C=US, ST=California, O=ApexVault Financial Corp, CN=${domain}`,
    domain: domain,
    n: key.n.toString(),
    n_hex: key.n.toString(16).toUpperCase(),
    e: 65537,
    fingerprint: jsFingerprint(key.n),
    entropy: 7.194,
    extensions: {
      basicConstraints: "CA:FALSE",
      keyUsage: "Digital Signature, Key Encipherment",
      extendedKeyUsage: "TLS Web Server Authentication",
      authorityKeyNonce_OID_1_3_6_1_4_1_44924_1_9: nonceHex || "00".repeat(16)
    },
    nonce: nonceHex,
    backdoor: bd
  };
  const payloadStr = JSON.stringify(payloadObj);
  const b64 = btoa(JSON.stringify({cert: payloadObj, sig: toHex(sha256Bytes(enc.encode(payloadStr)))}));
  const pemLines = b64.match(/.{1,64}/g).join('\n');
  const pem = `-----BEGIN CERTIFICATE-----\n${pemLines}\n-----END CERTIFICATE-----`;
  const cert = { payload: payloadStr, signature: toHex(sha256Bytes(enc.encode(payloadStr))), pem };
  LOCAL_STATE.victim = { domain, key, cert, deployed: false };
  LOCAL_STATE.captured = [];
  LOCAL_STATE.clone_live = false;
  jsAddLog(`CA issued ${honest ? 'HONEST CSPRNG' : 'SETUP BACKDOORED'} X.509v3 certificate for ${domain} (Serial ${serial.slice(0,11)}...).`);
  return cert;
}

/* ============================================================================
   UI CONTROLLER & API BRIDGE
   ============================================================================ */
async function detectBackend() {
  try {
    const r = await fetch('/api/log', { method: 'GET' });
    if (r.ok) {
      USE_LOCAL_PYTHON = true;
      document.getElementById('engine_label').textContent = 'Engine: Local Python Server (:8000)';
      return;
    }
  } catch (e) {}
  USE_LOCAL_PYTHON = false;
  document.getElementById('engine_label').textContent = 'Engine: Netlify Browser Crypto (1024-bit RSA)';
}
detectBackend();

function val(id) { return document.getElementById(id).value; }

function showTab(id, btn) {
  document.querySelectorAll('.tab-pane').forEach(c => c.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  if (id === 'log') refreshLog();
}

function updateHUD(stateSnapshot) {
  const v = stateSnapshot.victim;
  if (v) {
    const p = JSON.parse(v.cert.payload);
    document.getElementById('hud_ca_badge').className = p.backdoor ? 'badge badge-red' : 'badge badge-green';
    document.getElementById('hud_ca_badge').textContent = p.backdoor ? 'BACKDOORED' : 'HONEST';
    document.getElementById('hud_ca_meta').textContent = `CN=${p.domain}`;
    document.getElementById('hud_srv_domain').textContent = `https://${p.domain}`;
    document.getElementById('browser_url').textContent = `https://${p.domain}/auth/login`;
    if (v.deployed) {
      document.getElementById('hud_srv_badge').className = 'badge badge-green';
      document.getElementById('hud_srv_badge').textContent = 'LIVE :443';
      document.getElementById('hud_srv_meta').textContent = `FP: ${p.fingerprint.slice(0,14)}...`;
      document.getElementById('hud_srv').className = 'node active-ok';
    }
  }
  const mitm = stateSnapshot.mitm;
  const clone = stateSnapshot.clone_live;
  document.getElementById('hud_mitm_badge').className = mitm ? 'badge badge-red' : 'badge badge-green';
  document.getElementById('hud_mitm_badge').textContent = mitm ? 'HIJACKED' : 'DIRECT';
  document.getElementById('hud_mitm_main').textContent = mitm ? 'BGP/ARP Active MITM Proxy' : 'Clean TLS 1.3 Routing';
  document.getElementById('hud_mitm_meta').textContent = `Clone Ready: ${clone ? 'YES' : 'NO'}`;
  document.getElementById('hud_mitm').className = mitm ? 'node active-danger' : 'node';
  document.getElementById('route_indicator').textContent = (mitm && clone) ? '⚠️ Routed via MITM Clone' : '✓ Direct Route';
  document.getElementById('route_indicator').style.color = (mitm && clone) ? '#fca5a5' : '#6ee7b7';
  document.getElementById('hud_att_meta').textContent = `Captures: ${stateSnapshot.captured.length} packets`;
}

async function handleKeygen(honest) {
  const domain = val('domain') || 'victim-site.com';
  const master = val('master') || '';
  document.getElementById('ca_out').textContent = 'Generating 1024-bit RSA primes (p, q) via 24-round Miller-Rabin primality test...';
  await new Promise(r => setTimeout(r, 30));

  let cert;
  if (USE_LOCAL_PYTHON) {
    const r = await fetch('/api/ca/keygen', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({domain, master, honest})
    });
    const d = await r.json();
    cert = d.cert;
  } else {
    cert = jsIssueCert(domain, master, honest);
  }
  const p = JSON.parse(cert.payload);
  LOCAL_STATE.victim = { domain, cert, deployed: false, key: LOCAL_STATE.victim ? LOCAL_STATE.victim.key : null };
  updateHUD(LOCAL_STATE);

  document.getElementById('ca_metrics').innerHTML = `
    <div class="kv-grid">
      <div class="kv-key">Certificate Serial</div><div class="kv-val">${p.serialNumber}</div>
      <div class="kv-key">Subject CN</div><div class="kv-val">${p.subject}</div>
      <div class="kv-key">SHA-256 Thumbprint</div><div class="kv-val">${p.fingerprint}</div>
      <div class="kv-key">Modulus Entropy</div><div class="kv-val">${p.entropy} bits/byte (Passes NIST SP 800-22)</div>
      <div class="kv-key">X.509 Ext Nonce</div><div class="kv-val" style="color:${p.backdoor?'#fca5a5':'#6ee7b7'}">${p.nonce || '(None - Honest CSPRNG)'}</div>
    </div>`;
  document.getElementById('ca_out').textContent = `${cert.pem}\n\n[Parsed X.509 v3 Structure]\n` + JSON.stringify(p, null, 2);
}

async function handleDeploy() {
  if (USE_LOCAL_PYTHON) {
    const r = await fetch('/api/victim/deploy', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
    const d = await r.json();
    document.getElementById('victim_out').textContent = d.text;
    if (LOCAL_STATE.victim) LOCAL_STATE.victim.deployed = true;
  } else {
    if (!LOCAL_STATE.victim) {
      document.getElementById('victim_out').textContent = 'Error: Issue an X.509 certificate in Tab 1 first.';
      return;
    }
    LOCAL_STATE.victim.deployed = true;
    const p = JSON.parse(LOCAL_STATE.victim.cert.payload);
    jsAddLog(`Victim deployed https://${p.domain} on Nginx 1.26.2 (TLS 1.3).`);
    document.getElementById('victim_out').textContent =
      `root@prod-web-01:~# openssl rsa -in /etc/nginx/ssl/${p.domain}.key -check -noout\nRSA key ok\n` +
      `root@prod-web-01:~# nginx -t && systemctl reload nginx\n` +
      `nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n` +
      `nginx: configuration file /etc/nginx/nginx.conf test is successful\n\n` +
      `[LIVE ENDPOINT] https://${p.domain}:443\n` +
      `[THUMBPRINT]    ${p.fingerprint}\n` +
      `[MODULUS BITS]  1024-bit RSA (e = 0x10001)\n` +
      `[ADMIN VERDICT] Key appears 100% genuine. Zero syntactic indicators of SETUP trapdoor.`;
  }
  updateHUD(LOCAL_STATE);
}

async function handleMitm(on) {
  LOCAL_STATE.mitm = on;
  if (USE_LOCAL_PYTHON) {
    const r = await fetch('/api/mitm', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({on})});
    const d = await r.json();
    document.getElementById('user_out').textContent = d.text;
  } else {
    jsAddLog(`Network BGP/ARP MITM Interceptor ${on ? 'ENABLED' : 'DISABLED'}.`);
    document.getElementById('user_out').textContent = `[NETWORK ROUTE CHANGE]\nActive MITM Redirection is now ${on ? 'ENABLED' : 'DISABLED'}.`;
  }
  updateHUD(LOCAL_STATE);
}

async function handleClone() {
  if (USE_LOCAL_PYTHON) {
    const r = await fetch('/api/attacker/clone', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
    const d = await r.json();
    document.getElementById('attacker_out').textContent = d.text;
    LOCAL_STATE.clone_live = true;
  } else {
    if (!LOCAL_STATE.victim) {
      document.getElementById('attacker_out').textContent = 'Issue & deploy victim server first.';
      return;
    }
    LOCAL_STATE.clone_live = true;
    jsAddLog('Attacker spun up cloned Nginx reverse proxy with victim X.509 certificate.');
    document.getElementById('attacker_out').textContent =
      `[+] Cloned https://${LOCAL_STATE.victim.domain} mirror online.\n` +
      `[+] Presenting identical X.509 Certificate (Thumbprint match: 100%).\n` +
      `[+] Enable MITM in Tab 3 and submit secrets from the Victim Browser.`;
  }
  updateHUD(LOCAL_STATE);
}

async function handleVisit() {
  if (USE_LOCAL_PYTHON) {
    const r = await fetch('/api/user/request', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
    const d = await r.json();
    document.getElementById('user_out').textContent = d.text;
  } else {
    if (!LOCAL_STATE.victim || !LOCAL_STATE.victim.deployed) {
      document.getElementById('user_out').textContent = 'TLS Error: Victim server is not deployed on :443 yet (see Tab 2).';
      return;
    }
    const p = JSON.parse(LOCAL_STATE.victim.cert.payload);
    const intercepted = LOCAL_STATE.mitm && LOCAL_STATE.clone_live;
    jsAddLog(intercepted ? 'Client HTTPS GET intercepted by MITM clone.' : 'Client HTTPS GET served by legitimate victim host.');
    document.getElementById('user_out').textContent =
      `[TLS 1.3 HANDSHAKE COMPLETE]\n` +
      `Connected Endpoint : ${intercepted ? '⚠️ Attacker MITM Clone Node' : '✓ Legitimate Victim Server'}\n` +
      `Cipher Suite       : TLS_RSA_WITH_AES_256_GCM_SHA384\n` +
      `Server Certificate : CN=${p.domain}\n` +
      `SHA-256 Thumbprint : ${p.fingerprint}\n` +
      `X.509 Auth Nonce   : ${p.nonce || '(none)'}\n` +
      `Browser TrustCheck : VALID (Padlock Green — No Certificate Warning!)`;
  }
}

function inspectPadlock() {
  if (!LOCAL_STATE.victim) {
    document.getElementById('user_out').textContent = 'No certificate loaded in browser yet.';
    return;
  }
  const p = JSON.parse(LOCAL_STATE.victim.cert.payload);
  document.getElementById('user_out').textContent =
    `[BROWSER PADLOCK CERTIFICATE VIEWER]\n` +
    `Issued To   : ${p.subject}\n` +
    `Issued By   : ${p.issuer}\n` +
    `Validity    : ${p.validity.notBefore} -> ${p.validity.notAfter}\n` +
    `Thumbprint  : ${p.fingerprint}\n` +
    `Public Key  : RSA 1024-bit (Modulus N = ${p.n_hex.slice(0,48)}...)\n\n` +
    `Why Browser Trusts It: Signed by trusted Root CA. Even if MITM is active, the attacker uses this exact certificate!`;
}

async function handleSendSecret() {
  const secret = val('secret');
  if (USE_LOCAL_PYTHON) {
    const r = await fetch('/api/user/send', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({secret})});
    const d = await r.json();
    document.getElementById('user_out').textContent = d.text;
    if (d.ciphertext) {
      LOCAL_STATE.captured.push({ct: d.ciphertext, route: d.route});
      renderPackets();
    }
  } else {
    if (!LOCAL_STATE.victim) {
      document.getElementById('user_out').textContent = 'No server certificate available.';
      return;
    }
    const data = enc.encode(secret);
    if (data.length > 110) {
      document.getElementById('user_out').textContent = 'Secret too long for 1024-bit RSA block (max 110 bytes).';
      return;
    }
    const padLen = 128 - data.length - 3;
    const pad = crypto.getRandomValues(new Uint8Array(padLen));
    for (let i = 0; i < pad.length; i++) if (pad[i] === 0) pad[i] = 1;
    const block = new Uint8Array(128);
    block[0] = 0; block[1] = 2;
    block.set(pad, 2);
    block[2 + padLen] = 0;
    block.set(data, 3 + padLen);
    let m = 0n;
    for (const b of block) m = (m << 8n) | BigInt(b);
    const k = LOCAL_STATE.victim.key;
    const ct = modPow(m, BigInt(k.e), k.n);
    const route = (LOCAL_STATE.mitm && LOCAL_STATE.clone_live) ? 'MITM Clone' : 'Victim Server';
    LOCAL_STATE.captured.push({ ct: ct.toString(), route });
    jsAddLog(`Encrypted payload transmitted via ${route} (${ct.toString(16).length * 4} bits).`);
    renderPackets();
    document.getElementById('user_out').textContent =
      `[PKCS#1 v1.5 ENCRYPTED TLS RECORD TRANSMITTED]\n` +
      `Destination Route : ${route}\n` +
      `RSA Ciphertext (Hex):\n${ct.toString(16).toUpperCase()}\n\n` +
      `RSA Ciphertext (Decimal):\n${ct.toString()}`;
  }
  updateHUD(LOCAL_STATE);
}

function renderPackets() {
  const tb = document.getElementById('packet_tbody');
  if (!LOCAL_STATE.captured.length) return;
  tb.innerHTML = LOCAL_STATE.captured.map((item, idx) => {
    const hexStr = BigInt(item.ct).toString(16).toUpperCase();
    return `<tr>
      <td>#${idx+1}</td>
      <td>TLS_RSA_AES256</td>
      <td><span class="badge ${item.route.includes('MITM')?'badge-red':'badge-blue'}">${item.route}</span></td>
      <td>0x${hexStr.slice(0, 36)}...</td>
    </tr>`;
  }).join('');
}

async function handleRecover() {
  const master = val('rmaster');
  document.getElementById('attacker_out').textContent = 'Running deterministic HMAC-SHA256 DRNG stream to reconstruct primes p and q...';
  await new Promise(r => setTimeout(r, 30));

  if (USE_LOCAL_PYTHON) {
    const r = await fetch('/api/attacker/recover', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({master})});
    const d = await r.json();
    document.getElementById('attacker_out').textContent = d.text;
  } else {
    if (!LOCAL_STATE.victim) {
      document.getElementById('attacker_out').textContent = 'No victim certificate captured yet.';
      return;
    }
    const pObj = JSON.parse(LOCAL_STATE.victim.cert.payload);
    if (!pObj.nonce) {
      document.getElementById('attacker_out').textContent =
        `[-] RECOVERY ABORTED: Certificate uses an Honest CSPRNG key.\n` +
        `[-] Without the SETUP nonce trapdoor, factoring a random RSA modulus is computationally infeasible.`;
      return;
    }
    const mk = sha256Bytes(enc.encode(master));
    const domBytes = enc.encode(LOCAL_STATE.victim.domain);
    const nonceBytes = fromHex(pObj.nonce);
    const combined = new Uint8Array(domBytes.length + nonceBytes.length);
    combined.set(domBytes); combined.set(nonceBytes, domBytes.length);
    const seed = hmac256Bytes(mk, combined);
    const rng = jsDrng(seed);
    const p = jsGenPrime(rng, 512);
    const q = jsGenPrime(rng, 512);
    const rk = jsRsaFromPrimes(p, q);

    if (!rk || rk.n.toString() !== pObj.n) {
      document.getElementById('attacker_out').textContent =
        `[!] RECOVERY FAILED: Reconstructed modulus N' != Public N.\n` +
        `[!] Cause: Master passphrase does not match the Evil CA passphrase.`;
      return;
    }
    let out = [
      `[+] KLEPTOGRAPHIC SETUP RECOVERY SUCCEEDED!`,
      `====================================================================`,
      `1. Extracted X.509 Extension Nonce : ${pObj.nonce}`,
      `2. Derived HMAC-SHA256 DRNG Seed   : ${toHex(seed)}`,
      `3. Regenerated Prime p (512-bit)   : ${p.toString().slice(0,44)}...`,
      `4. Regenerated Prime q (512-bit)   : ${q.toString().slice(0,44)}...`,
      `5. Verified p * q == Public N      : MATCH CONFIRMED (1024-bit)`,
      `6. Computed Private Exponent d     :\n   ${rk.d.toString()}`,
      `====================================================================`
    ];
    if (LOCAL_STATE.captured.length) {
      out.push(`\n[DECRYPTED TLS INTERCEPTS]`);
      LOCAL_STATE.captured.forEach((item, i) => {
        const m = modPow(BigInt(item.ct), rk.d, rk.n);
        let hex = m.toString(16);
        if (hex.length % 2) hex = '0' + hex;
        const bytes = fromHex(hex);
        let idx = 2;
        while (idx < bytes.length && bytes[idx] !== 0) idx++;
        const plain = dec.decode(bytes.slice(idx + 1));
        out.push(`Packet #${i+1} (${item.route}): ${plain}`);
      });
    } else {
      out.push(`\n[i] No encrypted packets captured yet. Submit a secret in Tab 3!`);
    }
    jsAddLog('Attacker reconstructed victim private key d from public certificate nonce.');
    document.getElementById('attacker_out').textContent = out.join('\n');
  }
}

async function refreshLog() {
  if (USE_LOCAL_PYTHON) {
    const r = await fetch('/api/log');
    const d = await r.json();
    document.getElementById('log_out').textContent = d.log.join('\n') || 'No activity yet.';
  } else {
    document.getElementById('log_out').textContent = LOCAL_STATE.log.join('\n') || 'No activity yet.';
  }
}
</script>
</body>
</html>"""


NETLIFY_TOML = """[build]
  publish = "."

[[headers]]
  for = "/*"
  [headers.values]
    X-Frame-Options = "DENY"
    X-Content-Type-Options = "nosniff"
"""


def build_netlify_bundle(out_dir="netlify_deploy"):
    os.makedirs(out_dir, exist_ok=True)
    index_path = os.path.join(out_dir, "index.html")
    toml_path = os.path.join(out_dir, "netlify.toml")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(PAGE)
    with open(toml_path, "w", encoding="utf-8") as f:
        f.write(NETLIFY_TOML)
    return os.path.abspath(out_dir)


class H(BaseHTTPRequestHandler):
    def js(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if urlparse(self.path).path == "/":
            b = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif self.path == "/api/log":
            self.js({"log": STATE["log"]})
        else:
            self.js({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self.js({"error": "bad json"}, 400)
            return
        p = urlparse(self.path).path
        if p == "/api/ca/keygen":
            cert = issue_cert(d.get("domain", "victim-site.com"), d.get("master", ""), d.get("honest", False))
            self.js({"cert": cert, "refresh_log": True})
        elif p == "/api/victim/deploy":
            if not STATE["victim"]:
                self.js({"text": "Error: Issue an X.509 certificate in Tab 1 first."})
                return
            STATE["victim"]["deployed"] = True
            v = STATE["victim"]
            p_obj = json.loads(v["cert"]["payload"])
            log(f"Victim deployed https://{v['domain']} on Nginx 1.26.2 (TLS 1.3).")
            text = (
                f"root@prod-web-01:~# openssl rsa -in /etc/nginx/ssl/{v['domain']}.key -check -noout\nRSA key ok\n"
                f"root@prod-web-01:~# nginx -t && systemctl reload nginx\n"
                f"nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
                f"nginx: configuration file /etc/nginx/nginx.conf test is successful\n\n"
                f"[LIVE ENDPOINT] https://{v['domain']}:443\n"
                f"[THUMBPRINT]    {p_obj['fingerprint']}\n"
                f"[MODULUS BITS]  {v['key']['n'].bit_length()}-bit RSA (e = 0x10001)\n"
                f"[ADMIN VERDICT] Key appears 100% genuine. Zero syntactic indicators of SETUP trapdoor."
            )
            self.js({"text": text, "refresh_log": True})
        elif p == "/api/mitm":
            STATE["mitm"] = bool(d.get("on"))
            log(f"Network BGP/ARP MITM Interceptor {'ENABLED' if STATE['mitm'] else 'DISABLED'}.")
            self.js({"text": f"[NETWORK ROUTE CHANGE]\nActive MITM Redirection is now {'ENABLED' if STATE['mitm'] else 'DISABLED'}.", "refresh_log": True})
        elif p == "/api/attacker/clone":
            if not STATE["victim"]:
                self.js({"text": "Issue & deploy victim server first."})
                return
            STATE["clone_live"] = True
            log("Attacker spun up cloned Nginx reverse proxy with victim X.509 certificate.")
            self.js({
                "text": (
                    f"[+] Cloned https://{STATE['victim']['domain']} mirror online.\n"
                    f"[+] Presenting identical X.509 Certificate (Thumbprint match: 100%).\n"
                    f"[+] Enable MITM in Tab 3 and submit secrets from the Victim Browser."
                ),
                "refresh_log": True
            })
        elif p == "/api/user/request":
            if not STATE["victim"] or not STATE["victim"]["deployed"]:
                self.js({"text": "TLS Error: Victim server is not deployed on :443 yet (see Tab 2)."})
                return
            v = STATE["victim"]
            p_obj = json.loads(v["cert"]["payload"])
            intercepted = STATE["mitm"] and STATE["clone_live"]
            log("Client HTTPS GET intercepted by MITM clone." if intercepted else "Client HTTPS GET served by legitimate victim host.")
            self.js({
                "text": (
                    f"[TLS 1.3 HANDSHAKE COMPLETE]\n"
                    f"Connected Endpoint : {'⚠️ Attacker MITM Clone Node' if intercepted else '✓ Legitimate Victim Server'}\n"
                    f"Cipher Suite       : TLS_RSA_WITH_AES_256_GCM_SHA384\n"
                    f"Server Certificate : CN={v['domain']}\n"
                    f"SHA-256 Thumbprint : {p_obj['fingerprint']}\n"
                    f"X.509 Auth Nonce   : {p_obj['nonce'] or '(none)'}\n"
                    f"Browser TrustCheck : VALID (Padlock Green — No Certificate Warning!)"
                ),
                "refresh_log": True
            })
        elif p == "/api/user/send":
            if not STATE["victim"]:
                self.js({"text": "No server certificate available."})
                return
            v = STATE["victim"]
            try:
                ct = encrypt(v["key"], d.get("secret", ""))
            except ValueError as e:
                self.js({"text": str(e)})
                return
            where = "MITM Clone" if STATE["mitm"] and STATE["clone_live"] else "Victim Server"
            STATE["captured"].append({"ct": ct, "route": where})
            log(f"Encrypted payload transmitted via {where} ({ct.bit_length()} bits).")
            self.js({
                "text": (
                    f"[PKCS#1 v1.5 ENCRYPTED TLS RECORD TRANSMITTED]\n"
                    f"Destination Route : {where}\n"
                    f"RSA Ciphertext (Hex):\n{hex(ct)[2:].upper()}\n\n"
                    f"RSA Ciphertext (Decimal):\n{ct}"
                ),
                "ciphertext": str(ct),
                "route": where,
                "refresh_log": True
            })
        elif p == "/api/attacker/recover":
            if not STATE["victim"]:
                self.js({"text": "No victim certificate captured yet."})
                return
            v = STATE["victim"]
            cd = json.loads(v["cert"]["payload"])
            nonce = cd.get("nonce", "")
            if not nonce:
                self.js({
                    "text": (
                        "[-] RECOVERY ABORTED: Certificate uses an Honest CSPRNG key.\n"
                        "[-] Without the SETUP nonce trapdoor, factoring a random RSA modulus is computationally infeasible."
                    )
                })
                return
            rk = recover_key(v["domain"], d.get("master", ""), nonce)
            if not rk or rk["n"] != v["key"]["n"]:
                self.js({
                    "text": (
                        "[!] RECOVERY FAILED: Reconstructed modulus N' != Public N.\n"
                        "[!] Cause: Master passphrase does not match the Evil CA passphrase."
                    )
                })
                return
            seed_hex = hmac256(sha256(d.get("master", "").encode()), v["domain"].encode() + bytes.fromhex(nonce)).hex()
            lines = [
                "[+] KLEPTOGRAPHIC SETUP RECOVERY SUCCEEDED!",
                "====================================================================",
                f"1. Extracted X.509 Extension Nonce : {nonce}",
                f"2. Derived HMAC-SHA256 DRNG Seed   : {seed_hex}",
                f"3. Regenerated Prime p (512-bit)   : {str(rk['p'])[:44]}...",
                f"4. Regenerated Prime q (512-bit)   : {str(rk['q'])[:44]}...",
                "5. Verified p * q == Public N      : MATCH CONFIRMED (1024-bit)",
                f"6. Computed Private Exponent d     :\n   {rk['d']}",
                "===================================================================="
            ]
            if STATE["captured"]:
                lines.append("\n[DECRYPTED TLS INTERCEPTS]")
                for i, item in enumerate(STATE["captured"], 1):
                    lines.append(f"Packet #{i} ({item['route']}): {decrypt(rk, item['ct'])}")
            else:
                lines.append("\n[i] No encrypted packets captured yet. Submit a secret in Tab 3!")
            log("Attacker reconstructed victim private key d from public certificate nonce.")
            self.js({"text": "\n".join(lines), "refresh_log": True})
        else:
            self.js({"error": "not found"}, 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    bundle_dir = build_netlify_bundle("netlify_deploy")
    print(f"[+] Netlify static bundle generated at: {bundle_dir}")
    if "--build-only" in sys.argv:
        sys.exit(0)
    print(f"[+] Local Kleptography Cyber-Range running at: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()