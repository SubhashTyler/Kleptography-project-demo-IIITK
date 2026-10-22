#!/usr/bin/env python3
"""Kleptography: Breaking Trust in Cryptography - interactive local GUI demo."""
import base64, hashlib, hmac, json, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST, PORT = "127.0.0.1", 8000
RSA_BITS = 1024
E = 65537

STATE = {"victim": None, "clone_live": False, "mitm": False,
         "captured": [], "log": []}

def sha256(b): return hashlib.sha256(b).digest()
def hmac256(k, d): return hmac.new(k, d, hashlib.sha256).digest()

def drng(seed):
    c = 0
    while True:
        block = hashlib.sha256(seed + c.to_bytes(8, "big")).digest()
        c += 1
        for b in block: yield b

def is_prime(n, rng):
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29,31,37]:
        if n % p == 0: return n == p
    d, r = n - 1, 0
    while d % 2 == 0: d //= 2; r += 1
    for _ in range(24):
        a = 2 + ((next(rng) << 8) | next(rng)) % (n - 4)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def gen_prime(rng, bits):
    while True:
        cand = 0; rem = bits
        while rem > 0:
            cand = (cand << 8) | next(rng); rem -= 8
        cand |= (1 << (bits - 1)) | 1
        if is_prime(cand, rng): return cand

def rsa_from_primes(p, q):
    n = p * q; phi = (p - 1) * (q - 1)
    if phi % E == 0: return None
    return {"n": n, "e": E, "d": pow(E, -1, phi), "p": p, "q": q}

def honest_keygen(bits=RSA_BITS):
    while True:
        p = gen_prime(drng(secrets.token_bytes(32)), bits // 2)
        q = gen_prime(drng(secrets.token_bytes(32)), bits // 2)
        if p != q:
            k = rsa_from_primes(p, q)
            if k: return k

def backdoored_keygen(domain, master, bits=RSA_BITS):
    mk = sha256(master.encode()); nonce = secrets.token_bytes(16)
    while True:
        seed = hmac256(mk, domain.encode() + nonce)
        rng = drng(seed)
        p = gen_prime(rng, bits // 2); q = gen_prime(rng, bits // 2)
        if p == q:
            nonce = secrets.token_bytes(16); continue
        k = rsa_from_primes(p, q)
        if k:
            k["nonce"] = nonce.hex(); return k

def recover_key(domain, master, nonce_hex):
    mk = sha256(master.encode())
    seed = hmac256(mk, domain.encode() + bytes.fromhex(nonce_hex))
    rng = drng(seed)
    p = gen_prime(rng, RSA_BITS // 2); q = gen_prime(rng, RSA_BITS // 2)
    k = rsa_from_primes(p, q)
    if k: k["nonce"] = nonce_hex
    return k

def sign(key, msg): return pow(int.from_bytes(sha256(msg), "big"), key["d"], key["n"])
def verify(key, msg, sig): return pow(sig, key["e"], key["n"]) == int.from_bytes(sha256(msg), "big")

def encrypt(key, text):
    data = text.encode()
    if len(data) > RSA_BITS // 8 - 11:
        raise ValueError("Secret too long for demo RSA key (max ~100 chars).")
    padded = b"\x00" + data + b"\x00" + secrets.token_bytes(RSA_BITS // 8 - len(data) - 2)
    return pow(int.from_bytes(padded, "big"), key["e"], key["n"])

def decrypt(key, ct):
    m = pow(ct, key["d"], key["n"])
    padded = m.to_bytes(RSA_BITS // 8, "big")
    parts = padded.split(b"\x00", 1)
    return parts[1].split(b"\x00", 1)[0].decode(errors="replace") if len(parts) > 1 else ""

def fingerprint(n): return sha256(str(n).encode()).hex()[:32]
def log(m): STATE["log"].insert(0, m); STATE["log"] = STATE["log"][:80]

def issue_cert(domain, master, honest):
    if honest:
        key = honest_keygen(); nonce = ""; bd = False
    else:
        key = backdoored_keygen(domain, master); nonce = key["nonce"]; bd = True
    ca = honest_keygen()
    payload = json.dumps({"domain": domain, "n": str(key["n"]), "e": key["e"],
                          "nonce": nonce, "backdoor": bd}, sort_keys=True).encode()
    cert = {"payload": payload.decode(), "signature": sign(ca, payload)}
    STATE["victim"] = {"domain": domain, "key": key, "cert": cert, "deployed": False}
    STATE["captured"] = []; STATE["clone_live"] = False
    log(f"Evil CA issued {'honest' if honest else 'BACKDOORED'} certificate for {domain}.")
    return cert

PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>Kleptography: Breaking Trust in Cryptography</title><style>
body{font-family:Arial;background:#0e1420;color:#e8edf5;margin:0}
header{background:#111a2b;padding:18px 24px;border-bottom:1px solid #23324a}
h1{margin:0;font-size:22px}.sub{color:#8fa3bf;font-size:14px;margin-top:4px}
main{max-width:1100px;margin:20px auto;padding:0 16px}
.tabs{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
button.tab{background:#1a2537;color:#cfe0f5;border:1px solid #2c3d59;padding:10px 14px;border-radius:8px;cursor:pointer}
button.tab.active{background:#2f6fed;color:#fff}
.card{background:#141d2e;border:1px solid #24344e;border-radius:12px;padding:18px;margin-bottom:16px}
h2{margin-top:0;font-size:18px}
label{display:block;margin:10px 0 4px;font-size:13px;color:#a9bcd6}
input{width:100%;box-sizing:border-box;background:#0d1420;color:#e8edf5;border:1px solid #2c3d59;border-radius:8px;padding:9px}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>div{flex:1;min-width:220px}
.btn{background:#2f6fed;border:none;color:#fff;padding:10px 14px;border-radius:8px;cursor:pointer;margin-top:10px}
.gray{background:#33465f}.red{background:#c0392b}.green{background:#1e8e4f}
pre{background:#0b111c;border:1px solid #24344e;padding:12px;border-radius:8px;overflow:auto;font-size:12px;white-space:pre-wrap}
.small{font-size:12px;color:#8fa3bf}.warn{color:#ffb84d;font-size:13px}
.hidden{display:none}</style></head><body>
<header><h1>Kleptography: Breaking Trust in Cryptography</h1>
<div class=sub>Interactive RSA backdoor + simulated TLS MITM demo (local, educational)</div></header>
<main>
<div class=tabs>
<button class="tab active" onclick="show('ca',this)">1. Evil CA</button>
<button class=tab onclick="show('victim',this)">2. Victim Server</button>
<button class=tab onclick="show('user',this)">3. User Browser</button>
<button class=tab onclick="show('attacker',this)">4. MITM / Attacker</button>
<button class=tab onclick="show('log',this)">Activity Log</button></div>

<div id=ca class=card><h2>Evil Certificate Authority</h2>
<p class=small>Backdoored RSA keys are generated deterministically from the attacker passphrase, domain, and a nonce published in the certificate.</p>
<label>Victim domain</label><input id=domain value="victim-site.com">
<label>Attacker master passphrase</label><input id=master value="attacker-master-secret">
<div class=row><div><button class="btn red" onclick="api('/api/ca/keygen',{domain:val('domain'),master:val('master'),honest:false})">Generate backdoored key + certificate</button></div>
<div><button class="btn gray" onclick="api('/api/ca/keygen',{domain:val('domain'),master:val('master'),honest:true})">Generate honest key for comparison</button></div></div>
<pre id=ca_out>No certificate issued yet.</pre></div>

<div id=victim class="card hidden"><h2>Victim Web Server</h2>
<p class=small>The victim deploys the certificate and key. Nothing visible reveals the backdoor.</p>
<button class="btn green" onclick="api('/api/victim/deploy',{})">Deploy victim-site.com</button>
<pre id=victim_out>No deployment yet.</pre></div>

<div id=user class="card hidden"><h2>User Browser</h2>
<p class=small>Visit the site and submit a secret. With MITM enabled, the clone serves the page.</p>
<div class=row><div><button class=btn onclick="api('/api/user/request',{})">Visit https://victim-site.com</button></div>
<div><button class="btn gray" onclick="api('/api/mitm',{on:true})">Enable MITM</button>
<button class="btn gray" onclick="api('/api/mitm',{on:false})">Disable MITM</button></div></div>
<label>Secret to submit</label><input id=secret value="Bank password: correct-horse-battery">
<button class=btn onclick="api('/api/user/send',{secret:val('secret')})">Submit encrypted secret</button>
<pre id=user_out>No page loaded yet.</pre></div>

<div id=attacker class="card hidden"><h2>MITM / Attacker Recovery</h2>
<p class=small>Clone the site, capture traffic, then recover the private key from the public nonce plus the master passphrase.</p>
<button class="btn gray" onclick="api('/api/attacker/clone',{})">Clone victim-site.com</button>
<label>Master passphrase</label><input id=rmaster value="attacker-master-secret">
<button class="btn red" onclick="api('/api/attacker/recover',{master:val('rmaster')})">Recover victim private key</button>
<pre id=attacker_out>No attacker action yet.</pre></div>

<div id=log class="card hidden"><h2>Activity Log</h2><pre id=log_out>No activity yet.</pre></div>

<div class=card><h2>Security notice</h2>
<p class=warn>Local educational simulation only. No ARP poisoning, real interception, or attacks on third-party systems.</p></div>
</main>
<script>
function val(id){return document.getElementById(id).value}
function show(id,btn){document.querySelectorAll('.card').forEach(c=>c.classList.add('hidden'));
document.getElementById(id).classList.remove('hidden');
document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
if(id==='log')refreshLog()}
async function api(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
const d=await r.json();if(d.target)document.getElementById(d.target).textContent=d.text;if(d.refresh_log)refreshLog()}
async function refreshLog(){const r=await fetch('/api/log');const d=await r.json();
document.getElementById('log_out').textContent=d.log.join('\\n')}
</script></body></html>"""

class H(BaseHTTPRequestHandler):
    def js(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if urlparse(self.path).path == "/":
            b = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
        elif self.path == "/api/log":
            self.js({"log": STATE["log"]})
        else:
            self.js({"error": "not found"}, 404)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try: d = json.loads(self.rfile.read(n) or b"{}")
        except Exception: self.js({"error": "bad json"}, 400); return
        p = urlparse(self.path).path
        if p == "/api/ca/keygen":
            cert = issue_cert(d.get("domain","victim-site.com"), d.get("master",""), d.get("honest", False))
            self.js({"target": "ca_out", "text": "Issued certificate:\n\n" + json.dumps(cert, indent=2), "refresh_log": True})
        elif p == "/api/victim/deploy":
            if not STATE["victim"]: self.js({"target":"victim_out","text":"Issue a certificate first."}); return
            STATE["victim"]["deployed"] = True
            v = STATE["victim"]
            log(f"Victim deployed https://{v['domain']}.")
            self.js({"target":"victim_out","text":f"Deployed https://{v['domain']}\nFingerprint: {fingerprint(v['key']['n'])}\nModulus bits: {v['key']['n'].bit_length()}","refresh_log":True})
        elif p == "/api/mitm":
            STATE["mitm"] = bool(d.get("on"))
            log(f"MITM {'enabled' if STATE['mitm'] else 'disabled'}.")
            self.js({"target":"user_out","text":f"MITM {'ENABLED' if STATE['mitm'] else 'DISABLED'}.","refresh_log":True})
        elif p == "/api/attacker/clone":
            if not STATE["victim"]: self.js({"target":"attacker_out","text":"Deploy victim first."}); return
            STATE["clone_live"] = True
            log("Attacker cloned victim site.")
            self.js({"target":"attacker_out","text":"Clone ready. Enable MITM and revisit the site.","refresh_log":True})
        elif p == "/api/user/request":
            if not STATE["victim"] or not STATE["victim"]["deployed"]:
                self.js({"target":"user_out","text":"Victim site not deployed."}); return
            v = STATE["victim"]
            if STATE["mitm"] and STATE["clone_live"]:
                where = "MITM clone"; page = "Cloned page served by attacker."
                log("User request intercepted by MITM clone.")
            else:
                where = "Victim server"; page = "Legitimate victim page."
                log("User request served by victim.")
            nonce = json.loads(v["cert"]["payload"])["nonce"]
            self.js({"target":"user_out","text":f"Connected to: {where}\nCertificate nonce: {nonce or '(none)'}\n\n{page}","refresh_log":True})
        elif p == "/api/user/send":
            if not STATE["victim"]: self.js({"target":"user_out","text":"No certificate."}); return
            v = STATE["victim"]
            try: ct = encrypt(v["key"], d.get("secret",""))
            except ValueError as e: self.js({"target":"user_out","text":str(e)}); return
            STATE["captured"].append(ct)
            where = "MITM clone" if STATE["mitm"] and STATE["clone_live"] else "Victim server"
            log(f"User secret captured via {where}.")
            self.js({"target":"user_out","text":f"Encrypted and submitted via {where}.\nCiphertext:\n{ct}","refresh_log":True})
        elif p == "/api/attacker/recover":
            if not STATE["victim"]: self.js({"target":"attacker_out","text":"No victim certificate."}); return
            v = STATE["victim"]; cd = json.loads(v["cert"]["payload"]); nonce = cd.get("nonce","")
            if not nonce: self.js({"target":"attacker_out","text":"Honest key: nothing to recover."}); return
            rk = recover_key(v["domain"], d.get("master",""), nonce)
            if not rk or rk["n"] != v["key"]["n"]:
                self.js({"target":"attacker_out","text":"Recovery failed: wrong passphrase."}); return
            lines = ["Private key reconstructed from public certificate data.",
                     f"Recovered d: {rk['d']}"]
            if STATE["captured"]:
                lines.append("\nDecrypted captures:")
                for i, ct in enumerate(STATE["captured"],1):
                    lines.append(f"{i}. {decrypt(rk, ct)}")
            log("Attacker recovered victim private key.")
            self.js({"target":"attacker_out","text":"\n".join(lines),"refresh_log":True})
        else:
            self.js({"error":"not found"},404)
    def log_message(self,*a): pass

if __name__ == "__main__":
    print(f"Kleptography demo running: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
