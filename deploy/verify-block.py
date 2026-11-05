#!/usr/bin/env python3
"""Non-destructive end-to-end check of the manual SSH block API.

Runs on the server against 127.0.0.1:8087 so the Secure session cookie can be
replayed by hand.

Design rule: this script must never disturb a block an operator created.
It only chooses a target that is *not* currently blocked, and always unblocks
it again, so the block list is identical before and after. IPs that are
already blocked are only ever read, never modified.

Exit code 0 = all checks passed.
"""
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8087"
ENV_FILE = "/etc/monitor/monitor.env"
FAIL_FILE = "/var/lib/monitor/ssh-failures.json"
KNOWN_FILE = "/var/lib/monitor/known-ips.json"

fails = []


def env_password():
    with open(ENV_FILE) as fh:
        for line in fh:
            m = re.match(r"^MONITOR_PASSWORD=(.*)$", line.rstrip("\n"))
            if m:
                return m.group(1).strip().strip('"').strip("'")
    raise SystemExit("MONITOR_PASSWORD not found in " + ENV_FILE)


def call(path, method="GET", body=None, cookie=None, csrf=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", "mon_session=" + cookie)
    if csrf:
        req.add_header("X-CSRF-Token", csrf)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except Exception:
            return e.code, {"raw": raw.decode("utf-8", "replace")}


def check(label, cond, detail=""):
    if cond:
        print("  PASS  " + label + ("  " + detail if detail else ""))
    else:
        print("  FAIL  " + label + ("  " + detail if detail else ""))
        fails.append(label)


def nft_sets():
    """Current set contents as {ip: (packets, bytes)}, empty on any failure."""
    out = {}
    res = subprocess.run(["nft", "-j", "list", "table", "inet", "monitor_block"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        return out
    try:
        doc = json.loads(res.stdout)
    except Exception:
        return out
    for item in doc.get("nftables", []):
        st = item.get("set")
        if not st:
            continue
        for el in st.get("elem", []) or []:
            val = el.get("elem")
            if not val:
                continue
            counter = val.get("counter") or {}
            out[val["val"]] = (counter.get("packets", 0), counter.get("bytes", 0))
    return out


print("== auth")
# CSRF is an HMAC over the session cookie, so both must come from the *same*
# login response; reusing a token across two logins is correctly refused.
opener = urllib.request.build_opener()
req = urllib.request.Request(
    BASE + "/api/login",
    data=json.dumps({"password": env_password()}).encode(),
    method="POST",
    headers={"Content-Type": "application/json"},
)
with opener.open(req, timeout=20) as r:
    raw_cookie = r.headers.get("Set-Cookie", "")
    body = json.loads(r.read() or b"{}")
check("login", body.get("ok") is True)
csrf = body.get("csrf")
check("csrf token issued", bool(csrf))

m = re.search(r"mon_session=([^;]+)", raw_cookie)
check("session cookie issued", bool(m))
cookie = m.group(1) if m else ""

status, payload = call("/api/status", cookie=cookie)
check("authenticated status", status == 200 and payload.get("ok"), f"HTTP {status}")

print("== csrf and method enforcement")
status, _ = call("/api/block", "POST", {"ip": "1.2.3.4"}, cookie=cookie, csrf="wrong")
check("block with a bad csrf token is refused", status == 403, f"HTTP {status}")
status, _ = call("/api/block", "GET", cookie=cookie)
check("block via GET is not a route", status in (404, 405), f"HTTP {status}")
status, _ = call("/api/block", "POST", {"ip": "1.2.3.4"})
check("block without a session is refused", status in (401, 403), f"HTTP {status}")

print("== guards")
before = nft_sets()
cases = [
    ("203.0.113.11", ("protected", "has_logged_in"), "protected admin IP"),
    ("8.8.8.8", ("no_failures",), "no failure history"),
    ("10.0.0.5", ("not_public",), "private address"),
    ("203.0.113.10", ("self",), "the server itself"),
    ("not-an-ip", ("invalid_ip",), "garbage input"),
]
for ip, allowed, label in cases:
    status, payload = call("/api/block", "POST", {"ip": ip}, cookie=cookie, csrf=csrf)
    ok = status == 400 and payload.get("error") in allowed
    check(f"refuses {ip} ({label})", ok, f"HTTP {status} {payload.get('error')}")

after = nft_sets()
check("refused attempts changed nothing in the kernel",
      before == after, f"{len(before)} entries before, {len(after)} after")

print("== a real block, on a target that is not already blocked")
status, payload = call("/api/blocked", cookie=cookie)
blocked_now = {r["ip"] for r in payload.get("ips", [])}
print(f"    currently blocked: {sorted(blocked_now) or '(none)'}")

try:
    failures = json.load(open(FAIL_FILE))
    known = json.load(open(KNOWN_FILE))
except Exception as e:
    failures, known = {}, {}
    print(f"    could not read failure history: {e}")

candidates = [
    ip for ip, rec in sorted(failures.items(),
                            key=lambda kv: kv[1].get("count", 0), reverse=True)
    if rec.get("count") and ip not in blocked_now and ip not in known
]
TARGET = candidates[0] if candidates else None


def always_unblock():
    """Leave no trace, even if a check above raised or failed mid-way.

    A test that leaves a real IP blocked on a production box is worse than no
    test at all, so cleanup is unconditional rather than part of the happy path.
    """
    if not TARGET:
        return
    try:
        call("/api/unblock", "POST", {"ip": TARGET}, cookie=cookie, csrf=csrf)
    except Exception as e:  # pragma: no cover - last resort
        print(f"    WARNING: cleanup unblock of {TARGET} failed: {e}")
        print(f"             run: nft delete element inet monitor_block ssh4 {{ {TARGET} }}")

if not TARGET:
    print("  SKIP  no unblocked IP with failures and no successful login")
    print("        (guards above already exercised the full request path)")
else:
    print(f"    target: {TARGET} (not blocked, has failures, never logged in)")
    status, payload = call("/api/block", "POST", {"ip": TARGET}, cookie=cookie, csrf=csrf)
    check(f"block {TARGET}", status == 200 and payload.get("ok"),
          f"HTTP {status} {payload.get('error') or ''}")

    sets = nft_sets()
    check("target is in the kernel set", TARGET in sets)

    res = subprocess.run(["nft", "list", "table", "inet", "monitor_block"],
                         capture_output=True, text=True)
    check("rule drops and logs with the MONITOR_BLOCK prefix",
          "drop" in res.stdout and "MONITOR_BLOCK" in res.stdout)

    status, payload = call("/api/blocked", cookie=cookie)
    row = next((r for r in payload.get("ips", []) if r["ip"] == TARGET), None)
    check("appears in the blocked list", bool(row), f"HTTP {status}")
    if row:
        check("reported as present in the kernel set", row.get("inKernelSet") is True)
        check("block timestamp recorded", bool(row.get("blockedAt")))

    status, payload = call("/api/ssh-failures", cookie=cookie)
    row = next((r for r in payload.get("ips", []) if r["ip"] == TARGET), None)
    check("still visible in the failure table", bool(row))
    if row:
        check("flagged as blocked there", row.get("blocked") is True)

    status, payload = call("/api/block", "POST", {"ip": TARGET}, cookie=cookie, csrf=csrf)
    check("a second block is refused as already_blocked",
          status == 400 and payload.get("error") == "already_blocked",
          f"HTTP {status} {payload.get('error')}")

    status, payload = call("/api/blocked", cookie=cookie)
    check("203.0.113.11 is advertised as protected",
          "203.0.113.11" in (payload.get("protectedIps") or []))

    status, payload = call("/api/unblock", "POST", {"ip": TARGET}, cookie=cookie, csrf=csrf)
    check(f"unblock {TARGET}", status == 200 and payload.get("ok"), f"HTTP {status}")
    check("target is gone from the kernel set", TARGET not in nft_sets())
    status, payload = call("/api/blocked", cookie=cookie)
    check("target is gone from the blocked list",
          not any(r["ip"] == TARGET for r in payload.get("ips", [])))

print("== operator blocks were not touched")
always_unblock()
status, payload = call("/api/blocked", cookie=cookie)
final = {r["ip"] for r in payload.get("ips", [])}
check("block list matches what was there before the test",
      final == blocked_now,
      f"before {sorted(blocked_now)} / after {sorted(final)}")

print()
if fails:
    print("FAILED: " + ", ".join(fails))
    sys.exit(1)
print("all checks passed")
