#!/usr/bin/env python3
"""
req-red proxy — system-wide HTTPS interceptor.
Managed by server.py; can also run standalone.

Rule schema (new):
  { id, name, enabled, priority,
    match: { url: {kind, value}, method?, graphql?: {operationName?, payloadKey?, payloadValue?} },
    action: RedirectAction | BlockAction | MockAction }

RedirectAction : { type:"redirect", to:str }
BlockAction    : { type:"block" }
MockAction     : { type:"mock", status:int, headers:{}, body:str, bodyMode:"static"|"dynamic",
                   script:str, delayMs:int }

Old flat format is migrated transparently on load.
"""

import asyncio
import atexit
import fnmatch
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys

# Force UTF-8 stdout/stderr on Windows so box-drawing characters don't crash cp1252
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
import time
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Optional

PORT_HINT  = 8080
SCRIPT_DIR = Path(__file__).parent
RULES_FILE = SCRIPT_DIR / "rules.json"

# Prevent mitmproxy's own outbound connections from looping back through
# the system proxy it just set (causes 502 on Windows).
os.environ.setdefault("NO_PROXY", "localhost,127.0.0.1")
os.environ.setdefault("no_proxy", "localhost,127.0.0.1")

# ─── dependency bootstrap ─────────────────────────────────────────────────────

def _pip(*pkgs):
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", *pkgs],
                       capture_output=True)
    if r.returncode != 0:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet",
                        "--break-system-packages", *pkgs], check=True)

try:
    from mitmproxy import http
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
except ImportError:
    print("mitmproxy not found — installing…")
    _pip("mitmproxy")
    os.execv(sys.executable, [sys.executable] + sys.argv)

log = logging.getLogger("req-red")
logging.basicConfig(level=logging.INFO, format="%(message)s")

# ─── rule schema migration ────────────────────────────────────────────────────

_KIND_MAP = {
    "equals": "exact", "contains": "contains", "startswith": "startswith",
    "endswith": "endswith", "regex": "regex",
}

def migrate_rule(r: dict) -> dict:
    """Convert old flat format → new nested schema in-place."""
    if "match" in r:
        return r
    return {
        "id":       r.get("id", ""),
        "name":     r.get("name", "rule"),
        "enabled":  r.get("enabled", True),
        "priority": r.get("priority", 0),
        "match": {
            "url": {
                "kind":  _KIND_MAP.get(r.get("match_type", "equals"), "exact"),
                "value": r.get("target", ""),
            }
        },
        "action": {"type": "redirect", "to": r.get("redirect", "")},
    }

def load_rules() -> List[dict]:
    if RULES_FILE.exists():
        try:
            raw = json.loads(RULES_FILE.read_text())
            rules = [migrate_rule(r) for r in raw]
            rules.sort(key=lambda r: (r.get("priority", 0)))
            return [r for r in rules if r.get("enabled", True)]
        except Exception as e:
            log.error(f"Could not load rules.json: {e}")
    return []

# ─── matching engine ──────────────────────────────────────────────────────────

def _url_matches(url: str, m: dict) -> bool:
    kind  = m.get("kind", "exact")
    value = m.get("value", "")
    if kind == "exact":       return url == value
    if kind == "contains":    return value in url
    if kind == "startswith":  return url.startswith(value)
    if kind == "endswith":    return url.endswith(value)
    if kind == "wildcard":    return fnmatch.fnmatch(url, value)
    if kind == "regex":       return bool(re.search(value, url))
    if kind == "domain":
        host = urllib.parse.urlparse(url).hostname or ""
        if value.startswith("*."):
            d = value[2:]
            return host == d or host.endswith("." + d)
        return host == value
    return False

def _get_nested(obj: Any, path: str) -> Any:
    """Traverse dot-notation path through a dict."""
    for key in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return obj

def _match_graphql(gql: dict, flow: http.HTTPFlow) -> bool:
    try:
        body = json.loads(flow.request.content)
    except Exception:
        return False
    op = gql.get("operationName")
    if op and body.get("operationName") != op:
        return False
    pk, pv = gql.get("payloadKey"), gql.get("payloadValue")
    if pk:
        actual = _get_nested(body, pk)
        if pv and str(actual) != pv:
            return False
    return True

def _rule_matches(rule: dict, flow: http.HTTPFlow) -> bool:
    match = rule.get("match", {})
    url_m = match.get("url", {})
    if not _url_matches(flow.request.pretty_url, url_m):
        return False
    method = match.get("method")
    if method and method.upper() != flow.request.method.upper():
        return False
    gql = match.get("graphql")
    if gql and any(gql.values()):
        if not _match_graphql(gql, flow):
            return False
    return True

# ─── host extraction for allow_hosts ──────────────────────────────────────────

def _parse_host(value: str) -> str:
    """Extract hostname from a URL-like string, adding a scheme if missing."""
    if value and "://" not in value:
        value = "https://" + value
    return urllib.parse.urlparse(value).hostname or ""

def extract_allow_hosts(rules: List[dict]) -> List[str]:
    hosts = set()
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        url_m = rule.get("match", {}).get("url", {})
        kind  = url_m.get("kind", "exact")
        value = url_m.get("value", "")
        if kind in ("exact", "startswith", "contains", "endswith"):
            h = _parse_host(value)
            if h:
                hosts.add(re.escape(h))
        elif kind == "domain":
            d = value.lstrip("*.")
            if d:
                hosts.add(r"(?:.*\.)?" + re.escape(d))
        elif kind == "wildcard":
            h = _parse_host(value.replace("*", "x"))
            if h:
                hosts.add(re.escape(h))
        elif kind == "regex":
            if "host" in rule:
                hosts.add(re.escape(rule["host"]))
    return list(hosts)

# ─── actions ──────────────────────────────────────────────────────────────────

def _do_redirect(flow: http.HTTPFlow, to: str, name: str):
    p = urllib.parse.urlparse(to)
    flow.request.scheme = p.scheme
    flow.request.host   = p.hostname
    flow.request.port   = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    flow.request.path = path
    flow.request.headers["host"] = p.netloc

def _do_block(flow: http.HTTPFlow):
    flow.response = http.Response.make(
        403, b'{"error":"blocked by req-red"}',
        {"Content-Type": "application/json", "X-Blocked-By": "req-red"},
    )

def _do_mock(flow: http.HTTPFlow, action: dict):
    delay = action.get("delayMs", 0)
    if delay and delay > 0:
        time.sleep(delay / 1000)

    body: str = action.get("body", "")
    if action.get("bodyMode") == "dynamic":
        body = _run_script(action.get("script", ""), flow)

    raw = body.encode("utf-8") if isinstance(body, str) else body
    headers = dict(action.get("headers") or {})
    if "Content-Type" not in headers:
        try:
            json.loads(body)
            headers["Content-Type"] = "application/json"
        except Exception:
            headers["Content-Type"] = "text/plain"

    flow.response = http.Response.make(
        action.get("status", 200), raw, headers,
    )

def _run_script(script: str, flow: http.HTTPFlow) -> str:
    """Execute JS script via Node.js to generate mock body."""
    args = json.dumps({
        "method":         flow.request.method,
        "url":            flow.request.pretty_url,
        "requestHeaders": dict(flow.request.headers),
        "requestBody":    flow.request.content.decode("utf-8", errors="replace"),
    })
    node_src = f"""
const args = {args};
{script}
const r = typeof modifyResponse === 'function' ? modifyResponse(args) : null;
if (r === null || r === undefined) process.stdout.write('');
else if (typeof r === 'string') process.stdout.write(r);
else process.stdout.write(JSON.stringify(r));
"""
    try:
        res = subprocess.run(["node", "-e", node_src],
                             capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return res.stdout
        log.error(f"[req-red] script stderr: {res.stderr.strip()}")
        return json.dumps({"error": res.stderr.strip()})
    except FileNotFoundError:
        return json.dumps({"error": "Node.js not installed — required for dynamic scripts"})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Script execution timed out (5s)"})
    except Exception as e:
        return json.dumps({"error": str(e)})

# ─── structured request log ───────────────────────────────────────────────────

def _emit_request(flow: http.HTTPFlow, rule: Optional[dict], action_type: str,
                  status: Optional[int] = None):
    entry = {
        "__reqlog__": True,
        "ts":         int(time.time() * 1000),
        "method":     flow.request.method,
        "url":        flow.request.pretty_url,
        "rule_id":    rule["id"]   if rule else None,
        "rule_name":  rule["name"] if rule else None,
        "action":     action_type,
        "status":     status,
    }
    print(json.dumps(entry), flush=True)

# ─── mitmproxy addon ──────────────────────────────────────────────────────────

class ReqRedAddon:
    def __init__(self, rules: List[dict], port: int, use_sys: bool):
        self.rules   = rules
        self.port    = port
        self.use_sys = use_sys
        self._proxy_set = False

    def running(self):
        """Called by mitmproxy once it is fully bound and listening."""
        if self.use_sys:
            try:
                set_system_proxy(self.port)
                self._proxy_set = True
            except Exception as e:
                print(f"Warning: could not set system proxy: {e}")

    def done(self):
        """Called by mitmproxy on clean shutdown."""
        if self._proxy_set:
            try:
                unset_system_proxy()
                self._proxy_set = False
            except Exception:
                pass

    def request(self, flow: http.HTTPFlow) -> None:
        for rule in self.rules:
            if not _rule_matches(rule, flow):
                continue
            action = rule.get("action", {})
            atype  = action.get("type", "redirect")
            name   = rule.get("name", "")
            url    = flow.request.pretty_url

            if atype == "redirect":
                log.info(f"[req-red] [redirect] [{name}] {url}  →  {action.get('to','')}")
                _do_redirect(flow, action.get("to", ""), name)
                _emit_request(flow, rule, "redirect")

            elif atype == "block":
                log.info(f"[req-red] [block] [{name}] {url}")
                _do_block(flow)
                _emit_request(flow, rule, "block", 403)

            elif atype == "mock":
                log.info(f"[req-red] [mock] [{name}] {url}  →  {action.get('status',200)}")
                _do_mock(flow, action)
                _emit_request(flow, rule, "mock", action.get("status", 200))

            return  # first matching rule wins

# ─── system proxy ─────────────────────────────────────────────────────────────

def _network_services() -> List[str]:
    """macOS only — list active network services."""
    if sys.platform != "darwin":
        return []
    out = subprocess.run(["networksetup", "-listallnetworkservices"],
                         capture_output=True, text=True).stdout
    return [l.strip() for l in out.splitlines()[1:]
            if l.strip() and not l.startswith("*")]

def set_system_proxy(port: int):
    if sys.platform == "darwin":
        svcs = _network_services()
        if not svcs:
            return
        print(f"Setting system proxy (port {port}) on: {', '.join(svcs)}")
        for svc in svcs:
            subprocess.run(["networksetup", "-setwebproxy",            svc, "127.0.0.1", str(port)], check=True)
            subprocess.run(["networksetup", "-setsecurewebproxy",      svc, "127.0.0.1", str(port)], check=True)
            subprocess.run(["networksetup", "-setwebproxystate",       svc, "on"],                   check=True)
            subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "on"],                   check=True)
    elif sys.platform == "win32":
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                             0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "ProxyEnable",   0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer",   0, winreg.REG_SZ,    f"127.0.0.1:{port}")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,    "<local>")
        winreg.CloseKey(key)
        subprocess.run(["ie4uinit.exe", "-show"], capture_output=True)
        print(f"System proxy set to 127.0.0.1:{port} (Windows registry)")
    else:
        # Linux — try GNOME gsettings
        try:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode",        "manual"],      check=True)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http",  "host",  "127.0.0.1"],   check=True)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http",  "port",  str(port)],     check=True)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "host",  "127.0.0.1"],   check=True)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "port",  str(port)],     check=True)
            print(f"System proxy set via gsettings (GNOME) on port {port}")
        except Exception as e:
            print(f"Warning: could not set system proxy via gsettings: {e}")
            print(f"Set HTTP_PROXY=http://127.0.0.1:{port} and HTTPS_PROXY=http://127.0.0.1:{port} manually.")

def unset_system_proxy():
    if sys.platform == "darwin":
        for svc in _network_services():
            subprocess.run(["networksetup", "-setwebproxystate",       svc, "off"])
            subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"])
    elif sys.platform == "win32":
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            subprocess.run(["ie4uinit.exe", "-show"], capture_output=True)
        except Exception as e:
            print(f"Could not unset Windows proxy: {e}")
    else:
        try:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"],
                           capture_output=True)
        except Exception:
            pass
    print("System proxy disabled.")

# ─── port ────────────────────────────────────────────────────────────────────

def find_free_port(start: int = PORT_HINT) -> int:
    for p in range(start, start + 20):
        with socket.socket() as s:
            try:
                s.bind(("", p)); return p
            except OSError:
                pass
    raise RuntimeError("No free port found")

# ─── CA cert ─────────────────────────────────────────────────────────────────

CERT_PATH = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

def install_ca_cert():
    if not CERT_PATH.exists():
        print("CA cert not found — start proxy once first.")
        return False
    if sys.platform == "darwin":
        script = (
            f'set certPath to "{str(CERT_PATH)}"\n'
            'do shell script "security add-trusted-cert -d -r trustRoot '
            '-k /Library/Keychains/System.keychain " & quoted form of certPath '
            'with administrator privileges'
        )
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"cert install failed: {r.stderr.strip()}")
        return r.returncode == 0
    if sys.platform == "win32":
        cert = str(CERT_PATH).replace("'", "`'")
        ps = (f"Start-Process certutil "
              f"-ArgumentList '-addstore','-f','Root','{cert}' "
              f"-Verb RunAs -Wait")
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            print(f"certutil failed: {r.stderr.strip()}")
        return r.returncode == 0
    # Linux — try Debian/Ubuntu then Fedora/RHEL
    import shutil as _sh
    for dest, update_cmd in [
        (Path("/usr/local/share/ca-certificates/mitmproxy-ca.crt"), ["sudo", "update-ca-certificates"]),
        (Path("/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt"), ["sudo", "update-ca-trust", "extract"]),
    ]:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            _sh.copy2(CERT_PATH, dest)
            r = subprocess.run(update_cmd, capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                print(f"CA cert installed to {dest}")
                return True
        except Exception as e:
            print(f"Cert install attempt failed ({dest}): {e}")
    print(f"Manual install: sudo cp {CERT_PATH} /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates")
    return False

# ─── runner ───────────────────────────────────────────────────────────────────

async def _run(port: int, allow_hosts: List[str], use_sys: bool):
    opts = Options(
        listen_host="0.0.0.0",
        listen_port=port,
        ssl_insecure=True,
        allow_hosts=allow_hosts or ["^$"],
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    rules  = load_rules()
    master.addons.add(ReqRedAddon(rules, port, use_sys))
    try:
        await master.run()
    except KeyboardInterrupt:
        master.shutdown()

def _banner(port, rules, allow_hosts):
    active = [r for r in rules if r.get("enabled", True)]
    print(f"┌{'─'*62}┐")
    print(f"│{'req-red':^62}│")
    print(f"├{'─'*62}┤")
    print(f"│  port {port}  ·  {len(active)} rule(s)  ·  watching {len(allow_hosts)} host(s){'':>20}│")
    print(f"│  all other traffic: blind tunnel (no MITM){'':>19}│")
    print(f"└{'─'*62}┘")

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-system-proxy", action="store_true")
    ap.add_argument("--install-cert",    action="store_true")
    ap.add_argument("--unset-proxy",     action="store_true")
    args = ap.parse_args()

    if args.unset_proxy:    unset_system_proxy(); return
    if args.install_cert:   install_ca_cert();    return

    port        = find_free_port()
    all_rules   = load_rules()
    allow_hosts = extract_allow_hosts(all_rules)

    if not allow_hosts:
        print("INFO: no active rules — proxy will start but intercept nothing until rules are added.")
        allow_hosts = ["^$"]  # matches no host; safe to run

    use_sys = not args.no_system_proxy

    # Emergency cleanup — unset proxy if process is killed before done() fires
    def _cleanup():
        try: unset_system_proxy()
        except Exception: pass
    atexit.register(_cleanup)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (_cleanup(), sys.exit(0)))

    _banner(port, all_rules, allow_hosts)
    # System proxy is set inside ReqRedAddon.running() — only after mitmproxy
    # confirms it is bound and listening, so a crash before that point never
    # leaves a dead proxy entry in the OS network settings.
    asyncio.run(_run(port, allow_hosts, use_sys))

if __name__ == "__main__":
    main()
