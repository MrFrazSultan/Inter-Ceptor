#!/usr/bin/env python3
"""req-red web server.  Run: python server.py  →  http://localhost:4750"""

import collections, json, os, platform, queue, re, socket, subprocess
import sys, threading, time, uuid
from pathlib import Path

UI_PORT    = 4750
PROXY_HINT = 8080
SCRIPT_DIR = Path(__file__).parent
RULES_FILE = SCRIPT_DIR / "rules.json"
CERT_PATH  = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
REQ_RED    = SCRIPT_DIR / "req_red.py"
SYSTEM     = platform.system()

def _pip(*pkgs):
    r = subprocess.run([sys.executable,"-m","pip","install","--quiet",*pkgs],capture_output=True)
    if r.returncode!=0:
        subprocess.run([sys.executable,"-m","pip","install","--quiet",
                        "--break-system-packages",*pkgs],check=True)
try:
    from flask import Flask, jsonify, request, Response
except ImportError:
    print("Installing Flask…"); _pip("flask")
    from flask import Flask, jsonify, request, Response

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ── state ─────────────────────────────────────────────────────────────────────
_proxy_proc = None
_proxy_port = PROXY_HINT
_proxy_lock = threading.Lock()

_log_buf  = collections.deque(maxlen=800)
_log_subs: list = []
_log_lock = threading.Lock()

_req_buf  = collections.deque(maxlen=200)   # request log (intercepted)
_req_subs: list = []
_req_lock = threading.Lock()

def _emit(msg:str, tag:str="info"):
    e={"t":time.strftime("%H:%M:%S"),"msg":msg.rstrip(),"tag":tag}
    with _log_lock:
        _log_buf.append(e)
        for q in list(_log_subs):
            try: q.put_nowait(e)
            except queue.Full: pass

def _emit_req(entry:dict):
    with _req_lock:
        _req_buf.appendleft(entry)
        for q in list(_req_subs):
            try: q.put_nowait(entry)
            except queue.Full: pass

# ── rules ─────────────────────────────────────────────────────────────────────
_KIND_MAP={"equals":"exact","contains":"contains","startswith":"startswith",
           "endswith":"endswith","regex":"regex"}

def _migrate(r:dict)->dict:
    if "match" in r: return r
    return {"id":r.get("id",str(uuid.uuid4())),"name":r.get("name","rule"),
            "enabled":r.get("enabled",True),"priority":r.get("priority",0),
            "match":{"url":{"kind":_KIND_MAP.get(r.get("match_type","equals"),"exact"),
                            "value":r.get("target","")}},
            "action":{"type":"redirect","to":r.get("redirect","")}}

DEFAULT_RULES=[{"id":"example-rule","name":"example-redirect","enabled":False,"priority":0,
  "match":{"url":{"kind":"exact","value":"https://api.example.com/endpoint"}},
  "action":{"type":"redirect","to":"https://localhost:3000/endpoint"}}]

def load_rules()->list:
    if RULES_FILE.exists():
        try: return [_migrate(r) for r in json.loads(RULES_FILE.read_text())]
        except: pass
    return [r.copy() for r in DEFAULT_RULES]

def save_rules(rules:list):
    RULES_FILE.write_text(json.dumps(rules,indent=2))

# ── system checks ─────────────────────────────────────────────────────────────
def _check_deps():
    try:
        from importlib.metadata import version as v
        ver=v("mitmproxy")
        return {"ok":True,"version":ver}
    except Exception:
        return {"ok":False,"version":None}

def _run_cmd(args, timeout=4):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None

def _check_cert_trusted():
    if SYSTEM=="Darwin":
        for kc in ["/Library/Keychains/System.keychain",
                   os.path.expanduser("~/Library/Keychains/login.keychain-db")]:
            r=_run_cmd(["security","find-certificate","-c","mitmproxy",kc])
            if r and r.returncode==0: return True
        return False
    if SYSTEM=="Windows":
        r=_run_cmd(["certutil","-store","Root","mitmproxy"])
        return bool(r and r.returncode==0)
    # Linux — check well-known trust store paths
    for p in ["/usr/local/share/ca-certificates/mitmproxy-ca.crt",
              "/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt",
              "/etc/ssl/certs/mitmproxy-ca.pem"]:
        if Path(p).exists(): return True
    return False

# cache system proxy result for 5s to avoid hammering system commands
_sp_cache={"ts":0,"val":{"enabled":False,"services":[]}}
def _check_system_proxy():
    global _sp_cache
    if time.time()-_sp_cache["ts"]<5: return _sp_cache["val"]
    if SYSTEM=="Darwin":
        svcs=[]
        for svc in _network_services():
            r=_run_cmd(["networksetup","-getsecurewebproxy",svc],timeout=3)
            if r and "Enabled: Yes" in r.stdout: svcs.append(svc)
        val={"enabled":bool(svcs),"services":svcs}
    elif SYSTEM=="Windows":
        try:
            import winreg
            key=winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            enabled,_=winreg.QueryValueEx(key,"ProxyEnable")
            winreg.CloseKey(key)
            val={"enabled":bool(enabled),"services":["Windows"]}
        except Exception:
            val={"enabled":False,"services":[]}
    else:
        # Linux — check GNOME gsettings
        r=_run_cmd(["gsettings","get","org.gnome.system.proxy","mode"],timeout=3)
        is_on=bool(r and "manual" in r.stdout)
        val={"enabled":is_on,"services":["GNOME"] if is_on else []}
    _sp_cache={"ts":time.time(),"val":val}
    return val

def _network_services():
    if SYSTEM!="Darwin": return []
    r=_run_cmd(["networksetup","-listallnetworkservices"],timeout=4)
    if not r: return []
    return [l.strip() for l in r.stdout.splitlines()[1:]
            if l.strip() and not l.startswith("*")]

def _detect_os():
    if SYSTEM=="Darwin":
        ver=platform.mac_ver()[0]
        return {"system":"Darwin","display":f"macOS {ver}","distro":None,"pkg_family":"brew"}
    if SYSTEM=="Windows":
        ver=platform.version().split(".")[0]
        return {"system":"Windows","display":f"Windows {ver}","distro":None,"pkg_family":"winget"}
    # Linux — read /etc/os-release for distro details
    distro_name="Linux"; distro_id="linux"; pkg_family="apt"
    try:
        info={}
        with open("/etc/os-release") as f:
            for line in f:
                line=line.strip()
                if "=" in line:
                    k,v=line.split("=",1); info[k]=v.strip('"')
        distro_name=info.get("PRETTY_NAME",info.get("NAME","Linux"))
        distro_id=info.get("ID","linux").lower()
        id_like=info.get("ID_LIKE","").lower()
        if distro_id in ("fedora","rhel","centos","rocky","almalinux") or \
           any(x in id_like for x in ("fedora","rhel")):
            pkg_family="rpm"
        elif distro_id in ("arch","manjaro","endeavouros") or "arch" in id_like:
            pkg_family="pacman"
        else:
            pkg_family="apt"
    except Exception:
        pass
    return {"system":"Linux","display":distro_name,"distro":distro_id,"pkg_family":pkg_family}

_OS_INFO=_detect_os()

def _find_free_port(start=PROXY_HINT):
    for p in range(start,start+20):
        with socket.socket() as s:
            try: s.bind(("",p)); return p
            except OSError: pass
    raise RuntimeError("No free port")

def _proxy_running():
    return _proxy_proc is not None and _proxy_proc.poll() is None

# ── proxy management ──────────────────────────────────────────────────────────
def _stream(proc):
    global _proxy_proc
    for raw in iter(proc.stdout.readline, b""):
        line=raw.decode("utf-8",errors="replace").rstrip()
        if not line: continue
        # structured request log line
        if line.startswith('{"__reqlog__"'):
            try:
                entry=json.loads(line)
                entry.pop("__reqlog__",None)
                _emit_req(entry)
                continue
            except: pass
        tag="err" if any(w in line.lower() for w in ("error","failed","warn")) else \
            ("proxy" if "req-red" in line else "info")
        _emit(line,tag)
    proc.wait()
    _emit(f"[proxy] exited (code {proc.returncode})","info")
    with _proxy_lock: _proxy_proc=None

def _start_proxy():
    global _proxy_proc,_proxy_port
    with _proxy_lock:
        if _proxy_running(): return False,"Already running."
        try: _proxy_port=_find_free_port()
        except RuntimeError as e: return False,str(e)
        save_rules(load_rules())
        try:
            env={**os.environ,"PYTHONUNBUFFERED":"1"}
            proc=subprocess.Popen([sys.executable,str(REQ_RED)],
                                  stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env)
        except Exception as e: return False,str(e)
        _proxy_proc=proc
    threading.Thread(target=_stream,args=(proc,),daemon=True).start()
    _emit(f"[proxy] starting on port {_proxy_port}","ok")
    return True,f"Proxy started on port {_proxy_port}."

def _stop_proxy():
    global _proxy_proc
    with _proxy_lock:
        if not _proxy_running(): return False,"Not running."
        _proxy_proc.terminate()
        try: _proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired: _proxy_proc.kill()
        _proxy_proc=None
    _emit("[proxy] stopped.","info")
    return True,"Proxy stopped."

def _maybe_restart():
    if _proxy_running():
        _emit("[proxy] rules changed — restarting…","info")
        _stop_proxy(); time.sleep(0.4); _start_proxy()

# ── background actions ────────────────────────────────────────────────────────
def _install_deps_bg():
    _emit("Installing mitmproxy…","info")
    try: _pip("mitmproxy"); _emit("mitmproxy installed.","ok")
    except Exception as e: _emit(f"Install failed: {e}","err")

def _gen_cert_bg():
    _emit("Generating CA cert — starting proxy briefly…","info")
    p=subprocess.Popen([sys.executable,str(REQ_RED),"--no-system-proxy"],
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    t=time.time()
    while time.time()-t<8:
        if CERT_PATH.exists(): break
        time.sleep(0.3)
    p.terminate(); p.wait()
    if CERT_PATH.exists(): _emit(f"CA cert generated at {CERT_PATH}","ok")
    else: _emit("Cert generation timed out.","err")

def _install_cert():
    if not CERT_PATH.exists():
        return False,"CA cert not found — generate it first."
    if SYSTEM=="Darwin":
        # Use AppleScript variable + quoted form of to avoid any quoting issues in the shell cmd
        script=(
            f'set certPath to "{str(CERT_PATH)}"\n'
            'do shell script "security add-trusted-cert -d -r trustRoot '
            '-k /Library/Keychains/System.keychain " & quoted form of certPath '
            'with administrator privileges'
        )
        r=subprocess.run(["osascript","-e",script],capture_output=True,text=True)
        # macOS sometimes returns non-zero (SecTrustSettingsSetTrustSettings error) even
        # when the cert is actually installed and trusted — verify the real outcome.
        if _check_cert_trusted():
            return True,"Certificate installed to System keychain."
        err=r.stderr.strip()
        if "cancelled" in err.lower() or "-128" in err:
            return False,"Authentication cancelled — please try again and enter your password."
        return False,(err or "osascript failed — check System Preferences > Security.")
    if SYSTEM=="Windows":
        # Elevate via PowerShell RunAs so Windows shows the UAC prompt
        cert=str(CERT_PATH).replace("'","`'")
        ps=(f"Start-Process certutil "
            f"-ArgumentList '-addstore','-f','Root','{cert}' "
            f"-Verb RunAs -Wait")
        r=subprocess.run(["powershell","-NoProfile","-Command",ps],
                         capture_output=True,text=True,timeout=60)
        if r.returncode==0: return True,"Certificate installed to Windows Root store."
        return False,(r.stderr.strip() or "UAC prompt cancelled or certutil failed.")
    # Linux — try pkexec (GUI password prompt) then fall back to sudo
    import shutil as _sh, shlex as _sx
    for dest,update_cmd in [
        (Path("/usr/local/share/ca-certificates/mitmproxy-ca.crt"), "update-ca-certificates"),
        (Path("/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt"), "update-ca-trust extract"),
    ]:
        try:
            shell_cmd=f"cp {_sx.quote(str(CERT_PATH))} {_sx.quote(str(dest))} && {update_cmd}"
            # pkexec shows a native GUI auth dialog on GNOME/KDE
            r=subprocess.run(["pkexec","sh","-c",shell_cmd],
                             capture_output=True,text=True,timeout=30)
            if r.returncode==0: return True,f"Certificate installed ({dest})"
            # fall back to sudo (works in terminals)
            r2=subprocess.run(["sudo","sh","-c",shell_cmd],
                              capture_output=True,text=True,timeout=30)
            if r2.returncode==0: return True,f"Certificate installed ({dest})"
        except Exception:
            continue
    manual=(f"sudo cp {CERT_PATH} /usr/local/share/ca-certificates/mitmproxy.crt "
            f"&& sudo update-ca-certificates")
    return False,f"Auto-install failed. Run manually:\n{manual}"

# ── SSE helper ────────────────────────────────────────────────────────────────
def _sse_stream(buf_ref, subs_ref, lock_ref):
    q=queue.Queue(maxsize=300)
    with lock_ref:
        subs_ref.append(q)
        history=list(buf_ref)
    def gen():
        try:
            for e in history: yield f"data:{json.dumps(e)}\n\n"
            while True:
                try: yield f"data:{json.dumps(q.get(timeout=25))}\n\n"
                except queue.Empty: yield 'data:{"ping":true}\n\n'
        finally:
            with lock_ref:
                try: subs_ref.remove(q)
                except ValueError: pass
    return Response(gen(),mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/status")
def api_status():
    deps=_check_deps()
    return jsonify({"proxy_running":_proxy_running(),"proxy_port":_proxy_port,
                    "deps":deps,"cert_exists":CERT_PATH.exists(),
                    "cert_trusted":_check_cert_trusted(),
                    "system_proxy":_check_system_proxy(),"platform":SYSTEM,
                    "os_info":_OS_INFO})

@app.route("/api/deps/install",methods=["POST"])
def api_deps():
    threading.Thread(target=_install_deps_bg,daemon=True).start()
    return jsonify({"ok":True})

@app.route("/api/cert/generate",methods=["POST"])
def api_cert_gen():
    threading.Thread(target=_gen_cert_bg,daemon=True).start()
    return jsonify({"ok":True})

@app.route("/api/cert/install",methods=["POST"])
def api_cert_install():
    ok,msg=_install_cert()
    _emit(f"[cert] {msg}","ok" if ok else "err")
    return jsonify({"ok":ok,"msg":msg})

@app.route("/api/proxy/start",methods=["POST"])
def api_proxy_start():
    ok,msg=_start_proxy(); return jsonify({"ok":ok,"msg":msg})

@app.route("/api/proxy/stop",methods=["POST"])
def api_proxy_stop():
    ok,msg=_stop_proxy(); return jsonify({"ok":ok,"msg":msg})

@app.route("/api/logs")
def api_logs(): return _sse_stream(_log_buf,_log_subs,_log_lock)

@app.route("/api/requests")
def api_requests(): return _sse_stream(_req_buf,_req_subs,_req_lock)

@app.route("/api/rules",methods=["GET"])
def api_rules_list(): return jsonify(load_rules())

@app.route("/api/rules",methods=["POST"])
def api_rules_create():
    d=request.get_json(); rules=load_rules()
    rule={"id":str(uuid.uuid4()),"name":d.get("name","rule"),
          "enabled":d.get("enabled",True),
          "priority":max((r.get("priority",0) for r in rules),default=-1)+1,
          "match":d.get("match",{"url":{"kind":"exact","value":""}}),
          "action":d.get("action",{"type":"redirect","to":""})}
    rules.append(rule); save_rules(rules); _maybe_restart()
    return jsonify(rule),201

@app.route("/api/rules/<rid>",methods=["PUT"])
def api_rules_update(rid):
    d=request.get_json(); rules=load_rules()
    for r in rules:
        if r["id"]==rid:
            for k in ("name","enabled","priority","match","action"):
                if k in d: r[k]=d[k]
            save_rules(rules); _maybe_restart(); return jsonify(r)
    return jsonify({"error":"not found"}),404

@app.route("/api/rules/<rid>",methods=["DELETE"])
def api_rules_delete(rid):
    rules=[r for r in load_rules() if r["id"]!=rid]
    save_rules(rules); _maybe_restart(); return jsonify({"ok":True})

@app.route("/api/rules/<rid>/toggle",methods=["PATCH"])
def api_rules_toggle(rid):
    rules=load_rules()
    for r in rules:
        if r["id"]==rid:
            r["enabled"]=not r["enabled"]
            save_rules(rules); _maybe_restart(); return jsonify(r)
    return jsonify({"error":"not found"}),404

@app.route("/api/rules/<rid>/priority",methods=["PATCH"])
def api_rules_priority(rid):
    d=request.get_json(); rules=load_rules()
    for r in rules:
        if r["id"]==rid:
            r["priority"]=d.get("priority",r.get("priority",0))
            rules.sort(key=lambda x:x.get("priority",0))
            for i,rl in enumerate(rules): rl["priority"]=i
            save_rules(rules); _maybe_restart(); return jsonify(r)
    return jsonify({"error":"not found"}),404

@app.route("/api/rules/export")
def api_rules_export():
    return jsonify({"version":1,"rules":load_rules()})

@app.route("/api/rules/import",methods=["POST"])
def api_rules_import():
    d=request.get_json(); mode=d.get("mode","replace"); incoming=d.get("rules",[])
    if mode=="replace":
        save_rules(incoming); _maybe_restart()
        return jsonify({"ok":True,"count":len(incoming)})
    existing={r["id"]:r for r in load_rules()}
    for r in incoming:
        ex=existing.get(r["id"])
        if ex is None or r.get("updatedAt",0)>ex.get("updatedAt",0):
            existing[r["id"]]=r
    merged=sorted(existing.values(),key=lambda x:x.get("priority",0))
    save_rules(merged); _maybe_restart()
    return jsonify({"ok":True,"count":len(merged)})

# ── frontend ──────────────────────────────────────────────────────────────────
HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Interceptor</title>
<style>
/* ── tokens ── */
:root{
  --bg:#0d1117;--sf:#161b22;--sf2:#1c2128;--bd:#21262d;--bd2:#30363d;
  --fg:#e6edf3;--fg2:#8b949e;--fg3:#484f58;
  --ac:#58a6ff;--ac-bg:rgba(88,166,255,.12);
  --gr:#3fb950;--gr-bg:rgba(63,185,80,.12);
  --am:#e3b341;--am-bg:rgba(227,179,65,.12);
  --re:#f85149;--re-bg:rgba(248,81,73,.12);
  --or:#fb923c;--or-bg:rgba(251,146,60,.12);
  --mono:'Menlo','Monaco','JetBrains Mono','Fira Code','Consolas',monospace;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --r:6px;--r2:10px;
  --nav-h:52px;--bot-h:56px;
}
@media(prefers-color-scheme:light){:root:not([data-theme=dark]){
  --bg:#f6f8fa;--sf:#fff;--sf2:#f0f2f4;--bd:#d0d7de;--bd2:#b8bfc7;
  --fg:#1f2328;--fg2:#656d76;--fg3:#afb8c1;
  --ac:#0969da;--ac-bg:rgba(9,105,218,.08);
  --gr:#1a7f37;--gr-bg:rgba(26,127,55,.08);
  --am:#9a6700;--am-bg:rgba(154,103,0,.08);
  --re:#cf222e;--re-bg:rgba(207,34,46,.08);
  --or:#bc4c00;--or-bg:rgba(188,76,0,.08);
}}
:root[data-theme=light]{
  --bg:#f6f8fa;--sf:#fff;--sf2:#f0f2f4;--bd:#d0d7de;--bd2:#b8bfc7;
  --fg:#1f2328;--fg2:#656d76;--fg3:#afb8c1;
  --ac:#0969da;--ac-bg:rgba(9,105,218,.08);
  --gr:#1a7f37;--gr-bg:rgba(26,127,55,.08);
  --am:#9a6700;--am-bg:rgba(154,103,0,.08);
  --re:#cf222e;--re-bg:rgba(207,34,46,.08);
  --or:#bc4c00;--or-bg:rgba(188,76,0,.08);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:14px;
  line-height:1.6;min-height:100vh;padding-bottom:var(--bot-h)}

/* ── topbar ── */
.topbar{background:var(--sf);border-bottom:1px solid var(--bd);
  height:var(--nav-h);display:flex;align-items:center;gap:10px;padding:0 16px;
  position:sticky;top:0;z-index:90}
.logo{font-family:var(--mono);font-weight:600;font-size:15px;letter-spacing:-.3px;white-space:nowrap}
.logo em{color:var(--re);font-style:normal}
.status-pill{display:flex;align-items:center;gap:6px;font-family:var(--mono);
  font-size:11px;padding:3px 10px;border-radius:100px;border:1px solid var(--bd2);
  background:var(--sf2);color:var(--fg2);white-space:nowrap}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--fg3);transition:background .3s}
.status-pill .dot.on{background:var(--gr)}
.port-label{font-family:var(--mono);font-size:11px;color:var(--fg3)}
.topbar-r{margin-left:auto;display:flex;align-items:center;gap:8px}
.btn{display:inline-flex;align-items:center;gap:5px;font-family:var(--sans);font-size:13px;
  font-weight:500;padding:6px 14px;border-radius:var(--r);border:1px solid transparent;
  cursor:pointer;transition:opacity .15s,background .15s;white-space:nowrap;line-height:1}
.btn:disabled{opacity:.4;cursor:default;pointer-events:none}
.btn-gr{background:var(--gr);color:#fff;border-color:var(--gr)}
.btn-re{background:var(--re-bg);color:var(--re);border-color:var(--re)}
.btn-ac{background:var(--ac);color:#fff}
.btn-ghost{background:transparent;color:var(--fg2);border-color:var(--bd2)}
.btn-ghost:hover{color:var(--fg);border-color:var(--fg3)}
.btn-sm{font-size:12px;padding:4px 10px}
.btn-icon{padding:5px 9px;background:transparent;border:1px solid var(--bd);
  border-radius:var(--r);color:var(--fg2);cursor:pointer;font-size:13px;line-height:1}
.btn-icon:hover{color:var(--fg);border-color:var(--bd2)}

/* ── desktop tabs ── */
.dtabs{background:var(--sf);border-bottom:1px solid var(--bd);
  display:flex;padding:0 16px;gap:0}
.dtab{font-size:13px;font-weight:500;padding:10px 14px;cursor:pointer;
  color:var(--fg2);border-bottom:2px solid transparent;transition:color .15s;white-space:nowrap}
.dtab:hover{color:var(--fg)}
.dtab.active{color:var(--ac);border-bottom-color:var(--ac)}

/* ── bottom mobile nav ── */
.bnav{display:none;position:fixed;bottom:0;left:0;right:0;z-index:90;
  background:var(--sf);border-top:1px solid var(--bd);
  height:var(--bot-h);padding:0 8px;
  align-items:center;justify-content:space-around}
.bntab{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;
  padding:6px 4px;cursor:pointer;color:var(--fg2);font-size:10px;font-weight:500;
  border-radius:var(--r);transition:color .15s}
.bntab .icon{font-size:18px;line-height:1}
.bntab.active{color:var(--ac)}
@media(max-width:640px){
  .dtabs{display:none}
  .bnav{display:flex}
  .port-label{display:none}
  .topbar{padding:0 12px}
}

/* ── panels ── */
.panel{display:none}.panel.active{display:block}
.page{max-width:960px;margin:0 auto;padding:20px 16px 40px}
@media(max-width:640px){.page{padding:14px 12px 32px}}

/* ── cards / containers ── */
.card{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r2);overflow:hidden}
.card-hd{padding:12px 16px;border-bottom:1px solid var(--bd);
  display:flex;align-items:center;gap:10px}
.card-hd-title{font-family:var(--mono);font-size:11px;font-weight:600;
  text-transform:uppercase;letter-spacing:.6px;color:var(--fg2)}
.card-bd{padding:16px}

/* ── OS banner ── */
.os-banner{display:flex;align-items:center;gap:10px;padding:10px 14px;
  background:var(--sf);border:1px solid var(--bd);border-radius:var(--r2);
  margin-bottom:14px}
.os-icon{font-size:22px;line-height:1}
.os-label-sub{font-size:10px;color:var(--fg3);text-transform:uppercase;letter-spacing:.06em}
.os-label{font-size:13px;font-weight:600}
/* ── setup checklist ── */
.chk{display:flex;flex-direction:column;gap:10px}
.chk-item{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r2);
  padding:14px 16px;display:grid;grid-template-columns:22px 1fr auto;
  gap:12px;align-items:start;border-left-width:3px}
.chk-item.ok  {border-left-color:var(--gr)}
.chk-item.warn{border-left-color:var(--am)}
.chk-item.fail{border-left-color:var(--re)}
.chk-icon{font-size:15px;text-align:center;font-family:var(--mono);padding-top:1px}
.chk-title{font-size:13px;font-weight:600}
.chk-desc{font-size:11.5px;color:var(--fg2);margin-top:2px;font-family:var(--mono);word-break:break-all}
.chk-act{flex-shrink:0;display:flex;flex-direction:column;align-items:flex-end;gap:6px}
.manual-det{margin-top:6px;font-size:11px;width:100%}
.manual-det summary{cursor:pointer;color:var(--fg3);user-select:none;list-style:none;display:flex;align-items:center;gap:4px}
.manual-det summary::before{content:'▶';font-size:8px;transition:transform .15s}
.manual-det[open] summary::before{transform:rotate(90deg)}
.manual-pre{margin:6px 0 0;padding:8px 10px;background:var(--bg);border:1px solid var(--bd);
  border-radius:6px;font-family:var(--mono);font-size:11px;white-space:pre;overflow-x:auto;
  color:var(--fg2);line-height:1.6}
.copy-btn{margin-left:auto;font-size:10px;padding:2px 8px;border:1px solid var(--bd);
  border-radius:4px;background:var(--sf2);color:var(--fg2);cursor:pointer;flex-shrink:0}
.copy-btn:hover{background:var(--bd);color:var(--fg)}
@media(max-width:480px){
  .chk-item{grid-template-columns:22px 1fr;gap:10px}
  .chk-act{grid-column:2;margin-top:4px;align-items:flex-start}
}

/* ── badge ── */
.badge{font-family:var(--mono);font-size:10px;font-weight:600;padding:2px 8px;
  border-radius:100px;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap}
.bg-gr{background:var(--gr-bg);color:var(--gr)}
.bg-re{background:var(--re-bg);color:var(--re)}
.bg-ac{background:var(--ac-bg);color:var(--ac)}
.bg-am{background:var(--am-bg);color:var(--am)}
.bg-or{background:var(--or-bg);color:var(--or)}
.bg-muted{background:var(--sf2);color:var(--fg2);border:1px solid var(--bd)}

/* ── rules ── */
.rules-bar{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.rules-bar-r{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.search-box{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  color:var(--fg);font-family:var(--mono);font-size:12px;padding:5px 10px;
  outline:none;width:180px}
.search-box:focus{border-color:var(--ac)}

/* desktop table */
.rtable{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r2);overflow:hidden}
.rtable-head{display:grid;grid-template-columns:36px 1fr 80px 1fr 1fr 54px 90px;
  background:var(--sf2);border-bottom:1px solid var(--bd)}
.rth{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.5px;
  text-transform:uppercase;color:var(--fg2);padding:9px 12px}
.rrow{display:grid;grid-template-columns:36px 1fr 80px 1fr 1fr 54px 90px;
  border-bottom:1px solid var(--bd);align-items:center;transition:background .1s}
.rrow:last-child{border-bottom:none}
.rrow:hover{background:var(--sf2)}
.rrow.off{opacity:.45}
.rc{padding:9px 12px;font-size:13px;overflow:hidden;min-width:0}
.rc-mono{font-family:var(--mono);font-size:11px;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;color:var(--fg2)}
.rc-acts{display:flex;gap:5px;align-items:center;justify-content:flex-end;padding-right:10px}

/* mobile rule cards */
.rcards{display:none;flex-direction:column;gap:10px}
.rcard{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r2);
  padding:12px 14px}
.rcard.off{opacity:.5}
.rcard-hd{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.rcard-name{font-weight:600;font-size:13px;flex:1;min-width:0;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rcard-urls{font-family:var(--mono);font-size:11px;color:var(--fg2);
  display:flex;flex-direction:column;gap:3px;margin-bottom:8px;
  overflow:hidden;text-overflow:ellipsis}
.rcard-ft{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
@media(max-width:640px){
  .rtable{display:none}
  .rcards{display:flex}
}

/* ── toggle ── */
.tgl{position:relative;width:34px;height:18px;cursor:pointer;flex-shrink:0;display:inline-block}
.tgl input{position:absolute;opacity:0;width:100%;height:100%;margin:0;cursor:pointer;z-index:2}
.tgl-tk{position:absolute;inset:0;background:var(--bd2);border-radius:100px;transition:background .2s;z-index:0}
.tgl input:checked~.tgl-tk{background:var(--gr)}
.tgl-th{position:absolute;top:2px;left:2px;width:14px;height:14px;background:#fff;
  border-radius:50%;transition:transform .2s;box-shadow:0 1px 3px rgba(0,0,0,.4);z-index:1;pointer-events:none}
.tgl input:checked~.tgl-th{transform:translateX(16px)}

/* ── match chip ── */
.mchip{font-family:var(--mono);font-size:10px;font-weight:600;padding:2px 6px;
  border-radius:4px;text-transform:uppercase;letter-spacing:.3px;display:inline-block}
.mc-exact    {background:var(--ac-bg);color:var(--ac)}
.mc-wildcard {background:rgba(188,140,255,.15);color:#c586ff}
.mc-regex    {background:var(--re-bg);color:var(--re)}
.mc-domain   {background:var(--gr-bg);color:var(--gr)}
.mc-contains,.mc-startswith,.mc-endswith{background:var(--am-bg);color:var(--am)}

/* ── request log ── */
.req-list{display:flex;flex-direction:column;gap:6px}
.req-item{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r2);
  padding:10px 14px;display:grid;grid-template-columns:56px 1fr auto;
  gap:10px;align-items:start;cursor:pointer;transition:border-color .15s}
.req-item:hover{border-color:var(--bd2)}
.req-item.expanded .req-detail{display:block}
.req-method{font-family:var(--mono);font-size:11px;font-weight:600;
  padding:2px 6px;border-radius:4px;text-align:center;align-self:start}
.m-GET   {background:var(--gr-bg);color:var(--gr)}
.m-POST  {background:var(--ac-bg);color:var(--ac)}
.m-PUT   {background:var(--am-bg);color:var(--am)}
.m-DELETE{background:var(--re-bg);color:var(--re)}
.m-PATCH {background:var(--or-bg);color:var(--or)}
.m-OTHER {background:var(--sf2);color:var(--fg2)}
.req-url{font-family:var(--mono);font-size:11.5px;word-break:break-all;color:var(--fg)}
.req-meta{font-size:11px;color:var(--fg2);margin-top:2px}
.req-ts{font-family:var(--mono);font-size:10.5px;color:var(--fg3);white-space:nowrap}
.req-detail{display:none;margin-top:10px;padding-top:10px;
  border-top:1px solid var(--bd);font-family:var(--mono);font-size:11.5px;
  color:var(--fg2);white-space:pre-wrap;word-break:break-all;grid-column:1/-1}
@media(max-width:480px){
  .req-item{grid-template-columns:50px 1fr}
  .req-ts{grid-column:1/-1;text-align:right}
}

/* ── logs ── */
.log-bar{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap}
.log-filter{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  color:var(--fg);font-family:var(--mono);font-size:12px;padding:5px 10px;
  outline:none;width:180px}
.log-filter:focus{border-color:var(--ac)}
.logbox{background:#010409;border:1px solid var(--bd);border-radius:var(--r2);
  height:440px;overflow-y:auto;padding:10px 12px;
  font-family:var(--mono);font-size:11.5px;line-height:1.75}
.log-line{display:flex;gap:10px;padding:0}
.log-line:hover{background:rgba(255,255,255,.025);border-radius:3px}
.lts{color:#3d444d;flex-shrink:0;user-select:none}
.lmsg{word-break:break-all;white-space:pre-wrap}
.lmsg.ok   {color:var(--gr)}.lmsg.err{color:var(--re)}
.lmsg.proxy{color:var(--ac)}.lmsg.info{color:var(--fg)}
@media(max-width:640px){.logbox{height:calc(100vh - 200px)}}

/* ── modal ── */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;
  display:none;align-items:flex-end;justify-content:center}
.overlay.open{display:flex}
@media(min-width:600px){.overlay{align-items:center}}
.modal{background:var(--sf);border:1px solid var(--bd2);
  border-radius:var(--r2) var(--r2) 0 0;width:100%;max-width:580px;
  max-height:92vh;overflow-y:auto;display:flex;flex-direction:column}
@media(min-width:600px){.modal{border-radius:var(--r2);max-height:88vh}}
.modal-hd{padding:14px 18px;border-bottom:1px solid var(--bd);
  display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;background:var(--sf);z-index:1}
.modal-title{font-size:15px;font-weight:600}
.modal-bd{padding:18px;display:flex;flex-direction:column;gap:14px;flex:1}
.modal-ft{padding:14px 18px;border-top:1px solid var(--bd);
  display:flex;justify-content:flex-end;gap:8px;
  position:sticky;bottom:0;background:var(--sf)}

/* form */
.fgrp{display:flex;flex-direction:column;gap:5px}
.flbl{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.5px;
  text-transform:uppercase;color:var(--fg2)}
.finp,.fsel,.ftxt{width:100%;background:var(--sf2);border:1px solid var(--bd2);
  border-radius:var(--r);color:var(--fg);font-family:var(--mono);font-size:12.5px;
  padding:8px 10px;outline:none;transition:border-color .15s}
.finp:focus,.fsel:focus,.ftxt:focus{border-color:var(--ac)}
.fsel option{background:var(--sf2)}
.ftxt{resize:vertical;min-height:90px;line-height:1.6}
.frow{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:480px){.frow{grid-template-columns:1fr}}
.fsub{font-size:11.5px;color:var(--fg2);margin-top:2px}

/* headers editor */
.hdr-list{display:flex;flex-direction:column;gap:6px}
.hdr-row{display:grid;grid-template-columns:1fr 1fr 28px;gap:6px;align-items:center}
.hdr-row .finp{padding:6px 8px}

/* section divider */
.sec-divider{display:flex;align-items:center;gap:8px;margin:4px 0}
.sec-divider::before,.sec-divider::after{content:'';flex:1;height:1px;background:var(--bd)}
.sec-label{font-family:var(--mono);font-size:10px;color:var(--fg3);
  text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}

/* section collapse */
.collapsible summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px;
  font-family:var(--mono);font-size:11px;font-weight:600;color:var(--fg2);
  text-transform:uppercase;letter-spacing:.5px;padding:4px 0}
.collapsible summary::-webkit-details-marker{display:none}
.collapsible summary::before{content:'▸';font-size:10px;transition:transform .2s}
.collapsible[open] summary::before{transform:rotate(90deg)}
.collapsible .inner{margin-top:10px;display:flex;flex-direction:column;gap:12px}

/* import area */
.import-drop{border:2px dashed var(--bd2);border-radius:var(--r2);padding:24px;
  text-align:center;color:var(--fg2);font-size:13px;cursor:pointer;
  transition:border-color .2s}
.import-drop:hover,.import-drop.drag{border-color:var(--ac);color:var(--fg)}

/* empty */
.empty{padding:40px 20px;text-align:center;color:var(--fg2);font-size:13px}
.spinner{display:inline-block;width:12px;height:12px;border:2px solid currentColor;
  border-top-color:transparent;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.gap4{margin-top:4px}.gap8{margin-top:8px}.gap16{margin-top:16px}
[hidden]{display:none!important}
#offlineBanner{display:flex}
</style>
</head>
<body>

<!-- TOPBAR -->
<header class="topbar">
  <span class="logo">Inter<em>ceptor</em></span>
  <div class="status-pill"><span class="dot" id="dot"></span><span id="slabel">—</span></div>
  <span class="port-label" id="portLabel"></span>
  <div class="topbar-r">
    <button class="btn btn-gr btn-sm" id="startBtn" onclick="startProxy()">Start</button>
    <button class="btn btn-re btn-sm" id="stopBtn"  onclick="stopProxy()" style="display:none">Stop</button>
    <button class="btn-icon" onclick="toggleTheme()" title="Toggle theme">◑</button>
  </div>
</header>

<!-- DESKTOP TABS -->
<nav class="dtabs">
  <div class="dtab active" onclick="tab('setup')">Setup</div>
  <div class="dtab" onclick="tab('rules')">Rules</div>
  <div class="dtab" onclick="tab('reqs')">Requests</div>
  <div class="dtab" onclick="tab('logs')">Logs</div>
</nav>

<!-- OFFLINE BANNER -->
<div id="offlineBanner" hidden style="background:var(--re-bg);border-bottom:1px solid var(--re);
  padding:10px 18px;align-items:center;gap:10px;font-size:13px;color:var(--re)">
  <span style="font-size:16px">⚠</span>
  <span>Cannot reach server — if you restarted it, <strong>refresh this page</strong>.</span>
  <button class="btn btn-sm" onclick="location.reload()"
    style="margin-left:auto;background:var(--re);color:#fff;border:none">Refresh</button>
</div>

<!-- SETUP -->
<div class="panel active" id="p-setup">
<div class="page">
  <div class="os-banner">
    <span class="os-icon" id="osIcon">💻</span>
    <div>
      <div class="os-label-sub">Detected OS</div>
      <div class="os-label" id="osLabel">Detecting…</div>
    </div>
  </div>
  <div class="chk" id="chkList">
    <div class="chk-item" id="ci-deps"><span class="chk-icon">⋯</span>
      <div><div class="chk-title">Python dependencies</div>
           <div class="chk-desc" id="ci-deps-d">checking…</div></div>
      <div class="chk-act" id="ci-deps-a"></div></div>
    <div class="chk-item" id="ci-cert"><span class="chk-icon">⋯</span>
      <div><div class="chk-title">CA certificate</div>
           <div class="chk-desc" id="ci-cert-d">checking…</div></div>
      <div class="chk-act" id="ci-cert-a"></div></div>
    <div class="chk-item" id="ci-trust"><span class="chk-icon">⋯</span>
      <div><div class="chk-title">Certificate trusted by system</div>
           <div class="chk-desc" id="ci-trust-d">checking…</div></div>
      <div class="chk-act" id="ci-trust-a"></div></div>
    <div class="chk-item" id="ci-proxy"><span class="chk-icon">⋯</span>
      <div><div class="chk-title">System proxy</div>
           <div class="chk-desc" id="ci-proxy-d">checking…</div></div>
      <div class="chk-act" id="ci-proxy-a"></div></div>
  </div>
</div>
</div>

<!-- RULES -->
<div class="panel" id="p-rules">
<div class="page">
  <div class="rules-bar">
    <input class="search-box" id="rSearch" placeholder="search rules…" oninput="renderRules()">
    <div class="rules-bar-r">
      <button class="btn btn-ghost btn-sm" onclick="exportRules()">Export</button>
      <button class="btn btn-ghost btn-sm" onclick="openImport()">Import</button>
      <button class="btn btn-ac btn-sm"    onclick="openModal()">+ Add rule</button>
    </div>
  </div>
  <!-- desktop table -->
  <div class="rtable">
    <div class="rtable-head">
      <div class="rth">#</div>
      <div class="rth">Name</div>
      <div class="rth">Action</div>
      <div class="rth">Match</div>
      <div class="rth">Target / Redirect</div>
      <div class="rth" style="text-align:center">On</div>
      <div class="rth" style="text-align:right;padding-right:16px">Actions</div>
    </div>
    <div id="rtableBody"></div>
  </div>
  <!-- mobile cards -->
  <div class="rcards" id="rcards"></div>
</div>
</div>

<!-- REQUESTS -->
<div class="panel" id="p-reqs">
<div class="page">
  <div class="log-bar">
    <input class="log-filter" id="reqFilter" placeholder="filter URL…" oninput="renderReqs()">
    <button class="btn btn-ghost btn-sm" style="margin-left:auto" onclick="clearReqs()">Clear</button>
  </div>
  <div id="reqList" class="req-list"><div class="empty">No intercepted requests yet — start the proxy and make some requests.</div></div>
</div>
</div>

<!-- LOGS -->
<div class="panel" id="p-logs">
<div class="page">
  <div class="log-bar">
    <input class="log-filter" id="logFilter" placeholder="filter…" oninput="renderLogs()">
    <label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--fg2);cursor:pointer">
      <input type="checkbox" id="autoScroll" checked> auto-scroll
    </label>
    <button class="btn btn-ghost btn-sm" style="margin-left:auto" onclick="clearLogs()">Clear</button>
  </div>
  <div class="logbox" id="logBox"></div>
</div>
</div>

<!-- BOTTOM NAV (mobile) -->
<nav class="bnav">
  <div class="bntab active" onclick="tab('setup')" id="bn-setup">
    <span class="icon">⚙</span><span>Setup</span>
  </div>
  <div class="bntab" onclick="tab('rules')" id="bn-rules">
    <span class="icon">⇄</span><span>Rules</span>
  </div>
  <div class="bntab" onclick="tab('reqs')" id="bn-reqs">
    <span class="icon">◎</span><span>Requests</span>
  </div>
  <div class="bntab" onclick="tab('logs')" id="bn-logs">
    <span class="icon">≡</span><span>Logs</span>
  </div>
</nav>

<!-- RULE MODAL -->
<div class="overlay" id="modal" onclick="if(event.target===this)closeModal()">
<div class="modal">
  <div class="modal-hd">
    <span class="modal-title" id="mTitle">Add rule</span>
    <button class="btn-icon" onclick="closeModal()">✕</button>
  </div>
  <div class="modal-bd">
    <input type="hidden" id="mId">

    <!-- basic -->
    <div class="frow">
      <div class="fgrp">
        <label class="flbl">Rule name</label>
        <input class="finp" id="mName" placeholder="my-rule">
      </div>
      <div class="fgrp">
        <label class="flbl">Action</label>
        <select class="fsel" id="mAction" onchange="onActionChange()">
          <option value="redirect">Redirect</option>
          <option value="block">Block</option>
          <option value="mock">Mock response</option>
        </select>
      </div>
    </div>

    <!-- match -->
    <div class="sec-divider"><span class="sec-label">Match</span></div>
    <div class="frow">
      <div class="fgrp">
        <label class="flbl">URL match kind</label>
        <select class="fsel" id="mKind">
          <option value="exact">exact — full URL</option>
          <option value="wildcard">wildcard — glob *</option>
          <option value="regex">regex — re.search</option>
          <option value="domain">domain — hostname</option>
          <option value="contains">contains — substring</option>
          <option value="startswith">startswith</option>
          <option value="endswith">endswith</option>
        </select>
      </div>
      <div class="fgrp">
        <label class="flbl">HTTP method (optional)</label>
        <select class="fsel" id="mMethod">
          <option value="">Any method</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="PATCH">PATCH</option>
          <option value="DELETE">DELETE</option>
          <option value="OPTIONS">OPTIONS</option>
        </select>
      </div>
    </div>
    <div class="fgrp">
      <label class="flbl">Target URL / pattern</label>
      <input class="finp" id="mTarget" placeholder="https://example.com/api/endpoint">
    </div>

    <!-- graphql collapsible -->
    <details class="collapsible" id="gqlSection">
      <summary>GraphQL matching</summary>
      <div class="inner">
        <div class="fgrp">
          <label class="flbl">Operation name</label>
          <input class="finp" id="mGqlOp" placeholder="GetUser">
          <span class="fsub">Matches requests where JSON body has this operationName</span>
        </div>
        <div class="frow">
          <div class="fgrp">
            <label class="flbl">Payload key (dot path)</label>
            <input class="finp" id="mGqlKey" placeholder="variables.userId">
          </div>
          <div class="fgrp">
            <label class="flbl">Expected value</label>
            <input class="finp" id="mGqlVal" placeholder="42">
          </div>
        </div>
      </div>
    </details>

    <!-- redirect fields -->
    <div id="rSection">
      <div class="sec-divider"><span class="sec-label">Redirect to</span></div>
      <div class="fgrp">
        <label class="flbl">Destination URL</label>
        <input class="finp" id="mTo" placeholder="https://other.host.com/endpoint">
      </div>
    </div>

    <!-- mock fields -->
    <div id="mockSection" style="display:none;flex-direction:column;gap:14px">
      <div class="sec-divider"><span class="sec-label">Mock response</span></div>
      <div class="frow">
        <div class="fgrp">
          <label class="flbl">Status code</label>
          <input class="finp" id="mStatus" type="number" value="200" min="100" max="599">
        </div>
        <div class="fgrp">
          <label class="flbl">Delay (ms)</label>
          <input class="finp" id="mDelay" type="number" value="0" min="0">
        </div>
      </div>
      <!-- response headers -->
      <div class="fgrp">
        <label class="flbl">Response headers</label>
        <div class="hdr-list" id="hdrList"></div>
        <button class="btn btn-ghost btn-sm gap4" onclick="addHeader()">+ add header</button>
      </div>
      <!-- body mode -->
      <div class="fgrp">
        <label class="flbl">Body mode</label>
        <select class="fsel" id="mBodyMode" onchange="onBodyModeChange()">
          <option value="static">Static body</option>
          <option value="dynamic">Dynamic script (JavaScript / Node.js)</option>
        </select>
      </div>
      <div id="bodyStatic" class="fgrp">
        <label class="flbl">Response body</label>
        <textarea class="ftxt" id="mBody" rows="5" placeholder='{"ok":true}'></textarea>
      </div>
      <div id="bodyDynamic" class="fgrp" style="display:none">
        <label class="flbl">JavaScript script (Node.js)</label>
        <textarea class="ftxt" id="mScript" rows="7"
          style="font-size:11.5px"
          placeholder="function modifyResponse(args) {
  // args: { method, url, requestBody, requestHeaders }
  return { ok: true, timestamp: Date.now() };
}"></textarea>
        <span class="fsub">Function <code style="color:var(--ac)">modifyResponse(args)</code> — return string, object (serialised to JSON), or null. Requires Node.js.</span>
      </div>
    </div>

    <!-- enable toggle -->
    <div style="display:flex;align-items:center;gap:10px">
      <label class="tgl"><input type="checkbox" id="mEnabled" checked>
        <span class="tgl-tk"></span><span class="tgl-th"></span></label>
      <span style="font-size:13px;color:var(--fg2)">Rule enabled</span>
    </div>
  </div>
  <div class="modal-ft">
    <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
    <button class="btn btn-ac"    onclick="saveRule()">Save rule</button>
  </div>
</div>
</div>

<!-- IMPORT MODAL -->
<div class="overlay" id="importModal" onclick="if(event.target===this)closeImport()">
<div class="modal" style="max-width:440px">
  <div class="modal-hd">
    <span class="modal-title">Import rules</span>
    <button class="btn-icon" onclick="closeImport()">✕</button>
  </div>
  <div class="modal-bd">
    <div class="import-drop" id="dropZone" onclick="document.getElementById('fileInput').click()"
         ondragover="event.preventDefault();this.classList.add('drag')"
         ondragleave="this.classList.remove('drag')"
         ondrop="handleDrop(event)">
      <div style="font-size:24px;margin-bottom:8px">📂</div>
      <div>Drop a <code style="font-family:var(--mono);color:var(--ac)">.json</code> file here or click to browse</div>
      <input type="file" id="fileInput" accept=".json" style="display:none" onchange="handleFile(this)">
    </div>
    <div class="fgrp gap8">
      <label class="flbl">Import mode</label>
      <select class="fsel" id="importMode">
        <option value="replace">Replace all existing rules</option>
        <option value="merge">Merge (newer updatedAt wins per ID)</option>
      </select>
    </div>
  </div>
  <div class="modal-ft">
    <button class="btn btn-ghost" onclick="closeImport()">Cancel</button>
    <button class="btn btn-ac"    onclick="doImport()" id="importBtn" disabled>Import</button>
  </div>
</div>
</div>

<script>
// ── globals ────────────────────────────────────────────────────────────────
let ST={}, rules=[], logs=[], reqs=[], importData=null, editId=null;
const tabs=['setup','rules','reqs','logs'];

// ── theme ──────────────────────────────────────────────────────────────────
function toggleTheme(){
  const r=document.documentElement,c=r.getAttribute('data-theme');
  r.setAttribute('data-theme',c==='light'?'dark':'light');
  try{localStorage.setItem('rr-theme',c==='light'?'dark':'light')}catch{}
}
try{const t=localStorage.getItem('rr-theme');if(t)document.documentElement.setAttribute('data-theme',t)}catch{}

// ── tabs ───────────────────────────────────────────────────────────────────
function tab(name){
  tabs.forEach(n=>{
    document.querySelectorAll('.dtab').forEach((el,i)=>el.classList.toggle('active',tabs[i]===name));
    document.getElementById('p-'+name)?.classList.toggle('active',true);
    document.getElementById('bn-'+name)?.classList.toggle('active',true);
  });
  tabs.filter(n=>n!==name).forEach(n=>{
    document.getElementById('p-'+n)?.classList.remove('active');
    document.getElementById('bn-'+n)?.classList.remove('active');
  });
  document.querySelectorAll('.dtab').forEach((el,i)=>el.classList.toggle('active',tabs[i]===name));
}

// ── status ─────────────────────────────────────────────────────────────────
let _failCount=0;
async function fetchStatus(){
  try{
    const ac=new AbortController();
    const t=setTimeout(()=>ac.abort(),5000);
    const r=await fetch('/api/status',{signal:ac.signal});
    clearTimeout(t);
    ST=await r.json();
    _failCount=0;
    const banner=document.getElementById('offlineBanner');
    if(banner) banner.hidden=true;
    renderStatus();
  }catch{
    _failCount++;
    if(_failCount>=3){
      const banner=document.getElementById('offlineBanner');
      if(banner) banner.hidden=false;
      ['deps','cert','trust','proxy'].forEach(id=>{
        const el=document.getElementById('ci-'+id);
        if(el){el.className='chk-item warn';el.querySelector('.chk-icon').textContent='○';}
        const d=document.getElementById('ci-'+id+'-d');
        if(d) d.textContent='Server unreachable — refresh the page';
        const a=document.getElementById('ci-'+id+'-a');
        if(a) a.innerHTML='';
      });
    }
  }
}
function renderStatus(){
  const on=ST.proxy_running;
  document.getElementById('dot').className='dot'+(on?' on':'');
  document.getElementById('slabel').textContent=on?'RUNNING':'STOPPED';
  document.getElementById('portLabel').textContent=on?':'+ST.proxy_port:'';
  document.getElementById('startBtn').style.display=on?'none':'';
  document.getElementById('stopBtn').style.display=on?'':'none';

  // OS banner
  const os=ST.os_info||{};
  const sys=os.system||'Unknown';
  const fam=os.pkg_family||'apt';
  const icons={Darwin:'🍎',Windows:'🪟',Linux:'🐧'};
  document.getElementById('osIcon').textContent=icons[sys]||'💻';
  document.getElementById('osLabel').textContent=os.display||sys;

  // manual fallback commands
  const port=ST.proxy_port||8080;
  const py=sys==='Windows'?'python':'python3';
  const pip=sys==='Windows'?'pip':'pip3';
  const certPath=sys==='Windows'?'%USERPROFILE%\\.mitmproxy\\mitmproxy-ca-cert.pem':'~/.mitmproxy/mitmproxy-ca-cert.pem';

  const manDeps=`${pip} install mitmproxy`;

  const manCert=`${py} req_red.py --no-system-proxy\n# Wait a few seconds for the cert to generate, then press Ctrl+C`;

  let manTrust;
  if(sys==='Darwin'){
    manTrust=`sudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain \\\n  ${certPath}`;
  } else if(sys==='Windows'){
    manTrust=`# Run Command Prompt or PowerShell as Administrator:\ncertutil -addstore -f Root "${certPath}"`;
  } else if(fam==='rpm'){
    manTrust=`sudo cp ${certPath} /etc/pki/ca-trust/source/anchors/mitmproxy.crt\nsudo update-ca-trust extract`;
  } else if(fam==='pacman'){
    manTrust=`sudo cp ${certPath} /etc/ca-certificates/trust-source/anchors/mitmproxy.crt\nsudo trust extract-compat`;
  } else {
    manTrust=`sudo cp ${certPath} /usr/local/share/ca-certificates/mitmproxy.crt\nsudo update-ca-certificates`;
  }

  let manProxy;
  if(sys==='Darwin'){
    manProxy=`# Replace "Wi-Fi" with your active network service name\nnetworksetup -setwebproxy "Wi-Fi" 127.0.0.1 ${port}\nnetworksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 ${port}\nnetworksetup -setwebproxystate "Wi-Fi" on\nnetworksetup -setsecurewebproxystate "Wi-Fi" on`;
  } else if(sys==='Windows'){
    manProxy=`# Run in PowerShell:\n$reg = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'\nSet-ItemProperty $reg ProxyEnable 1\nSet-ItemProperty $reg ProxyServer '127.0.0.1:${port}'`;
  } else {
    manProxy=`# GNOME:\ngsettings set org.gnome.system.proxy mode manual\ngsettings set org.gnome.system.proxy.http host 127.0.0.1\ngsettings set org.gnome.system.proxy.http port ${port}\ngsettings set org.gnome.system.proxy.https host 127.0.0.1\ngsettings set org.gnome.system.proxy.https port ${port}\n# KDE / other: set proxy in System Settings → Network → Proxy`;
  }

  // checklist
  const d=ST.deps||{};
  setChk('deps',d.ok,d.ok?'mitmproxy '+d.version:'Not installed',
    d.ok?null:{label:'Install',fn:'installDeps()'},manDeps);
  const ce=ST.cert_exists;
  setChk('cert',ce,ce?String(CERT_PATH||'~/.mitmproxy/mitmproxy-ca-cert.pem'):'Not generated',
    ce?null:{label:'Generate',fn:'genCert()'},manCert);
  const ct=ST.cert_trusted;
  setChk('trust',ct,ct?'Trusted in system keychain':'Not trusted — install via system dialog',
    ct?null:{label:'Install certificate',fn:'installCert()',primary:true},manTrust);
  const sp=ST.system_proxy||{};
  const spOk=on&&sp.enabled;
  setChk('proxy',on?spOk:null,
    on?(sp.enabled?'Active on: '+(sp.services||[]).join(', '):'Running but system proxy not set'):'Start the proxy to activate',
    null,manProxy);
}
function setChk(id,ok,desc,act,manual){
  const el=document.getElementById('ci-'+id);
  el.className='chk-item '+(ok===true?'ok':ok===false?'fail':'warn');
  el.querySelector('.chk-icon').textContent=ok===true?'✓':ok===false?'✗':'○';
  document.getElementById('ci-'+id+'-d').textContent=desc;
  const a=document.getElementById('ci-'+id+'-a');
  // preserve whether the manual details was open before rebuilding
  const wasOpen=a.querySelector('.manual-det')?.open||false;
  const btn=act?`<button class="btn btn-sm ${act.primary?'btn-ac':'btn-ghost'}"
    onclick="${act.fn}">${act.label}</button>`:(ok===true?'<span class="badge bg-gr">OK</span>':'');
  const man=manual?`<details class="manual-det"${wasOpen?' open':''}><summary>Manual command
    <button class="copy-btn" onclick="event.stopPropagation();copyCmd(this)">Copy</button>
    </summary><pre class="manual-pre">${esc(manual)}</pre></details>`:'';
  a.innerHTML=btn+man;
}
async function copyCmd(btn){
  const pre=btn.closest('.manual-det').querySelector('.manual-pre');
  try{
    await navigator.clipboard.writeText(pre.textContent);
    btn.textContent='✓ Copied';setTimeout(()=>btn.textContent='Copy',1800);
  }catch{btn.textContent='Copy';}
}
const CERT_PATH='~/.mitmproxy/mitmproxy-ca-cert.pem';

// ── proxy ──────────────────────────────────────────────────────────────────
async function startProxy(){
  const btn=document.getElementById('startBtn');
  btn.disabled=true;btn.innerHTML='<span class="spinner"></span> Starting…';
  tab('logs');
  try{ await fetch('/api/proxy/start',{method:'POST'}); }catch(e){}
  // poll until running or 10s timeout
  let tries=0;
  const poll=setInterval(async()=>{
    await fetchStatus();
    tries++;
    if(ST.proxy_running||tries>20){clearInterval(poll);btn.disabled=false;btn.textContent='Start';}
  },500);
}
async function stopProxy(){
  const btn=document.getElementById('stopBtn');
  btn.disabled=true;btn.innerHTML='<span class="spinner"></span>';
  try{ await fetch('/api/proxy/stop',{method:'POST'}); }catch(e){}
  setTimeout(()=>{fetchStatus();btn.disabled=false;btn.textContent='Stop';},1000);
}
async function installDeps(){tab('logs');await fetch('/api/deps/install',{method:'POST'})}
async function genCert(){tab('logs');await fetch('/api/cert/generate',{method:'POST'})}
async function installCert(){
  const b=event.target;b.disabled=true;b.innerHTML='<span class="spinner"></span>';
  const r=await(await fetch('/api/cert/install',{method:'POST'})).json();
  await fetchStatus();b.disabled=false;b.textContent='Install certificate';
  if(!r.ok)alert('Failed:\n'+r.msg);
}

// ── rules ──────────────────────────────────────────────────────────────────
async function fetchRules(){try{rules=await(await fetch('/api/rules')).json();renderRules();}catch{}}
function actionColor(t){return{redirect:'bg-ac',block:'bg-re',mock:'bg-or'}[t]||'bg-muted'}
function renderRules(){
  const q=(document.getElementById('rSearch').value||'').toLowerCase();
  const list=q?rules.filter(r=>r.name.toLowerCase().includes(q)||
    (r.match?.url?.value||'').toLowerCase().includes(q)):rules;
  // table
  document.getElementById('rtableBody').innerHTML=list.length?list.map((r,i)=>`
    <div class="rrow ${r.enabled?'':'off'}">
      <div class="rc" style="color:var(--fg3);font-family:var(--mono);font-size:11px">${r.priority??i}</div>
      <div class="rc" style="font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(r.name)}</div>
      <div class="rc"><span class="badge ${actionColor(r.action?.type)}">${r.action?.type||'—'}</span></div>
      <div class="rc"><span class="mchip mc-${r.match?.url?.kind||'exact'}">${r.match?.url?.kind||'exact'}</span></div>
      <div class="rc rc-mono" title="${esc(r.match?.url?.value||'')}">
        <span style="color:var(--am)">${esc(trunc(r.match?.url?.value||'',36))}</span>
        ${r.action?.to?`<br><span style="color:var(--gr)">→ ${esc(trunc(r.action.to,36))}</span>`:''}
      </div>
      <div class="rc" style="display:flex;align-items:center;justify-content:center">
        <label class="tgl"><input type="checkbox" ${r.enabled?'checked':''} onchange="toggleRule('${r.id}')">
          <span class="tgl-tk"></span><span class="tgl-th"></span></label>
      </div>
      <div class="rc rc-acts">
        <button class="btn-icon" onclick="moveRule('${r.id}',-1)" title="Higher priority">↑</button>
        <button class="btn-icon" onclick="moveRule('${r.id}',1)"  title="Lower priority">↓</button>
        <button class="btn-icon" onclick="editRule('${r.id}')"    title="Edit">✎</button>
        <button class="btn-icon" style="color:var(--re)" onclick="delRule('${r.id}')" title="Delete">✕</button>
      </div>
    </div>`).join(''):'<div class="empty">No rules yet — add one above.</div>';
  // mobile cards
  document.getElementById('rcards').innerHTML=list.length?list.map(r=>`
    <div class="rcard ${r.enabled?'':'off'}">
      <div class="rcard-hd">
        <span class="badge ${actionColor(r.action?.type)}">${r.action?.type||'—'}</span>
        <span class="rcard-name">${esc(r.name)}</span>
        <label class="tgl"><input type="checkbox" ${r.enabled?'checked':''} onchange="toggleRule('${r.id}')">
          <span class="tgl-tk"></span><span class="tgl-th"></span></label>
      </div>
      <div class="rcard-urls">
        <span style="color:var(--am)">${esc(trunc(r.match?.url?.value||'',52))}</span>
        ${r.action?.to?`<span style="color:var(--gr)">→ ${esc(trunc(r.action.to,52))}</span>`:''}
      </div>
      <div class="rcard-ft">
        <span class="mchip mc-${r.match?.url?.kind||'exact'}">${r.match?.url?.kind||'exact'}</span>
        ${r.match?.method?`<span class="badge bg-muted">${r.match.method}</span>`:''}
        <button class="btn-icon btn-sm" style="margin-left:auto" onclick="editRule('${r.id}')">✎ edit</button>
        <button class="btn-icon btn-sm" style="color:var(--re)" onclick="delRule('${r.id}')">✕</button>
      </div>
    </div>`).join(''):'<div class="empty">No rules. Add one →</div>';
}
async function toggleRule(id){await fetch('/api/rules/'+id+'/toggle',{method:'PATCH'});fetchRules()}
async function delRule(id){if(!confirm('Delete rule?'))return;await fetch('/api/rules/'+id,{method:'DELETE'});fetchRules()}
async function moveRule(id,dir){
  const idx=rules.findIndex(r=>r.id===id);if(idx<0)return;
  const p=rules[idx].priority??idx;
  await fetch('/api/rules/'+id+'/priority',{method:'PATCH',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({priority:p+dir})});
  fetchRules();
}

// ── modal ───────────────────────────────────���──────────────────────────────
function openModal(r=null){
  editId=r?r.id:null;
  document.getElementById('mTitle').textContent=r?'Edit rule':'Add rule';
  document.getElementById('mId').value=r?.id||'';
  document.getElementById('mName').value=r?.name||'';
  document.getElementById('mAction').value=r?.action?.type||'redirect';
  document.getElementById('mKind').value=r?.match?.url?.kind||'exact';
  document.getElementById('mMethod').value=r?.match?.method||'';
  document.getElementById('mTarget').value=r?.match?.url?.value||'';
  document.getElementById('mGqlOp').value=r?.match?.graphql?.operationName||'';
  document.getElementById('mGqlKey').value=r?.match?.graphql?.payloadKey||'';
  document.getElementById('mGqlVal').value=r?.match?.graphql?.payloadValue||'';
  document.getElementById('mTo').value=r?.action?.to||'';
  document.getElementById('mStatus').value=r?.action?.status||200;
  document.getElementById('mDelay').value=r?.action?.delayMs||0;
  document.getElementById('mBodyMode').value=r?.action?.bodyMode||'static';
  document.getElementById('mBody').value=r?.action?.body||'';
  document.getElementById('mScript').value=r?.action?.script||'';
  document.getElementById('mEnabled').checked=r?.enabled??true;
  // headers
  const hdrs=r?.action?.headers||{};
  document.getElementById('hdrList').innerHTML='';
  Object.entries(hdrs).forEach(([k,v])=>addHeader(k,v));
  onActionChange(); onBodyModeChange();
  document.getElementById('modal').classList.add('open');
}
function editRule(id){openModal(rules.find(r=>r.id===id))}
function closeModal(){editId=null;document.getElementById('modal').classList.remove('open')}
function onActionChange(){
  const t=document.getElementById('mAction').value;
  document.getElementById('rSection').style.display=t==='redirect'?'block':'none';
  document.getElementById('mockSection').style.display=t==='mock'?'flex':'none';
}
function onBodyModeChange(){
  const m=document.getElementById('mBodyMode').value;
  document.getElementById('bodyStatic').style.display=m==='static'?'':'none';
  document.getElementById('bodyDynamic').style.display=m==='dynamic'?'':'none';
}
function addHeader(k='',v=''){
  const row=document.createElement('div');row.className='hdr-row';
  row.innerHTML=`<input class="finp" placeholder="Content-Type" value="${esc(k)}">
    <input class="finp" placeholder="application/json" value="${esc(v)}">
    <button class="btn-icon" style="color:var(--re)" onclick="this.parentElement.remove()">✕</button>`;
  document.getElementById('hdrList').appendChild(row);
}
async function saveRule(){
  const id=document.getElementById('mId').value;
  const atype=document.getElementById('mAction').value;
  const hdrs={};
  document.querySelectorAll('#hdrList .hdr-row').forEach(row=>{
    const [ki,vi]=row.querySelectorAll('input');
    if(ki.value.trim()) hdrs[ki.value.trim()]=vi.value.trim();
  });
  const body={
    name:document.getElementById('mName').value.trim()||'rule',
    enabled:document.getElementById('mEnabled').checked,
    match:{
      url:{kind:document.getElementById('mKind').value,
           value:document.getElementById('mTarget').value.trim()},
      method:document.getElementById('mMethod').value||null,
      graphql:{
        operationName:document.getElementById('mGqlOp').value.trim()||null,
        payloadKey:document.getElementById('mGqlKey').value.trim()||null,
        payloadValue:document.getElementById('mGqlVal').value.trim()||null,
      }
    },
    action:{type:atype,
      ...(atype==='redirect'?{to:document.getElementById('mTo').value.trim()}:{}),
      ...(atype==='mock'?{
        status:parseInt(document.getElementById('mStatus').value)||200,
        delayMs:parseInt(document.getElementById('mDelay').value)||0,
        headers:hdrs,
        bodyMode:document.getElementById('mBodyMode').value,
        body:document.getElementById('mBody').value,
        script:document.getElementById('mScript').value,
      }:{}),
    }
  };
  if(!body.match.url.value){alert('Target URL is required.');return}
  const url=id?'/api/rules/'+id:'/api/rules';
  await fetch(url,{method:id?'PUT':'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  closeModal(); fetchRules();
}

// ── import / export ────────────────────────────────────────────────────────
function openImport(){importData=null;document.getElementById('importBtn').disabled=true;
  document.getElementById('importModal').classList.add('open')}
function closeImport(){document.getElementById('importModal').classList.remove('open')}
function exportRules(){
  const d={version:1,rules};
  const a=document.createElement('a');
  a.href='data:application/json,'+encodeURIComponent(JSON.stringify(d,null,2));
  a.download='req-red-rules.json'; a.click();
}
function handleFile(inp){const f=inp.files[0];if(f)readFile(f)}
function handleDrop(e){e.preventDefault();e.currentTarget.classList.remove('drag');
  const f=e.dataTransfer.files[0];if(f)readFile(f)}
function readFile(f){
  const r=new FileReader();
  r.onload=e=>{
    try{importData=JSON.parse(e.target.result);
      document.getElementById('importBtn').disabled=false;
      document.getElementById('dropZone').innerHTML=
        `<div style="font-size:20px;margin-bottom:6px">✓</div><div style="color:var(--gr)">${f.name} — ${importData.rules?.length||0} rules</div>`;
    }catch{alert('Invalid JSON file.')}
  };r.readAsText(f);
}
async function doImport(){
  if(!importData)return;
  const mode=document.getElementById('importMode').value;
  await fetch('/api/rules/import',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({mode,rules:importData.rules||importData})});
  closeImport(); fetchRules();
}

// ── request log ────────────────────────────────────────────────────────────
function renderReqs(){
  const q=(document.getElementById('reqFilter').value||'').toLowerCase();
  const list=q?reqs.filter(r=>(r.url||'').toLowerCase().includes(q)):reqs;
  const el=document.getElementById('reqList');
  if(!list.length){el.innerHTML='<div class="empty">No intercepted requests yet.</div>';return}
  el.innerHTML=list.map((r,i)=>`
    <div class="req-item" onclick="this.classList.toggle('expanded')">
      <div class="req-method m-${r.method||'OTHER'}">${r.method||'—'}</div>
      <div>
        <div class="req-url">${esc(r.url||'')}</div>
        <div class="req-meta">
          <span class="badge ${actionColor(r.action)}" style="font-size:9px">${r.action||'—'}</span>
          ${r.rule_name?`<span style="color:var(--fg2);font-size:11px;margin-left:6px">${esc(r.rule_name)}</span>`:''}
          ${r.status?`<span class="badge bg-muted" style="margin-left:4px">${r.status}</span>`:''}
        </div>
      </div>
      <div class="req-ts">${fmtTs(r.ts)}</div>
      <div class="req-detail">${JSON.stringify(r,null,2)}</div>
    </div>`).join('');
}
function clearReqs(){reqs=[];renderReqs()}
function fmtTs(ts){if(!ts)return'';const d=new Date(ts);return d.toLocaleTimeString()}

// ── logs ───────────────────────────────────────────────────────────────────
function renderLogs(){
  const q=(document.getElementById('logFilter').value||'').toLowerCase();
  const box=document.getElementById('logBox');
  const list=q?logs.filter(l=>l.msg.toLowerCase().includes(q)):logs;
  box.innerHTML=list.length?list.map(l=>
    `<div class="log-line"><span class="lts">${l.t}</span><span class="lmsg ${l.tag||''}">${esc(l.msg)}</span></div>`
  ).join(''):'<span style="color:#3d444d">No output yet.</span>';
  if(document.getElementById('autoScroll').checked) box.scrollTop=box.scrollHeight;
}
function clearLogs(){logs=[];renderLogs()}

// ── SSE ────────────────────────────────────────────────────────────────────
function sse(url, onMsg){
  let es=null;
  function connect(){
    if(es){try{es.close()}catch{} es=null;}
    es=new EventSource(url);
    es.onmessage=e=>{try{const d=JSON.parse(e.data);if(!d.ping)onMsg(d);}catch{}};
    es.onerror=()=>{try{es.close()}catch{} es=null; setTimeout(connect,4000);};
  }
  connect();
}
sse('/api/logs',e=>{logs.push(e);if(logs.length>800)logs.shift();renderLogs()});
sse('/api/requests',e=>{reqs.unshift(e);if(reqs.length>200)reqs.pop();renderReqs()});

// ── utils ──────────────────────────────────────────────────────────────────
function esc(s){const d=document.createElement('div');d.textContent=String(s);return d.innerHTML}
function trunc(s,n){return s.length>n?s.slice(0,n)+'…':s}

// ── init ───────────────────────────────────────────────────────────────────
fetchRules();
// staggered status checks: 0.5s, 1.5s, 3s, then every 3s
setTimeout(fetchStatus, 500);
setTimeout(fetchStatus, 1500);
setTimeout(()=>{ fetchStatus(); setInterval(fetchStatus,3000); }, 3000);
</script>
</body></html>"""

@app.route("/")
def index(): return HTML

# ── boot ───────────────────────────────────────────────────────────────────────
def _open_browser():
    time.sleep(1.2)
    url=f"http://localhost:{UI_PORT}"
    if SYSTEM=="Darwin": subprocess.run(["open","-n",url])
    elif SYSTEM=="Windows": subprocess.run(["start",url],shell=True)
    else: subprocess.run(["xdg-open",url])

if __name__=="__main__":
    _emit(f"req-red UI → http://localhost:{UI_PORT}","ok")
    _emit(f"Platform: {SYSTEM}  |  Python: {sys.version.split()[0]}","info")
    threading.Thread(target=_open_browser,daemon=True).start()
    app.run(host="0.0.0.0",port=UI_PORT,debug=False,threaded=True)
