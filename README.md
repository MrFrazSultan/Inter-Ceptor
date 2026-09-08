# Interceptor — Cross-Platform HTTPS Proxy Interceptor

**Interceptor** is a developer tool that lets you intercept, redirect, block, and mock HTTPS traffic system-wide — without touching your app's code. It runs a local [mitmproxy](https://mitmproxy.org) instance, sets your system proxy automatically, and gives you a clean web UI to manage rules in real time.

Works on **macOS**, **Windows**, and **Linux**.

![Status: Active](https://img.shields.io/badge/status-active-brightgreen)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-blue)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## What You Can Do

- **Redirect** any HTTPS request to a different URL (swap prod → staging, mock a CDN, reroute an API)
- **Block** requests outright — returns a 403 JSON response
- **Mock** a response with custom status code, headers, and body (static or dynamically generated via Node.js script)
- Target traffic by **exact URL, contains, starts/ends with, wildcard, regex, or domain** pattern
- Match on **HTTP method** (GET, POST, etc.) or **GraphQL operation name / payload key**
- All other traffic passes through as a **blind TCP tunnel — zero interception**, zero breakage for apps not in your rules

---

## Why Interceptor?

Most proxy tools intercept everything. That breaks services that pin certificates (Slack, Dropbox, etc.) and slows everything down. Interceptor only MITM's the specific hosts you target — everything else is an opaque TCP tunnel.

| Feature | Interceptor | Charles | mitmproxy CLI |
|---|---|---|---|
| Web UI | ✅ | ✅ | ❌ |
| Selective MITM (rules-only) | ✅ | ❌ | ❌ |
| Auto system proxy on/off | ✅ | ✅ | ❌ |
| Mock with dynamic script | ✅ | ❌ | ❌ |
| GraphQL matching | ✅ | ❌ | ❌ |
| macOS + Windows + Linux | ✅ | ✅ | ✅ |
| Free & open source | ✅ | ❌ | ✅ |

---

## Requirements

| Requirement | macOS | Windows | Linux |
|---|---|---|---|
| Python 3.8+ | ✅ | ✅ | ✅ |
| mitmproxy (auto-installed) | ✅ | ✅ | ✅ |
| Node.js (optional — dynamic mocks only) | ✅ | ✅ | ✅ |
| Admin/sudo for cert install | `osascript` prompts | Run as Administrator | `sudo` |

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/MrFrazSultan/Inter-Ceptor.git
cd Inter-Ceptor
```

### 2. Start the web UI

```bash
python3 server.py
```

On Windows:

```bash
python server.py
```

This automatically opens `http://localhost:4750` in your browser.

### 3. Install the CA Certificate

The first time the proxy runs, mitmproxy generates a CA certificate. You need to trust it so your browser accepts intercepted HTTPS responses.

In the **Setup** tab, click **Install Certificate**. Or run:

```bash
python3 req_red.py --install-cert
```

#### Platform-specific certificate trust

**macOS** — installs to System keychain via `osascript` (prompts for your password)

**Windows** — run a terminal as Administrator, then:
```cmd
certutil -addstore -f Root %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.pem
```
Or use the Install Certificate button in the UI.

**Linux (Debian/Ubuntu)**:
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

**Linux (Fedora/RHEL/Arch)**:
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /etc/pki/ca-trust/source/anchors/mitmproxy.crt
sudo update-ca-trust extract
```

**Firefox** — Firefox uses its own certificate store. Go to `about:preferences#privacy` → **Certificates** → **View Certificates** → **Authorities** → **Import** → select `~/.mitmproxy/mitmproxy-ca-cert.pem`.

**Chrome / Edge / Safari** — trust the system certificate store automatically once you install it above.

---

### 4. Add a Rule

Go to the **Rules** tab → **New Rule**. Set:
- **Pattern**: the URL or domain to intercept (e.g. `https://api.example.com/v1/data`)
- **Match type**: exact, contains, startswith, endswith, wildcard, regex, or domain
- **Action**: redirect → enter target URL, block, or mock → enter response body

### 5. Start the Proxy

Click **Start** in the UI. The proxy starts on a free port, sets your system proxy automatically, and begins intercepting traffic matching your rules. Everything else tunnels through untouched.

### 6. Stop

Click **Stop** or press `Ctrl+C`. The system proxy is restored automatically on all platforms.

---

## System Proxy Management

Interceptor sets and clears the system proxy automatically.

| Platform | Method |
|---|---|
| macOS | `networksetup` — sets HTTP + HTTPS proxy on all active network services |
| Windows | Windows registry (`HKCU\...\Internet Settings`) + `ie4uinit.exe` refresh |
| Linux (GNOME) | `gsettings` — sets `org.gnome.system.proxy` to manual mode |
| Linux (KDE/other) | Set `HTTP_PROXY` / `HTTPS_PROXY` environment variables manually |

---

## Rule Examples

### Redirect a production API to local dev

```json
{
  "match": { "url": { "kind": "startswith", "value": "https://api.myapp.com/" } },
  "action": { "type": "redirect", "to": "http://localhost:3000/" }
}
```

### Block all analytics calls

```json
{
  "match": { "url": { "kind": "contains", "value": "analytics.google.com" } },
  "action": { "type": "block" }
}
```

### Mock a specific endpoint

```json
{
  "match": { "url": { "kind": "exact", "value": "https://api.example.com/user/me" } },
  "action": {
    "type": "mock",
    "status": 200,
    "headers": { "Content-Type": "application/json" },
    "body": "{\"id\": 42, \"name\": \"Test User\", \"plan\": \"pro\"}"
  }
}
```

### Dynamic mock with Node.js script

```json
{
  "match": { "url": { "kind": "domain", "value": "api.example.com" } },
  "action": {
    "type": "mock",
    "status": 200,
    "bodyMode": "dynamic",
    "script": "function modifyResponse(req) { return { url: req.url, ts: Date.now() }; }"
  }
}
```

### Match by GraphQL operation

```json
{
  "match": {
    "url": { "kind": "contains", "value": "graphql" },
    "method": "POST",
    "graphql": { "operationName": "GetUser" }
  },
  "action": { "type": "block" }
}
```

---

## Rule Schema

```json
{
  "id": "unique-id",
  "name": "Human readable name",
  "enabled": true,
  "priority": 0,
  "match": {
    "url": {
      "kind": "exact | contains | startswith | endswith | wildcard | regex | domain",
      "value": "pattern"
    },
    "method": "GET | POST | PUT | DELETE | PATCH | ...",
    "graphql": {
      "operationName": "optional operation name",
      "payloadKey": "optional dot-path into request body",
      "payloadValue": "optional expected value"
    }
  },
  "action": {
    "type": "redirect | block | mock",
    "to": "https://target-url.com",
    "status": 200,
    "headers": {},
    "body": "response body string",
    "bodyMode": "static | dynamic",
    "script": "function modifyResponse(req) { ... }",
    "delayMs": 0
  }
}
```

Rules are stored in `rules.json` in the project directory and hot-reloaded on each proxy start.

---

## How It Works

```
Browser / App
     │
     ▼ (system HTTP/HTTPS proxy → 127.0.0.1:808x)
Interceptor (mitmproxy)
     │
     ├── URL matches a rule? ──► Apply action (redirect / block / mock)
     │
     └── No match? ──────────► Blind TCP tunnel (no MITM, cert never presented)
```

- `server.py` — Flask web server on port 4750, manages the proxy subprocess
- `req_red.py` — mitmproxy addon; loads rules, matches requests, applies actions, emits structured log lines
- `rules.json` — rule storage

Only the hosts referenced in your active rules are added to mitmproxy's `allow_hosts` list. Every other host gets a raw TCP tunnel — the proxy never presents its certificate, so no TLS errors, no cert-pinning failures.

---

## Running Standalone (No Web UI)

```bash
python3 req_red.py                    # start with system proxy
python3 req_red.py --no-system-proxy  # start without touching proxy settings
python3 req_red.py --install-cert     # install CA cert and exit
python3 req_red.py --unset-proxy      # disable system proxy and exit
```

---

## Importing & Exporting Rules

Use the **Rules** tab → **Export** to download `rules.json`. Import via the **Import** button or by replacing the file directly. Rules are plain JSON — easy to version-control or share across machines.

---

## Troubleshooting

**Browser shows "Your connection is not private"**
→ The CA certificate isn't trusted yet. Go to **Setup** tab and click **Install Certificate**.

**Proxy starts but requests aren't intercepted**
→ Check that your rule's pattern actually matches the URL. Use the **Requests** tab to see what's flowing through.

**Some apps still fail when proxy is running**
→ Those apps use certificate pinning. Interceptor deliberately does not MITM any host not in your rules, but if a pinned app explicitly refuses the proxy connection, add its domain to a block rule so it fails fast, or use `--no-system-proxy` and configure only the target app manually.

**Windows: proxy isn't applied after starting**
→ Some Windows apps require a process restart to pick up proxy registry changes. Internet Explorer / Edge apply the change immediately. Chrome may need to be restarted.

**Linux: system proxy not set (non-GNOME desktop)**
→ KDE, XFCE, and others don't use gsettings. Set the proxy manually in your desktop's network settings, or export environment variables:
```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

**`mitmproxy` install fails**
→ Try: `pip3 install mitmproxy` or `pip3 install --break-system-packages mitmproxy`

---

## Contributing

Pull requests are welcome. To add a new match type, edit `_url_matches()` in `req_red.py`. To add a new action type, add a handler alongside `_do_redirect`, `_do_block`, `_do_mock` and wire it into `ReqRedAddon.request()`.

---

## License

MIT — use it, fork it, ship it.
