# VLESS subscription to sing-box

**English** | [中文](README_zh-CN.md)

### Usage example

1. Run `vless_to_singbox` with its default command to generate `config.json`.
2. Run `proxy_settings` with its default command to enable automatic routing split.
3. Import `config.json` into sing-box directly, or from the command line: `python run_singbox_auto.py`

> Note: This tool currently supports sing-box 1.13 only.

----------

The converter itself uses only Python's standard library. `proxy_settings.py`
uses PyYAML to read desktop process rules. The generated config exposes a
SOCKS/HTTP mixed proxy at `127.0.0.1:<listen_port>` (default `2808`, set by
`listen_port` in `proxy_rules.yaml`) and puts all VLESS nodes in a `proxy`
selector. The port is read from `proxy_rules.yaml` as the single source of
truth by `proxy_settings.py`, `run_singbox_auto.py`, and
`check_ai_connectivity.py`.

```powershell
# Generate config.json from a subscription URL
python vless_to_singbox.py "https://example.com/subscription"

# Automatic routing: China/LAN direct, other traffic through VLESS (system proxy, no admin)
python proxy_settings.py

# Start sing-box with v2rayN-aligned Windows system proxy (auto mode)
python run_singbox_auto.py

# Disable system traffic capture; all system traffic is direct
python proxy_settings.py --mode off

# Global TUN proxy except private/LAN addresses (requires Administrator)
python proxy_settings.py --mode global

# Custom mode: only selected domains use VLESS
python proxy_settings.py --mode custom --proxy-domain google.com --proxy-domain youtube.com

# Desktop process rules are loaded automatically from proxy_rules.yaml
python proxy_settings.py

# Use another process rules file
python proxy_settings.py --rules-file my-rules.yaml

# Use another config file
python proxy_settings.py another-config.json --mode auto

# Verify AI services are reachable through the system proxy
python check_ai_connectivity.py --mode system
```

The launcher clears the system proxy on every exit path (normal exit, Ctrl+C,
closing the console window, logoff/shutdown) and also auto-clears a leftover
proxy from a previous crashed run on the next start. If a hard kill
(`taskkill /F`) still leaves the proxy enabled, recover with
`python run_singbox_auto.py --cleanup`.

The default output is `config.json`. Use `-o` only when another output path is
needed:

```powershell
python vless_to_singbox.py "subscription URL" -o another-config.json
```

`proxy_settings.py` keeps the mixed proxy at `127.0.0.1:<listen_port>` (default
`2808`). **auto (default)** uses `run_singbox_auto.py` for v2rayN-style Windows
system proxy split routing (`<local>` + private-network bypass, dial-up
connections)—no TUN or admin required—and SagerNet China domain/IP rule sets
with matching DNS split. Because the system proxy is set via WinInet, desktop
applications that use the Chromium network stack (Cursor, Claude Desktop,
ChatGPT/Codex Desktop, browsers) go through the proxy automatically; no
environment variables or TUN are needed. Command-line tools that ignore the
Windows system proxy would still need `HTTPS_PROXY`/`HTTP_PROXY`.
**global/tun** enables TUN transparent proxy for all non-private traffic and
requires Administrator. Custom mode proxies only selected domains without
system proxy or TUN.
Desktop applications override these rules by executable name in
`proxy_rules.yaml`; their DNS follows the same override. Example:

```yaml
direct_process:
  - WeChat.exe
  - QQ.exe
proxy_process:
  - chrome.exe
```

`proxy_settings.py` reads this file every time and replaces the generated
process rules. Use `--rules-file` to select another YAML file. PyYAML is
required (`python -m pip install PyYAML`).
The original file is backed up once as `<config name>.bak`. In global mode,
proxy server addresses are excluded from TUN routes to prevent a routing loop.

### Helper scripts

- `run_singbox_auto.py` — launcher for auto mode. Reads `listen_port` from
  `proxy_rules.yaml`, verifies it matches the mixed inbound in `config.json`
  (re-run `proxy_settings.py` if they differ), auto-clears any leftover proxy
  from a previous crashed run, enables the Windows system proxy, runs
  `sing-box run -c config.json`, and restores the system proxy on every exit
  path (normal exit, Ctrl+C, console-window close, logoff/shutdown). Options:
  `--sing-box`, `--rules-file`, `--bypass`, `--no-local-bypass`, and `--cleanup`
  (clear the system proxy and exit, to recover from a hard kill).
- `wininet_system_proxy.py` — Windows-only library used by the launcher. Sets
  and clears the system proxy through the WinInet API the same way v2rayN does
  (`ProxyServer`, `ProxyOverride` with `<local>` + private ranges, RAS dial-up
  connections). Not run directly.
- `check_ai_connectivity.py` — diagnostic for Cursor/OpenAI/Anthropic endpoints.
  `--mode system` tests the current Windows system proxy, `--mode proxy` tests
  the mixed port directly, `--mode direct`/`both` compare. The direct TCP
  pre-check is auto-skipped in `proxy`/`system` modes, since dialing a blocked IP
  directly would fail even when the proxy works.

Typical order: `vless_to_singbox.py` → `proxy_settings.py --mode auto` →
`run_singbox_auto.py`.

Supported transports: TCP, WebSocket, gRPC, HTTP/H2, HTTPUpgrade, and QUIC.
TLS, Reality, uTLS fingerprints, Vision flow, ALPN, insecure certificates,
WebSocket early data, and XUDP/packetaddr are mapped when present.
