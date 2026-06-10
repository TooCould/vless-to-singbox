# VLESS subscription to sing-box

**English** | [中文](README_zh-CN.md)

### Usage example

1. Run `vless_to_singbox` with its default command to generate `config.json`.
2. Run `proxy_settings` with its default command to enable automatic routing split.
3. Import `config.json` into sing-box directly, or from the command line: `sing-box run -c config.json`

> Note: This tool currently supports sing-box 1.13 only.

----------

The converter itself uses only Python's standard library. `proxy_settings.py`
uses PyYAML to read desktop process rules. The generated config exposes a
SOCKS/HTTP mixed proxy at `127.0.0.1:2080` and puts all VLESS nodes in a
`proxy` selector.

```powershell
# Generate config.json from a subscription URL
python vless_to_singbox.py "https://example.com/subscription"

# Automatic routing: China/LAN direct, other traffic through VLESS
python proxy_settings.py

# Start sing-box from an Administrator terminal
sing-box run -c config.json

# Disable system traffic capture; all system traffic is direct
python proxy_settings.py --mode off

# Global TUN proxy except private/LAN addresses
python proxy_settings.py --mode global

# Custom mode: only selected domains use VLESS
python proxy_settings.py --mode custom --proxy-domain google.com --proxy-domain youtube.com

# Desktop process rules are loaded automatically from proxy_rules.yaml
python proxy_settings.py

# Use another process rules file
python proxy_settings.py --rules-file my-rules.yaml

# Use another config file
python proxy_settings.py another-config.json --mode auto

# Enable Windows system proxy at 127.0.0.1:2080
.\system_proxy.cmd

# Disable or inspect the system proxy
.\system_proxy.cmd disable
.\system_proxy.cmd status
```

Disable the system proxy before stopping sing-box, otherwise applications may
keep trying to connect to the local proxy port after sing-box exits.

The default output is `config.json`. Use `-o` only when another output path is
needed:

```powershell
python vless_to_singbox.py "subscription URL" -o another-config.json
```

The system proxy script changes the current Windows user's HTTP/HTTPS proxy.
Applications that ignore Windows proxy settings must be configured separately.
Local and private IPv4 addresses are excluded from the system proxy.

`proxy_settings.py` keeps the mixed proxy at `127.0.0.1:2080`. Automatic mode
uses SagerNet's China domain/IP rule sets: China and private/LAN traffic is
direct, while other traffic uses VLESS. DNS follows the same split. Global mode
proxies all non-private traffic, and custom mode proxies only selected domains.
In automatic mode, Chinese IP ranges are excluded at the Windows TUN routing
layer, improving compatibility with desktop applications that monitor network
adapter changes. Automatic mode also disables strict TUN routing so direct
desktop applications can keep using physical-interface UDP/P2P sockets.
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
The original file is backed up once as `<config name>.bak`. Proxy server
addresses are excluded from TUN routes to prevent a routing loop.

Supported transports: TCP, WebSocket, gRPC, HTTP/H2, HTTPUpgrade, and QUIC.
TLS, Reality, uTLS fingerprints, Vision flow, ALPN, insecure certificates,
WebSocket early data, and XUDP/packetaddr are mapped when present.
