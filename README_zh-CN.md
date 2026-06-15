# VLESS 订阅转 sing-box

[English](README.md) | **中文**

### 使用示例
1. 使用 `vless_to_singbox` 默认命令生成配置文件config.json
2. 使用 `proxy_settings` 默认命令修改配置为自动分流
3. 直接给 sing-box 导入 `config.json` 或 在命令行: ```python run_singbox_auto.py```

> 注: 本工具目前只支持 sing-box 1.13
----------

转换器本身仅依赖 Python 标准库。`proxy_settings.py` 使用 PyYAML 读取桌面进程规则。生成的配置在 `127.0.0.1:<listen_port>`（默认 `2808`，由 `proxy_rules.yaml` 的 `listen_port` 决定）暴露 SOCKS/HTTP 混合代理，并将所有 VLESS 节点放入 `proxy` 选择器。该端口以 `proxy_rules.yaml` 为唯一来源，`proxy_settings.py`、`run_singbox_auto.py`、`check_ai_connectivity.py` 均从中读取。

```powershell
# 从订阅 URL 生成 config.json
python vless_to_singbox.py "https://example.com/subscription"

# 自动分流：国内/局域网直连，其余流量走 VLESS（系统代理，无需管理员）
python proxy_settings.py

# 启动 sing-box（auto 模式，v2rayN 风格系统代理）
python run_singbox_auto.py

# 关闭系统流量接管，所有系统流量直连
python proxy_settings.py --mode off

# 全局 TUN 代理（私有/局域网地址除外，需管理员）
python proxy_settings.py --mode global

# 自定义模式：仅指定域名走 VLESS
python proxy_settings.py --mode custom --proxy-domain google.com --proxy-domain youtube.com

# 自动从 proxy_rules.yaml 加载桌面进程规则
python proxy_settings.py

# 使用其他进程规则文件
python proxy_settings.py --rules-file my-rules.yaml

# 使用其他配置文件
python proxy_settings.py another-config.json --mode auto

# 验证 AI 服务是否经系统代理可达
python check_ai_connectivity.py --mode system
```

启动器会在各种退出路径（正常退出、Ctrl+C、关闭控制台窗口、注销/关机）下清理系统代理，并在下次启动时自动清除上次崩溃残留的代理。若被 `taskkill /F` 硬强杀导致代理仍开启，可用 `python run_singbox_auto.py --cleanup` 恢复。

默认输出为 `config.json`。仅在需要其他输出路径时使用 `-o`：

```powershell
python vless_to_singbox.py "订阅 URL" -o another-config.json
```

`proxy_settings.py` 保持混合代理监听 `127.0.0.1:<listen_port>`（默认 `2808`）。**auto（默认）** 通过 `run_singbox_auto.py` 设置 v2rayN 风格的 Windows 系统代理（`<local>` + 私有网段 bypass、拨号连接），无需 TUN/管理员权限；使用 SagerNet 中国域名/IP 规则集分流，DNS 同样分流。由于系统代理经 WinInet 设置，使用 Chromium 网络栈的桌面应用（Cursor、Claude 桌面版、ChatGPT/Codex 桌面版、浏览器）会自动走代理，无需环境变量或 TUN；而不读取 Windows 系统代理的命令行工具仍需设置 `HTTPS_PROXY`/`HTTP_PROXY`。**global/tun** 启用 TUN 透明代理，代理所有非私有流量，需管理员权限。自定义模式仅代理选定域名，不启用系统代理或 TUN。

桌面应用可通过 `proxy_rules.yaml` 中的可执行文件名覆盖上述规则，其 DNS 同样遵循该覆盖。示例：

```yaml
direct_process:
  - WeChat.exe
  - QQ.exe
proxy_process:
  - chrome.exe
```

`proxy_settings.py` 每次运行都会读取该文件并替换生成的进程规则。使用 `--rules-file` 可指定其他 YAML 文件。需要安装 PyYAML（`python -m pip install PyYAML`）。原配置文件会备份为 `<配置名>.bak`。global 模式下代理服务器地址会从 TUN 路由中排除，以避免路由环路。

### 辅助脚本

- `run_singbox_auto.py` —— auto 模式启动器。从 `proxy_rules.yaml` 读取 `listen_port`，校验其与 `config.json` 混合入站端口一致（不一致则提示重跑 `proxy_settings.py`），自动清除上次崩溃残留的代理，开启 Windows 系统代理，运行 `sing-box run -c config.json`，并在各种退出路径（正常退出、Ctrl+C、关闭控制台窗口、注销/关机）下还原系统代理。参数：`--sing-box`、`--rules-file`、`--bypass`、`--no-local-bypass`、`--cleanup`（清除系统代理并退出，用于硬强杀后的恢复）。
- `wininet_system_proxy.py` —— 仅 Windows 的库,供启动器调用。按 v2rayN 的方式通过 WinInet API 设置/清除系统代理（`ProxyServer`、含 `<local>` + 私有网段的 `ProxyOverride`、RAS 拨号连接）。无需直接运行。
- `check_ai_connectivity.py` —— Cursor/OpenAI/Anthropic 端点诊断。`--mode system` 测当前 Windows 系统代理，`--mode proxy` 直接测混合端口，`--mode direct`/`both` 做对比。`proxy`/`system` 模式会自动跳过直连 TCP 预检——因为对被墙 IP 直连必然失败,即使代理正常。

推荐顺序：`vless_to_singbox.py` → `proxy_settings.py --mode auto` → `run_singbox_auto.py`。

支持的传输协议：TCP、WebSocket、gRPC、HTTP/H2、HTTPUpgrade 和 QUIC。TLS、Reality、uTLS 指纹、Vision 流控、ALPN、跳过证书校验、WebSocket early data 以及 XUDP/packetaddr 在订阅中存在时会自动映射。
