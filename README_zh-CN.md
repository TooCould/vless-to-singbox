# VLESS 订阅转 sing-box

[English](README.md) | **中文**

### 使用示例
1. 使用 `vless_to_singbox` 默认命令生成配置文件config.json
2. 使用 `proxy_settings` 默认命令修改配置为自动分流
3. 直接给 sing-box 导入 `config.json` 或 在命令行: ```sing-box run -c config.json```

> 注: 本工具目前只支持 sing-box 1.13
----------

转换器本身仅依赖 Python 标准库。`proxy_settings.py` 使用 PyYAML 读取桌面进程规则。生成的配置在 `127.0.0.1:2080` 暴露 SOCKS/HTTP 混合代理，并将所有 VLESS 节点放入 `proxy` 选择器。

```powershell
# 从订阅 URL 生成 config.json
python vless_to_singbox.py "https://example.com/subscription"

# 自动分流：国内/局域网直连，其余流量走 VLESS
python proxy_settings.py

# 以管理员身份启动 sing-box
sing-box run -c config.json

# 关闭系统流量接管，所有系统流量直连
python proxy_settings.py --mode off

# 全局 TUN 代理（私有/局域网地址除外）
python proxy_settings.py --mode global

# 自定义模式：仅指定域名走 VLESS
python proxy_settings.py --mode custom --proxy-domain google.com --proxy-domain youtube.com

# 自动从 proxy_rules.yaml 加载桌面进程规则
python proxy_settings.py

# 使用其他进程规则文件
python proxy_settings.py --rules-file my-rules.yaml

# 使用其他配置文件
python proxy_settings.py another-config.json --mode auto

# 启用 Windows 系统代理（127.0.0.1:2080）
.\system_proxy.cmd

# 关闭或查看系统代理状态
.\system_proxy.cmd disable
.\system_proxy.cmd status
```

停止 sing-box 前请先关闭系统代理，否则应用可能在 sing-box 退出后仍尝试连接本地代理端口。

默认输出为 `config.json`。仅在需要其他输出路径时使用 `-o`：

```powershell
python vless_to_singbox.py "订阅 URL" -o another-config.json
```

系统代理脚本会修改当前 Windows 用户的 HTTP/HTTPS 代理设置。不遵循 Windows 代理设置的应用需单独配置。本地及私有 IPv4 地址会排除在系统代理之外。

`proxy_settings.py` 保持混合代理监听 `127.0.0.1:2080`。自动模式使用 SagerNet 的中国域名/IP 规则集：国内及私有/局域网流量直连，其余走 VLESS，DNS 同样分流。全局模式代理所有非私有流量，自定义模式仅代理选定域名。自动模式下，中国 IP 段在 Windows TUN 路由层排除，提升对监控网卡变化的桌面应用的兼容性。自动模式还会关闭严格 TUN 路由，使直连桌面应用可继续使用物理网卡的 UDP/P2P 套接字。

桌面应用可通过 `proxy_rules.yaml` 中的可执行文件名覆盖上述规则，其 DNS 同样遵循该覆盖。示例：

```yaml
direct_process:
  - WeChat.exe
  - QQ.exe
proxy_process:
  - chrome.exe
```

`proxy_settings.py` 每次运行都会读取该文件并替换生成的进程规则。使用 `--rules-file` 可指定其他 YAML 文件。需要安装 PyYAML（`python -m pip install PyYAML`）。原配置文件会备份为 `<配置名>.bak`。代理服务器地址会从 TUN 路由中排除，以避免路由环路。

支持的传输协议：TCP、WebSocket、gRPC、HTTP/H2、HTTPUpgrade 和 QUIC。TLS、Reality、uTLS 指纹、Vision 流控、ALPN、跳过证书校验、WebSocket early data 以及 XUDP/packetaddr 在订阅中存在时会自动映射。
