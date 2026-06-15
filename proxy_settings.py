#!/usr/bin/env python3
"""Configure sing-box system proxy routing modes for Windows."""

from __future__ import annotations

import argparse
import ipaddress
import json
import ntpath
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the local Python installation
    yaml = None


class ConfigError(ValueError):
    pass


DEFAULT_RULES_PATH = Path(__file__).with_name("proxy_rules.yaml")

# Fallback when proxy_rules.yaml omits listen_port.
DEFAULT_LISTEN_PORT = 2808


MIXED_INBOUND = {
    "type": "mixed",
    "tag": "mixed-in",
    "listen": "127.0.0.1",
    "listen_port": DEFAULT_LISTEN_PORT,
}

TUN_INBOUND = {
    "type": "tun",
    "tag": "tun-in",
    "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
    "auto_route": True,
    "strict_route": True,
    # system stack: lower latency on Windows than default gVisor userspace stack.
    "stack": "system",
}

# Short timeout: enough for TLS ClientHello SNI, avoids the old 300ms stall per connection.
SNIFF_RULE = {"action": "sniff", "timeout": "50ms", "sniffer": ["tls", "http"]}
DNS_HIJACK_RULE = {"port": 53, "action": "hijack-dns"}
PRIVATE_DIRECT_RULE = {"ip_is_private": True, "outbound": "direct"}

GEOSITE_CN_URL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
GEOIP_CN_URL = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"

# auto 模式：所有 *.cn / *.com.cn 直连（优先于 proxy_domain）。
CN_TLD_DIRECT_RULE = {"domain_suffix": ["cn"], "outbound": "direct"}
CN_TLD_DNS_RULE = {"domain_suffix": ["cn"], "action": "route", "server": "local-dns"}

CHINA_RULE_SETS = [
    {
        "type": "remote",
        "tag": "geosite-cn",
        "format": "binary",
        "url": GEOSITE_CN_URL,
        "download_detour": "proxy",
    },
    {
        "type": "remote",
        "tag": "geoip-cn",
        "format": "binary",
        "url": GEOIP_CN_URL,
        "download_detour": "proxy",
    },
]

LOCAL_DNS = {
    "type": "udp",
    "tag": "local-dns",
    "server": "223.5.5.5",
    "server_port": 53,
}

REMOTE_DNS = {
    "type": "udp",
    "tag": "remote-dns",
    "server": "1.1.1.1",
    "server_port": 53,
}


def _object_list(config: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = config.setdefault(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConfigError(f"{key} must be a list of objects")
    return value


def _normalize_domains(domains: list[str]) -> list[str]:
    result: list[str] = []
    for domain in domains:
        value = domain.strip().lower().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        if not value or "." not in value or any(char.isspace() for char in value):
            raise ConfigError(f"invalid domain: {domain}")
        if value not in result:
            result.append(value)
    return result


def _normalize_processes(processes: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for process in processes:
        value = ntpath.basename(process.strip().strip('"'))
        if not value or any(char in value for char in "<>|?*"):
            raise ConfigError(f"invalid process name: {process}")
        key = value
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _reject_cn_proxy_domains(domains: list[str]) -> None:
    for domain in domains:
        if domain == "cn" or domain.endswith(".cn"):
            raise ConfigError(
                f"proxy_domain cannot use .cn suffix (all .cn direct in auto): {domain}"
            )


def _normalize_listen_port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("listen_port must be an integer between 1 and 65535")
    if not 1 <= value <= 65535:
        raise ConfigError("listen_port must be an integer between 1 and 65535")
    return value


def load_rules(
    path: Path,
) -> tuple[list[str], list[str], list[str], list[str], int]:
    if yaml is None:
        raise ConfigError("PyYAML is required: python -m pip install PyYAML")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ConfigError(f"process rules file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError("process rules YAML root must be an object")

    list_keys = {"direct_process", "direct_domain", "proxy_process", "proxy_domain"}
    allowed = list_keys | {"listen_port"}
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"unknown process rules key: {unknown[0]}")

    for key in list_keys:
        value = data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ConfigError(f"{key} must be a list of strings")

    listen_port = (
        _normalize_listen_port(data["listen_port"])
        if "listen_port" in data
        else DEFAULT_LISTEN_PORT
    )
    direct_process = _normalize_processes(data.get("direct_process", []))
    direct_domain = _normalize_domains(data.get("direct_domain", []))
    proxy_process = _normalize_processes(data.get("proxy_process", []))
    proxy_domain = _normalize_domains(data.get("proxy_domain", []))
    _reject_cn_proxy_domains(proxy_domain)
    overlap = {item.casefold() for item in direct_process} & {
        item.casefold() for item in proxy_process
    }
    if overlap:
        raise ConfigError(f"process cannot be both direct and proxied: {sorted(overlap)[0]}")
    domain_overlap = set(direct_domain) & set(proxy_domain)
    if domain_overlap:
        raise ConfigError(
            f"domain cannot be both direct and proxied: {sorted(domain_overlap)[0]}"
        )
    return direct_process, direct_domain, proxy_process, proxy_domain, listen_port


def _proxy_server_routes(outbounds: list[dict[str, Any]]) -> list[str]:
    routes: set[str] = set()
    for outbound in outbounds:
        server = outbound.get("server")
        if not isinstance(server, str) or not server:
            continue
        try:
            addresses = [ipaddress.ip_address(server)]
        except ValueError:
            try:
                addresses = {
                    ipaddress.ip_address(item[4][0])
                    for item in socket.getaddrinfo(
                        server,
                        outbound.get("server_port", 0),
                        type=socket.SOCK_STREAM,
                    )
                }
            except (OSError, ValueError) as exc:
                raise ConfigError(f"cannot resolve proxy server for TUN exclusion: {server}") from exc
        for address in addresses:
            routes.add(f"{address}/{address.max_prefixlen}")
    return sorted(routes)


def _ensure_outbounds(config: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    outbounds = _object_list(config, "outbounds")
    outbound_tags = {item.get("tag") for item in outbounds}
    has_proxy = "proxy" in outbound_tags

    direct = next((item for item in outbounds if item.get("tag") == "direct"), None)
    if direct is None:
        outbounds.append({"type": "direct", "tag": "direct"})
    elif direct.get("type") != "direct":
        raise ConfigError('outbound tag "direct" is already used by a non-direct outbound')
    return outbounds, has_proxy


def _find_mixed_inbound(
    inbounds: list[dict[str, Any]],
    listen_port: int,
) -> dict[str, Any] | None:
    for item in inbounds:
        if item.get("tag") == "mixed-in":
            return item
        if (
            item.get("type") == "mixed"
            and item.get("listen") == "127.0.0.1"
            and item.get("listen_port") == listen_port
        ):
            return item
    return None


def _configure_inbounds(
    config: dict[str, Any],
    mode: str,
    proxy_server_routes: list[str],
    listen_port: int,
) -> None:
    inbounds = _object_list(config, "inbounds")

    mixed = _find_mixed_inbound(inbounds, listen_port)
    if mixed is None:
        if any(item.get("tag") == "mixed-in" for item in inbounds):
            raise ConfigError('inbound tag "mixed-in" is already used with different settings')
        mixed = dict(MIXED_INBOUND)
        inbounds.append(mixed)

    mixed["listen"] = "127.0.0.1"
    mixed["listen_port"] = listen_port
    mixed.pop("set_system_proxy", None)

    inbounds[:] = [item for item in inbounds if item.get("tag") != "tun-in"]
    if mode == "global":
        tun = dict(TUN_INBOUND)
        if proxy_server_routes:
            tun["route_exclude_address"] = proxy_server_routes
        inbounds.append(tun)


def _configure_route(
    config: dict[str, Any],
    mode: str,
    proxy_domains: list[str],
    direct_processes: list[str],
    direct_domains: list[str],
    proxy_processes: list[str],
) -> None:
    route = config.setdefault("route", {})
    if not isinstance(route, dict):
        raise ConfigError("route must be an object")

    rules: list[dict[str, Any]] = []
    if mode == "global":
        rules.extend([SNIFF_RULE, DNS_HIJACK_RULE, PRIVATE_DIRECT_RULE])
    elif mode != "off":
        rules.extend([SNIFF_RULE, PRIVATE_DIRECT_RULE])
    if direct_processes:
        rules.append({"process_name": direct_processes, "outbound": "direct"})
    if direct_domains:
        rules.append({"domain_suffix": direct_domains, "outbound": "direct"})
    if mode == "auto":
        rules.append(dict(CN_TLD_DIRECT_RULE))
    if proxy_domains:
        rules.append({"domain_suffix": proxy_domains, "outbound": "proxy"})
    if mode == "auto":
        rules.append({"rule_set": ["geosite-cn", "geoip-cn"], "outbound": "direct"})
    elif mode == "custom" and proxy_processes:
        rules.append({"process_name": proxy_processes, "outbound": "proxy"})

    route["rules"] = rules
    route["auto_detect_interface"] = True
    route["final"] = "direct" if mode in {"off", "custom"} else "proxy"
    if mode == "auto":
        route["rule_set"] = [dict(item) for item in CHINA_RULE_SETS]
    else:
        route.pop("rule_set", None)
    if mode == "off":
        route.pop("default_domain_resolver", None)
    elif mode == "auto":
        route["default_domain_resolver"] = "local-dns"
    else:
        route["default_domain_resolver"] = "local-dns"


def _configure_dns(
    config: dict[str, Any],
    mode: str,
    proxy_domains: list[str],
    direct_processes: list[str],
    direct_domains: list[str],
    proxy_processes: list[str],
) -> None:
    if mode == "off":
        config.pop("dns", None)
        return

    dns: dict[str, Any] = {
        "servers": [dict(LOCAL_DNS), dict(REMOTE_DNS)],
        "rules": [],
        "strategy": "ipv4_only",
    }
    if direct_processes:
        dns["rules"].append(
            {"process_name": direct_processes, "action": "route", "server": "local-dns"}
        )
    if direct_domains:
        dns["rules"].append(
            {"domain_suffix": direct_domains, "action": "route", "server": "local-dns"}
        )
    if mode == "auto":
        dns["rules"].append(dict(CN_TLD_DNS_RULE))
    if proxy_domains:
        dns["rules"].append(
            {"domain_suffix": proxy_domains, "action": "route", "server": "remote-dns"}
        )
    if mode == "auto":
        dns["rules"].append(
            {"rule_set": "geosite-cn", "action": "route", "server": "local-dns"}
        )
        dns["final"] = "local-dns"
    elif mode == "global":
        dns["final"] = "remote-dns"
    elif mode == "custom":
        if proxy_processes:
            dns["rules"].append(
                {"process_name": proxy_processes, "action": "route", "server": "remote-dns"}
            )
        dns["final"] = "local-dns"
    else:
        dns["final"] = "local-dns"
    config["dns"] = dns


def rewrite_config(
    config: dict[str, Any],
    mode: str = "auto",
    proxy_domains: list[str] | None = None,
    yaml_proxy_domains: list[str] | None = None,
    direct_processes: list[str] | None = None,
    direct_domains: list[str] | None = None,
    proxy_processes: list[str] | None = None,
    listen_port: int = DEFAULT_LISTEN_PORT,
) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ConfigError("config root must be a JSON object")
    if mode == "tun":
        mode = "global"
    if mode not in {"auto", "off", "global", "custom"}:
        raise ConfigError(f"unsupported mode: {mode}")

    cli_domains = _normalize_domains(proxy_domains or [])
    yaml_domains = _normalize_domains(yaml_proxy_domains or [])
    _reject_cn_proxy_domains(cli_domains)
    direct_apps = _normalize_processes(direct_processes or [])
    direct_sites = _normalize_domains(direct_domains or [])
    proxy_apps = _normalize_processes(proxy_processes or [])
    overlap = {item.casefold() for item in direct_apps} & {item.casefold() for item in proxy_apps}
    if overlap:
        raise ConfigError(f"process cannot be both direct and proxied: {sorted(overlap)[0]}")
    if mode in {"auto", "custom"}:
        domains = _normalize_domains(cli_domains + yaml_domains)
    else:
        domains = []
    domain_overlap = set(direct_sites) & set(domains)
    if domain_overlap:
        raise ConfigError(
            f"domain cannot be both direct and proxied: {sorted(domain_overlap)[0]}"
        )
    if mode == "custom" and not (domains or proxy_apps):
        raise ConfigError("custom mode requires --proxy-domain or proxy_process in YAML")

    outbounds, has_proxy = _ensure_outbounds(config)
    if mode != "off" and not has_proxy:
        raise ConfigError('config must contain an outbound tagged "proxy"')

    proxy_routes = _proxy_server_routes(outbounds) if mode == "global" else []
    _configure_inbounds(config, mode, proxy_routes, listen_port)
    _configure_route(config, mode, domains, direct_apps, direct_sites, proxy_apps)
    _configure_dns(config, mode, domains, direct_apps, direct_sites, proxy_apps)
    return config


def rewrite_file(
    path: Path,
    mode: str,
    proxy_domains: list[str],
    rules_path: Path = Path("proxy_rules.yaml"),
) -> tuple[Path | None, int]:
    try:
        config = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc

    (
        direct_processes,
        direct_domains,
        proxy_processes,
        yaml_proxy_domains,
        listen_port,
    ) = load_rules(rules_path)
    rendered = json.dumps(
        rewrite_config(
            config,
            mode,
            proxy_domains,
            yaml_proxy_domains,
            direct_processes,
            direct_domains,
            proxy_processes,
            listen_port,
        ),
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    backup = path.with_name(path.name + ".bak")
    created_backup: Path | None = None
    if not backup.exists():
        shutil.copy2(path, backup)
        created_backup = backup

    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=path.name + ".",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temp_file:
            temp_file.write(rendered)
            temp_name = temp_file.name
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    return created_backup, listen_port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "config",
        nargs="?",
        default="config.json",
        help="config file to rewrite in place (default: config.json)",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "off", "global", "tun", "custom"],
        default="auto",
        help="routing mode: auto=system proxy split, global/tun=TUN (default: auto)",
    )
    parser.add_argument(
        "--proxy-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="extra proxy domain suffix (also see proxy_domain in YAML); .cn not allowed",
    )
    parser.add_argument(
        "--rules-file",
        default=str(DEFAULT_RULES_PATH),
        metavar="YAML",
        help="desktop process rules YAML file (default: next to this script)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.config)
    try:
        backup, listen_port = rewrite_file(
            path,
            args.mode,
            args.proxy_domain,
            Path(args.rules_file),
        )
    except (ConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    normalized_mode = "global" if args.mode == "tun" else args.mode
    print(f"proxy mode set to {normalized_mode} in {path}")
    if backup:
        print(f"original config backed up to {backup}")
    if normalized_mode == "global":
        print("run sing-box with Administrator privileges")
    elif normalized_mode == "auto":
        print(f"start with: python run_singbox_auto.py {path}")
        print(f"(v2rayN-style system proxy: 127.0.0.1:{listen_port} + <local> bypass)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
