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


MIXED_INBOUND = {
    "type": "mixed",
    "tag": "mixed-in",
    "listen": "127.0.0.1",
    "listen_port": 2080,
}

TUN_INBOUND = {
    "type": "tun",
    "tag": "tun-in",
    "address": ["172.19.0.1/30"],
    "auto_route": True,
    "strict_route": True,
}

DNS_HIJACK_RULE = {"port": 53, "action": "hijack-dns"}
PRIVATE_DIRECT_RULE = {"ip_is_private": True, "outbound": "direct"}

GEOSITE_CN_URL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
GEOIP_CN_URL = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"

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
    "type": "https",
    "tag": "remote-dns",
    "server": "1.1.1.1",
    "server_port": 443,
    "path": "/dns-query",
    "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
    "detour": "proxy",
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
            raise ConfigError(f"invalid proxy domain: {domain}")
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


def load_process_rules(path: Path) -> tuple[list[str], list[str]]:
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

    allowed = {"direct_process", "proxy_process"}
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"unknown process rules key: {unknown[0]}")

    for key in allowed:
        value = data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ConfigError(f"{key} must be a list of strings")

    direct = _normalize_processes(data.get("direct_process", []))
    proxy = _normalize_processes(data.get("proxy_process", []))
    overlap = {item.casefold() for item in direct} & {item.casefold() for item in proxy}
    if overlap:
        raise ConfigError(f"process cannot be both direct and proxied: {sorted(overlap)[0]}")
    return direct, proxy


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


def _configure_inbounds(
    config: dict[str, Any],
    mode: str,
    proxy_server_routes: list[str],
) -> None:
    inbounds = _object_list(config, "inbounds")

    has_mixed = any(
        item.get("type") == "mixed"
        and item.get("listen") == "127.0.0.1"
        and item.get("listen_port") == 2080
        for item in inbounds
    )
    if not has_mixed:
        if any(item.get("tag") == "mixed-in" for item in inbounds):
            raise ConfigError('inbound tag "mixed-in" is already used with different settings')
        inbounds.append(dict(MIXED_INBOUND))

    inbounds[:] = [item for item in inbounds if item.get("tag") != "tun-in"]
    if mode != "off":
        tun = dict(TUN_INBOUND)
        if mode == "auto":
            tun["strict_route"] = False
        if proxy_server_routes:
            tun["route_exclude_address"] = proxy_server_routes
        if mode == "auto":
            tun["route_exclude_address_set"] = ["geoip-cn"]
        inbounds.append(tun)


def _configure_route(
    config: dict[str, Any],
    mode: str,
    proxy_domains: list[str],
    direct_processes: list[str],
    proxy_processes: list[str],
) -> None:
    route = config.setdefault("route", {})
    if not isinstance(route, dict):
        raise ConfigError("route must be an object")

    rules: list[dict[str, Any]] = []
    if mode != "off":
        rules.extend([DNS_HIJACK_RULE, PRIVATE_DIRECT_RULE])
    if direct_processes:
        rules.append({"process_name": direct_processes, "outbound": "direct"})
    if proxy_processes:
        rules.append({"process_name": proxy_processes, "outbound": "proxy"})
    if proxy_domains:
        rules.append({"domain_suffix": proxy_domains, "outbound": "proxy"})
    if mode == "auto":
        rules.append({"rule_set": ["geosite-cn", "geoip-cn"], "outbound": "direct"})

    route["rules"] = rules
    route["auto_detect_interface"] = True
    route["final"] = "direct" if mode in {"off", "custom"} else "proxy"
    if mode == "auto":
        route["rule_set"] = [dict(item) for item in CHINA_RULE_SETS]
    else:
        route.pop("rule_set", None)
    if mode == "off":
        route.pop("default_domain_resolver", None)
    else:
        route["default_domain_resolver"] = "local-dns"


def _configure_dns(
    config: dict[str, Any],
    mode: str,
    proxy_domains: list[str],
    direct_processes: list[str],
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
    if proxy_processes:
        dns["rules"].append(
            {"process_name": proxy_processes, "action": "route", "server": "remote-dns"}
        )
    if proxy_domains:
        dns["rules"].append(
            {"domain_suffix": proxy_domains, "action": "route", "server": "remote-dns"}
        )
    if mode == "auto":
        dns["rules"].append(
            {"rule_set": "geosite-cn", "action": "route", "server": "local-dns"}
        )
        dns["final"] = "remote-dns"
    elif mode == "global":
        dns["final"] = "remote-dns"
    else:
        dns["final"] = "local-dns"
    config["dns"] = dns


def rewrite_config(
    config: dict[str, Any],
    mode: str = "auto",
    proxy_domains: list[str] | None = None,
    direct_processes: list[str] | None = None,
    proxy_processes: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ConfigError("config root must be a JSON object")
    if mode == "tun":
        mode = "global"
    if mode not in {"auto", "off", "global", "custom"}:
        raise ConfigError(f"unsupported mode: {mode}")

    domains = _normalize_domains(proxy_domains or [])
    direct_apps = _normalize_processes(direct_processes or [])
    proxy_apps = _normalize_processes(proxy_processes or [])
    overlap = {item.casefold() for item in direct_apps} & {item.casefold() for item in proxy_apps}
    if overlap:
        raise ConfigError(f"process cannot be both direct and proxied: {sorted(overlap)[0]}")
    if mode == "custom" and not (domains or proxy_apps):
        raise ConfigError("custom mode requires --proxy-domain or proxy_process in YAML")

    outbounds, has_proxy = _ensure_outbounds(config)
    if mode != "off" and not has_proxy:
        raise ConfigError('config must contain an outbound tagged "proxy"')

    proxy_routes = _proxy_server_routes(outbounds) if mode != "off" else []
    _configure_inbounds(config, mode, proxy_routes)
    _configure_route(config, mode, domains, direct_apps, proxy_apps)
    _configure_dns(config, mode, domains, direct_apps, proxy_apps)
    return config


def rewrite_file(
    path: Path,
    mode: str,
    proxy_domains: list[str],
    rules_path: Path = Path("proxy_rules.yaml"),
) -> Path | None:
    try:
        config = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc

    direct_processes, proxy_processes = load_process_rules(rules_path)
    rendered = json.dumps(
        rewrite_config(config, mode, proxy_domains, direct_processes, proxy_processes),
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
    return created_backup


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
        help="routing mode (default: auto; tun is an alias for global)",
    )
    parser.add_argument(
        "--proxy-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="force a domain and its subdomains through VLESS; may be repeated",
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
        backup = rewrite_file(
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
    if normalized_mode != "off":
        print("run sing-box with Administrator privileges")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
