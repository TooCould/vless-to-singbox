#!/usr/bin/env python3
"""Convert VLESS share links/subscriptions to a sing-box client config."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import uuid as uuid_module
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit


class ConversionError(ValueError):
    pass


TRUE_VALUES = {"1", "true", "yes", "on"}
SUPPORTED_TRANSPORTS = {"tcp", "none", "ws", "websocket", "grpc", "http", "h2", "httpupgrade", "quic"}


def _first(params: dict[str, list[str]], *names: str, default: str = "") -> str:
    for name in names:
        values = params.get(name.lower())
        if values:
            return values[0]
    return default


def _is_true(value: str) -> bool:
    return value.strip().lower() in TRUE_VALUES


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _headers(host: str) -> dict[str, str]:
    return {"Host": host} if host else {}


def _decode_subscription(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise ConversionError("subscription is not valid UTF-8") from exc

    if "vless://" in text.lower():
        return text

    compact = re.sub(r"\s+", "", text)
    if not compact:
        raise ConversionError("subscription is empty")

    padded = compact + "=" * (-len(compact) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8-sig")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ConversionError("input is neither VLESS links nor a Base64 VLESS subscription") from exc
    if "vless://" not in decoded.lower():
        raise ConversionError("decoded subscription contains no VLESS links")
    return decoded


def extract_vless_links(raw: bytes) -> list[str]:
    text = _decode_subscription(raw)
    links = []
    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip()
        if line.lower().startswith("vless://"):
            links.append(line)
    if not links:
        raise ConversionError("no VLESS links found")
    return links


def _ws_path_and_early_data(path: str, params: dict[str, list[str]]) -> tuple[str, int, str]:
    early_data = _first(params, "ed", "max_early_data")
    early_header = _first(params, "eh", "early_data_header_name")

    # Some clients append ?ed=... to the WebSocket path instead of the URI query.
    if "?" in path:
        path_parts = urlsplit(path)
        path_params = {key.lower(): value for key, value in parse_qs(path_parts.query, keep_blank_values=True).items()}
        if not early_data:
            early_data = _first(path_params, "ed")
        if "ed" in path_params:
            filtered = [(key, value) for key, values in path_params.items() if key != "ed" for value in values]
            query = "&".join(f"{key}={value}" for key, value in filtered)
            path = urlunsplit(("", "", path_parts.path, query, path_parts.fragment))

    size = 0
    if early_data:
        try:
            size = int(early_data)
        except ValueError as exc:
            raise ConversionError(f"invalid WebSocket early-data size: {early_data}") from exc
        if size < 0:
            raise ConversionError("WebSocket early-data size cannot be negative")
    return path, size, early_header


def _build_transport(params: dict[str, list[str]]) -> dict[str, Any] | None:
    transport_type = _first(params, "type").lower()
    network_hint = _first(params, "network").lower()
    if not transport_type and network_hint not in {"tcp", "udp"}:
        transport_type = network_hint
    transport_type = transport_type or "tcp"

    header_type = _first(params, "headertype", "header_type").lower()
    if transport_type in {"tcp", "none"} and header_type == "http":
        transport_type = "http"
    if transport_type not in SUPPORTED_TRANSPORTS:
        raise ConversionError(f"unsupported VLESS transport: {transport_type}")
    if transport_type in {"tcp", "none"}:
        return None

    host = _first(params, "host")
    path = _first(params, "path", default="/") or "/"

    if transport_type in {"ws", "websocket"}:
        path, early_data, early_header = _ws_path_and_early_data(path, params)
        transport: dict[str, Any] = {"type": "ws", "path": path}
        if host:
            transport["headers"] = _headers(host)
        if early_data:
            transport["max_early_data"] = early_data
            if early_header:
                transport["early_data_header_name"] = early_header
        return transport

    if transport_type == "grpc":
        service_name = _first(params, "servicename", "service_name")
        return {"type": "grpc", "service_name": service_name}

    if transport_type in {"http", "h2"}:
        transport = {"type": "http", "path": path}
        if host:
            transport["host"] = _split_csv(host)
        method = _first(params, "method")
        if method:
            transport["method"] = method
        return transport

    if transport_type == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path}
        if host:
            transport["host"] = host
        return transport

    return {"type": "quic"}


def parse_vless_link(link: str) -> tuple[dict[str, Any], str]:
    try:
        parsed = urlsplit(link)
        port = parsed.port
        host = parsed.hostname
    except ValueError as exc:
        raise ConversionError(f"invalid VLESS URL: {exc}") from exc

    if parsed.scheme.lower() != "vless":
        raise ConversionError("link scheme must be vless://")
    if not parsed.username or not host or port is None:
        raise ConversionError("VLESS link must contain UUID, server, and port")

    user_id = unquote(parsed.username)
    try:
        uuid_module.UUID(user_id)
    except ValueError as exc:
        raise ConversionError(f"invalid VLESS UUID: {user_id}") from exc

    params = {key.lower(): value for key, value in parse_qs(parsed.query, keep_blank_values=True).items()}
    encryption = _first(params, "encryption", default="none").lower()
    if encryption not in {"", "none"}:
        raise ConversionError(f"unsupported VLESS encryption value: {encryption}")

    outbound: dict[str, Any] = {
        "type": "vless",
        "server": host,
        "server_port": port,
        "uuid": user_id,
    }

    flow = _first(params, "flow")
    if flow:
        if flow != "xtls-rprx-vision":
            raise ConversionError(f"unsupported VLESS flow: {flow}")
        outbound["flow"] = flow

    network = _first(params, "network").lower()
    if network in {"tcp", "udp"}:
        outbound["network"] = network

    packet_encoding = _first(params, "packetencoding", "packet_encoding").lower()
    if packet_encoding:
        if packet_encoding not in {"xudp", "packetaddr"}:
            raise ConversionError(f"unsupported packet encoding: {packet_encoding}")
        outbound["packet_encoding"] = packet_encoding

    security = _first(params, "security").lower()
    if security not in {"", "none", "tls", "reality"}:
        raise ConversionError(f"unsupported VLESS security: {security}")
    if security in {"tls", "reality"}:
        tls: dict[str, Any] = {"enabled": True}
        server_name = _first(params, "sni", "servername", "server_name")
        if server_name:
            tls["server_name"] = server_name
        if _is_true(_first(params, "allowinsecure", "insecure")):
            tls["insecure"] = True
        alpn = _split_csv(_first(params, "alpn"))
        if alpn:
            tls["alpn"] = alpn
        fingerprint = _first(params, "fp", "fingerprint")
        if fingerprint and fingerprint.lower() not in {"none", "off"}:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
        if security == "reality":
            public_key = _first(params, "pbk", "publickey", "public_key")
            if not public_key:
                raise ConversionError("Reality link is missing public key (pbk)")
            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": _first(params, "sid", "shortid", "short_id"),
            }
        outbound["tls"] = tls

    transport = _build_transport(params)
    if transport:
        outbound["transport"] = transport

    name = unquote(parsed.fragment).strip() or f"{host}:{port}"
    return outbound, name


def _clean_tag(name: str) -> str:
    tag = " ".join(name.split())
    tag = "".join(char for char in tag if char.isprintable())
    return tag or "vless"


def convert_links(
    links: list[str],
    listen: str = "127.0.0.1",
    port: int = 2808,
) -> dict[str, Any]:
    if not 1 <= port <= 65535:
        raise ConversionError("listen port must be between 1 and 65535")

    outbounds: list[dict[str, Any]] = []
    tags: list[str] = []
    used = {"proxy", "direct"}
    errors: list[str] = []

    for index, link in enumerate(links, start=1):
        try:
            outbound, name = parse_vless_link(link)
        except ConversionError as exc:
            errors.append(f"link {index}: {exc}")
            continue
        base_tag = _clean_tag(name)
        tag = base_tag
        suffix = 2
        while tag in used:
            tag = f"{base_tag} ({suffix})"
            suffix += 1
        used.add(tag)
        outbound["tag"] = tag
        tags.append(tag)
        outbounds.append(outbound)

    if errors:
        raise ConversionError("\n".join(errors))
    if not outbounds:
        raise ConversionError("no valid VLESS links found")

    selector = {
        "type": "selector",
        "tag": "proxy",
        "outbounds": tags,
        "default": tags[0],
    }
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": listen,
                "listen_port": port,
            }
        ],
        "outbounds": [selector, *outbounds, {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"ip_is_private": True, "outbound": "direct"}],
            "auto_detect_interface": True,
            "final": "proxy",
        },
    }


def read_input(source: str, timeout: float) -> bytes:
    if source == "-":
        return sys.stdin.buffer.read()
    if source.lower().startswith("vless://"):
        return source.encode("utf-8")
    if source.lower().startswith(("http://", "https://")):
        request = urllib.request.Request(source, headers={"User-Agent": "vless-to-sing-box/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
            if response.headers.get("Content-Encoding", "").lower() == "gzip":
                data = gzip.decompress(data)
            return data
    path = Path(source)
    if path.is_file():
        return path.read_bytes()
    return source.encode("utf-8")


def check_config(config_path: Path, sing_box: str | None) -> None:
    executable = sing_box or shutil.which("sing-box") or shutil.which("sing-box.exe")
    if not executable:
        raise ConversionError("sing-box executable was not found; pass --sing-box PATH")
    result = subprocess.run(
        [executable, "check", "-c", str(config_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ConversionError(f"sing-box check failed: {detail}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="subscription URL, local file, VLESS link, Base64 text, or - for stdin")
    parser.add_argument("-o", "--output", default="config.json", help="output path, or - for stdout")
    parser.add_argument("--timeout", type=float, default=15.0, help="subscription download timeout in seconds")
    parser.add_argument("--check", action="store_true", help="validate the generated config with sing-box")
    parser.add_argument("--sing-box", help="path to the sing-box executable")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw = read_input(args.source, args.timeout)
        config = convert_links(extract_vless_links(raw))
        rendered = json.dumps(config, ensure_ascii=False, indent=2) + "\n"

        if args.output == "-":
            if args.check:
                with tempfile.TemporaryDirectory() as directory:
                    temp_path = Path(directory) / "config.json"
                    temp_path.write_text(rendered, encoding="utf-8")
                    check_config(temp_path, args.sing_box)
            sys.stdout.write(rendered)
        else:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
            if args.check:
                check_config(output_path, args.sing_box)
            node_count = len(config["outbounds"][0]["outbounds"])
            print(f"wrote {node_count} node(s) to {output_path}", file=sys.stderr)
        return 0
    except (ConversionError, OSError, urllib.error.URLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
