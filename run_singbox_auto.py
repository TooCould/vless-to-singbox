#!/usr/bin/env python3
"""Run sing-box in auto mode with v2rayN-aligned Windows system proxy."""

from __future__ import annotations

import argparse
import atexit
import json
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from proxy_settings import DEFAULT_RULES_PATH, load_rules
from wininet_system_proxy import (
    apply_system_proxy,
    clear_system_proxy,
    get_system_proxy,
)


class ConfigError(ValueError):
    pass


class _Runtime:
    """Shared state so signal/console/atexit handlers stay consistent."""

    proxy_applied = False
    child: "subprocess.Popen[bytes] | None" = None


_runtime = _Runtime()


def _cleanup_proxy() -> None:
    if _runtime.proxy_applied:
        clear_system_proxy()
        _runtime.proxy_applied = False


def _terminate_child() -> None:
    child = _runtime.child
    if child is not None and child.poll() is None:
        try:
            child.terminate()
        except OSError:
            pass


# signal handlers do not fire when the terminal window is closed on Windows;
# SetConsoleCtrlHandler covers close/logoff/shutdown so the proxy is restored.
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _CTRL_CLOSE_EVENT = 2
    _CTRL_LOGOFF_EVENT = 5
    _CTRL_SHUTDOWN_EVENT = 6
    _HANDLER_ROUTINE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

    def _console_ctrl_handler(ctrl_type: int) -> bool:
        if ctrl_type in (_CTRL_CLOSE_EVENT, _CTRL_LOGOFF_EVENT, _CTRL_SHUTDOWN_EVENT):
            _terminate_child()
            _cleanup_proxy()
            return True
        return False

    _console_handler_ref = _HANDLER_ROUTINE(_console_ctrl_handler)

    def _install_console_handler() -> None:
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler_ref, True)

else:  # pragma: no cover - launcher is Windows-only

    def _install_console_handler() -> None:
        pass


def _read_listen_port(rules_path: Path) -> int:
    """Read the mixed-inbound port from proxy_rules.yaml (single source of truth)."""
    *_rest, listen_port = load_rules(rules_path)
    return listen_port


def _config_mixed_port(config_path: Path) -> int | None:
    """Return the mixed inbound port from config.json, or None if unavailable."""
    try:
        config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    if not isinstance(config, dict):
        return None
    for inbound in config.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        if inbound.get("type") == "mixed" or inbound.get("tag") == "mixed-in":
            port = inbound.get("listen_port")
            return port if isinstance(port, int) else None
    return None


def _resolve_singbox(explicit: str | None) -> str:
    if explicit:
        path = Path(explicit)
        if not path.exists():
            raise ConfigError(f"sing-box executable not found: {explicit}")
        return str(path)

    found = shutil.which("sing-box")
    if not found:
        raise ConfigError("sing-box not found in PATH; pass --sing-box")
    return found


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "config",
        nargs="?",
        default="config.json",
        help="sing-box config file (default: config.json)",
    )
    parser.add_argument(
        "--sing-box",
        metavar="EXE",
        help="sing-box executable path (default: search PATH)",
    )
    parser.add_argument(
        "--rules-file",
        default=str(DEFAULT_RULES_PATH),
        metavar="YAML",
        help="proxy rules YAML providing listen_port (default: next to scripts)",
    )
    parser.add_argument(
        "--no-local-bypass",
        action="store_true",
        help="do not prepend <local> to ProxyOverride (v2rayN NotProxyLocalAddress=false)",
    )
    parser.add_argument(
        "--bypass",
        metavar="LIST",
        help="custom ProxyOverride entries (v2rayN SystemProxyExceptions format)",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="clear the system proxy and exit (recover from a crashed run)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.platform != "win32":
        print("error: auto system proxy is Windows-only", file=sys.stderr)
        return 1

    args = build_parser().parse_args(argv)

    if args.cleanup:
        clear_system_proxy()
        print("system proxy cleared")
        return 0

    config_path = Path(args.config)

    try:
        host = "127.0.0.1"
        port = _read_listen_port(Path(args.rules_file))
        singbox = _resolve_singbox(args.sing_box)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    config_port = _config_mixed_port(config_path)
    if config_port is not None and config_port != port:
        print(
            f"error: config mixed port {config_port} != listen_port {port} in rules;"
            " re-run proxy_settings.py to sync",
            file=sys.stderr,
        )
        return 1

    # Recover from a previous run that crashed with the proxy still enabled.
    enabled, server = get_system_proxy()
    if enabled and f":{port}" in server:
        print(f"detected residual system proxy ({server}); clearing first")
        clear_system_proxy()

    def _handle_signal(_signum: int, _frame: object) -> None:
        # Stop sing-box; main's wait()/finally then restores the proxy.
        _terminate_child()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    atexit.register(_cleanup_proxy)
    _install_console_handler()

    try:
        # Mark applied before the call so a partial failure (e.g. some RAS
        # connections set, then an error) is still cleaned up on exit.
        _runtime.proxy_applied = True
        apply_system_proxy(
            host,
            port,
            bypass=args.bypass,
            include_local=not args.no_local_bypass,
        )
        print(f"system proxy enabled: {host}:{port} (v2rayN-style bypass list)")

        _runtime.child = subprocess.Popen([singbox, "run", "-c", str(config_path)])
        return _runtime.child.wait()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if _runtime.child is not None and _runtime.child.poll() is None:
            _runtime.child.wait()
        if _runtime.proxy_applied:
            _cleanup_proxy()
            print("system proxy cleared")


if __name__ == "__main__":
    raise SystemExit(main())
