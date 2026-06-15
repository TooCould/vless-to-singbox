#!/usr/bin/env python3
"""Windows WinInet system proxy helpers aligned with v2rayN ForcedChange."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Iterable

if sys.platform != "win32":
    raise NotImplementedError("Windows only")

# v2rayN Global.SystemProxyExceptionsWindows default
V2RAYN_PROXY_EXCEPTIONS = (
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;"
    "172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;"
    "172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*"
)

_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

INTERNET_OPTION_PER_CONNECTION_OPTION = 75
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

INTERNET_PER_CONN_FLAGS = 1
INTERNET_PER_CONN_PROXY_SERVER = 2
INTERNET_PER_CONN_PROXY_BYPASS = 3

PROXY_TYPE_DIRECT = 0x00000001
PROXY_TYPE_PROXY = 0x00000002

RAS_MAX_ENTRY_NAME = 256


class _INTERNET_PER_CONN_OPTION_VALUE(ctypes.Union):
    _fields_ = [
        ("dwValue", wintypes.DWORD),
        ("pszValue", wintypes.LPWSTR),
    ]


class INTERNET_PER_CONN_OPTION(ctypes.Structure):
    _fields_ = [
        ("dwOption", wintypes.DWORD),
        ("Value", _INTERNET_PER_CONN_OPTION_VALUE),
    ]


class INTERNET_PER_CONN_OPTION_LIST(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("pszConnection", wintypes.LPWSTR),
        ("dwOptionCount", wintypes.DWORD),
        ("dwOptionError", wintypes.DWORD),
        ("pOptions", ctypes.POINTER(INTERNET_PER_CONN_OPTION)),
    ]


class RASENTRYNAME(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("szEntryName", wintypes.WCHAR * (RAS_MAX_ENTRY_NAME + 1)),
    ]


_wininet = ctypes.windll.wininet
_rasapi32 = ctypes.windll.rasapi32


def build_bypass_exceptions(
    custom: str | None = None,
    *,
    include_local: bool = True,
) -> str:
    """Build ProxyOverride string like v2rayN (NotProxyLocalAddress + exceptions)."""
    exceptions = (custom if custom is not None else V2RAYN_PROXY_EXCEPTIONS).replace(" ", "")
    if include_local:
        return f"<local>{exceptions}"
    return exceptions


def _notify_proxy_change() -> None:
    _wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    _wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


def _enumerate_ras_entries() -> list[str]:
    entries = wintypes.DWORD(0)
    buffer_size = wintypes.DWORD(ctypes.sizeof(RASENTRYNAME))
    names = (RASENTRYNAME * 1)()
    names[0].dwSize = ctypes.sizeof(RASENTRYNAME)

    result = _rasapi32.RasEnumEntriesW(
        None,
        None,
        names,
        ctypes.byref(buffer_size),
        ctypes.byref(entries),
    )
    if result == 603:  # ERROR_BUFFER_TOO_SMALL
        count = buffer_size.value // ctypes.sizeof(RASENTRYNAME)
        names = (RASENTRYNAME * count)()
        for item in names:
            item.dwSize = ctypes.sizeof(RASENTRYNAME)
        result = _rasapi32.RasEnumEntriesW(
            None,
            None,
            names,
            ctypes.byref(buffer_size),
            ctypes.byref(entries),
        )
    if result != 0:
        return []

    return [names[index].szEntryName for index in range(entries.value)]


def _set_connection_proxy(
    connection_name: str | None,
    proxy_server: str | None,
    bypass: str | None,
    *,
    enable: bool,
) -> bool:
    if enable:
        flags = PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
        option_count = 3 if bypass else 2
    else:
        flags = PROXY_TYPE_DIRECT
        option_count = 1

    refs: list[str] = []
    options = (INTERNET_PER_CONN_OPTION * option_count)()
    options[0].dwOption = INTERNET_PER_CONN_FLAGS
    options[0].Value.dwValue = flags

    if enable:
        refs.append(proxy_server or "")
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER
        options[1].Value.pszValue = refs[-1]
        if bypass:
            refs.append(bypass)
            options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS
            options[2].Value.pszValue = refs[-1]

    option_list = INTERNET_PER_CONN_OPTION_LIST()
    option_list.dwSize = ctypes.sizeof(INTERNET_PER_CONN_OPTION_LIST)
    if connection_name is not None:
        refs.append(connection_name)
        option_list.pszConnection = refs[-1]
    else:
        option_list.pszConnection = None
    option_list.dwOptionCount = option_count
    option_list.dwOptionError = 0
    option_list.pOptions = options

    ok = _wininet.InternetSetOptionW(
        None,
        INTERNET_OPTION_PER_CONNECTION_OPTION,
        ctypes.byref(option_list),
        option_list.dwSize,
    )
    if ok:
        _notify_proxy_change()
    return bool(ok)


def _registry_set_proxy(proxy_server: str, bypass: str) -> None:
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        _REG_PATH,
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass)
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, "")
    _notify_proxy_change()


def _registry_clear_proxy() -> None:
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        _REG_PATH,
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "")
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, "")
    _notify_proxy_change()


def get_system_proxy() -> tuple[bool, str]:
    """Return (enabled, proxy_server) from the current-user WinInet registry."""
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            _REG_PATH,
            0,
            winreg.KEY_QUERY_VALUE,
        ) as key:
            try:
                enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except FileNotFoundError:
                enable = 0
            try:
                server = winreg.QueryValueEx(key, "ProxyServer")[0]
            except FileNotFoundError:
                server = ""
    except OSError:
        return False, ""
    return bool(enable), str(server or "")


def get_system_proxy() -> tuple[bool, str]:
    """Return (enabled, proxy_server) from the current-user registry."""
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            _REG_PATH,
            0,
            winreg.KEY_QUERY_VALUE,
        ) as key:
            try:
                enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except FileNotFoundError:
                enable = 0
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                server = ""
    except FileNotFoundError:
        return (False, "")
    return (bool(enable), server or "")


def _connection_targets() -> Iterable[str | None]:
    yield None
    yield from _enumerate_ras_entries()


def apply_system_proxy(
    host: str,
    port: int,
    *,
    bypass: str | None = None,
    include_local: bool = True,
) -> None:
    """Enable system proxy like v2rayN ForcedChange.

    host/port are required; the caller is the single source of truth (the port
    comes from listen_port in proxy_rules.yaml).
    """
    proxy_server = f"{host}:{port}"
    bypass_value = build_bypass_exceptions(bypass, include_local=include_local)

    success = False
    for connection in _connection_targets():
        if _set_connection_proxy(connection, proxy_server, bypass_value, enable=True):
            success = True

    if not success:
        _registry_set_proxy(proxy_server, bypass_value)


def clear_system_proxy() -> None:
    """Disable system proxy like v2rayN ForcedClear."""
    success = False
    for connection in _connection_targets():
        if _set_connection_proxy(connection, None, None, enable=False):
            success = True

    if not success:
        _registry_clear_proxy()
    else:
        _registry_clear_proxy()
