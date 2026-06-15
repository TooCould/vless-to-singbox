#!/usr/bin/env python3
"""Test connectivity and latency for Cursor Composer, OpenAI Codex, and Claude."""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable

USER_AGENT = "check-ai-connectivity/1.0"


def _default_proxy_port() -> int:
    """Read the mixed-inbound port from proxy_rules.yaml; fall back to 2808."""
    try:
        from proxy_settings import DEFAULT_RULES_PATH, load_rules

        *_rest, port = load_rules(DEFAULT_RULES_PATH)
        return port
    except Exception:
        return 2808


DEFAULT_PROXY = f"http://127.0.0.1:{_default_proxy_port()}"
DEFAULT_DNS_TIMEOUT = 3.0
DEFAULT_TCP_TIMEOUT = 5.0
DEFAULT_HTTP_TIMEOUT = 8.0

SERVICES: dict[str, list[tuple[str, str]]] = {
    "Composer (Cursor)": [
        ("cursor.com", "https://cursor.com/"),
        ("api2.cursor.sh", "https://api2.cursor.sh/"),
        ("api3.cursor.sh", "https://api3.cursor.sh/"),
        ("marketplace.cursorapi.com", "https://marketplace.cursorapi.com/"),
    ],
    "Codex (OpenAI)": [
        ("auth.openai.com", "https://auth.openai.com/"),
        ("api.openai.com", "https://api.openai.com/"),
        ("chatgpt.com", "https://chatgpt.com/"),
    ],
    "Claude (Anthropic)": [
        ("claude.ai", "https://claude.ai/"),
        ("claude.com", "https://claude.com/"),
        ("api.anthropic.com", "https://api.anthropic.com/"),
    ],
}


@dataclass
class ProbeResult:
    service: str
    host: str
    url: str
    mode: str
    dns_ms: float | None
    tcp_ms: float | None
    http_ms: float | None
    status: int | None
    ok: bool
    note: str


def _fmt_ms(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.0f}ms"


def _log(message: str) -> None:
    print(message, flush=True)


def _detect_system_proxy() -> str | None:
    proxies = urllib.request.getproxies()
    return proxies.get("https") or proxies.get("http")


def _resolve_host(host: str, timeout: float) -> tuple[list[str], float]:
    started = time.perf_counter()
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    finally:
        socket.setdefaulttimeout(previous)
    elapsed_ms = (time.perf_counter() - started) * 1000
    addresses = sorted({info[4][0] for info in infos})
    return addresses, elapsed_ms


def _tcp_connect(address: str, timeout: float) -> float:
    started = time.perf_counter()
    with socket.create_connection((address, 443), timeout=timeout):
        pass
    return (time.perf_counter() - started) * 1000


def _build_opener(proxy: str | None, force_direct: bool) -> urllib.request.OpenerDirector:
    if force_direct:
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        return urllib.request.build_opener(handler)
    return urllib.request.build_opener()


def _http_probe(
    url: str,
    opener: urllib.request.OpenerDirector,
    timeout: float,
) -> tuple[float, int | None, str]:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
    started = time.perf_counter()
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(256)
            elapsed_ms = (time.perf_counter() - started) * 1000
            return elapsed_ms, response.status, "ok"
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        if exc.code in {401, 403, 404, 405, 421, 426}:
            return elapsed_ms, exc.code, f"reachable ({exc.code})"
        raise


def probe_endpoint(
    service: str,
    host: str,
    url: str,
    mode: str,
    proxy: str | None,
    force_direct: bool,
    dns_timeout: float,
    tcp_timeout: float,
    http_timeout: float,
    skip_tcp: bool,
) -> ProbeResult:
    note = ""

    try:
        addresses, dns_ms = _resolve_host(host, dns_timeout)
    except OSError as exc:
        return ProbeResult(service, host, url, mode, None, None, None, None, False, f"DNS failed: {exc}")

    if not addresses:
        return ProbeResult(service, host, url, mode, dns_ms, None, None, None, False, "DNS failed: no address")

    ip = addresses[0]
    note = f"ip={ip}"
    tcp_ms: float | None = None

    if not skip_tcp:
        try:
            tcp_ms = _tcp_connect(ip, tcp_timeout)
        except OSError as exc:
            return ProbeResult(
                service,
                host,
                url,
                mode,
                dns_ms,
                None,
                None,
                None,
                False,
                f"TCP failed: {exc}",
            )

    try:
        opener = _build_opener(proxy, force_direct)
        http_ms, status, http_note = _http_probe(url, opener, http_timeout)
        if http_note != "ok":
            note = f"{note}, {http_note}"
        return ProbeResult(service, host, url, mode, dns_ms, tcp_ms, http_ms, status, True, note)
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            detail = f"TLS failed: {reason}"
        else:
            detail = f"HTTP failed: {reason}"
        return ProbeResult(service, host, url, mode, dns_ms, tcp_ms, None, None, False, detail)
    except OSError as exc:
        return ProbeResult(service, host, url, mode, dns_ms, tcp_ms, None, None, False, f"HTTP failed: {exc}")


def _format_row(item: ProbeResult) -> str:
    status = "-" if item.status is None else str(item.status)
    result = "OK" if item.ok else "FAIL"
    detail = f"{result} {item.note}".strip()
    return (
        f"{item.service:<20} {item.host:<28} {item.mode:<8} "
        f"{_fmt_ms(item.dns_ms):>7} {_fmt_ms(item.tcp_ms):>7} {_fmt_ms(item.http_ms):>7} "
        f"{status:>4}  {detail}"
    )


def run_suite(
    modes: Iterable[tuple[str, str | None, bool]],
    dns_timeout: float,
    tcp_timeout: float,
    http_timeout: float,
    skip_tcp: bool,
) -> list[ProbeResult]:
    mode_list = list(modes)
    jobs = [
        (service, host, url, mode, proxy, force_direct)
        for service, endpoints in SERVICES.items()
        for host, url in endpoints
        for mode, proxy, force_direct in mode_list
    ]
    total = len(jobs)
    results: list[ProbeResult] = []

    header = f"{'Service':<20} {'Host':<28} {'Mode':<8} {'DNS':>7} {'TCP':>7} {'HTTP':>7} {'St':>4}  Result"
    _log(header)
    _log("-" * len(header))

    for index, (service, host, url, mode, proxy, force_direct) in enumerate(jobs, start=1):
        _log(f"[{index}/{total}] probing {host} ({mode}) ...")
        # Direct TCP pre-check is meaningless when traffic goes through a proxy
        # (it would dial the blocked IP directly), so auto-skip it for proxy/system.
        effective_skip_tcp = skip_tcp or mode in {"proxy", "system"}
        item = probe_endpoint(
            service,
            host,
            url,
            mode,
            proxy,
            force_direct,
            dns_timeout,
            tcp_timeout,
            http_timeout,
            effective_skip_tcp,
        )
        results.append(item)
        _log(f"[{index}/{total}] {_format_row(item)}")

    return results


def _print_summary(results: list[ProbeResult]) -> None:
    _log("")
    _log("Summary")
    _log("-------")
    by_mode: dict[str, list[ProbeResult]] = {}
    for item in results:
        by_mode.setdefault(item.mode, []).append(item)

    for mode, items in by_mode.items():
        ok = sum(1 for item in items if item.ok)
        total = len(items)
        http_values = [item.http_ms for item in items if item.http_ms is not None]
        avg_http = sum(http_values) / len(http_values) if http_values else None
        avg_text = _fmt_ms(avg_http) if avg_http is not None else "-"
        _log(f"{mode}: {ok}/{total} reachable, avg HTTP {avg_text}")

    direct = {(r.service, r.host): r for r in results if r.mode == "direct"}
    proxy = {(r.service, r.host): r for r in results if r.mode == "proxy"}
    if direct and proxy:
        _log("")
        _log("Direct vs proxy (HTTP)")
        _log("----------------------")
        for key in sorted(set(direct) & set(proxy)):
            left = direct[key]
            right = proxy[key]
            if left.http_ms is None or right.http_ms is None:
                continue
            delta = right.http_ms - left.http_ms
            sign = "+" if delta >= 0 else ""
            winner = "direct" if delta > 0 else "proxy"
            if abs(delta) < 5:
                winner = "similar"
            _log(
                f"{left.host:<28} direct={_fmt_ms(left.http_ms):>7} "
                f"proxy={_fmt_ms(right.http_ms):>7} delta={sign}{delta:.0f}ms ({winner})"
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["both", "direct", "proxy", "system"],
        default="both",
        help="direct=无代理; proxy=mixed 端口(见 yaml); system=系统代理; both=direct+proxy (default)",
    )
    parser.add_argument(
        "--proxy",
        default=DEFAULT_PROXY,
        help=f"proxy URL for --mode proxy/both (default: {DEFAULT_PROXY})",
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=DEFAULT_DNS_TIMEOUT,
        help=f"DNS timeout seconds (default: {DEFAULT_DNS_TIMEOUT})",
    )
    parser.add_argument(
        "--tcp-timeout",
        type=float,
        default=DEFAULT_TCP_TIMEOUT,
        help=f"TCP connect timeout seconds (default: {DEFAULT_TCP_TIMEOUT})",
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=DEFAULT_HTTP_TIMEOUT,
        help=f"HTTP timeout seconds (default: {DEFAULT_HTTP_TIMEOUT})",
    )
    parser.add_argument(
        "--skip-tcp",
        action="store_true",
        help="skip direct TCP pre-check (auto-skipped in proxy/system modes)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    modes: list[tuple[str, str | None, bool]] = []

    if args.mode in {"direct", "both"}:
        modes.append(("direct", None, True))
    if args.mode == "proxy":
        modes.append(("proxy", args.proxy, False))
    elif args.mode == "system":
        system_proxy = _detect_system_proxy()
        if not system_proxy:
            print("error: no system proxy detected", file=sys.stderr)
            return 1
        _log(f"using system proxy: {system_proxy}")
        modes.append(("system", system_proxy, False))
    elif args.mode == "both":
        modes.append(("proxy", args.proxy, False))

    jobs = sum(len(endpoints) for endpoints in SERVICES.values()) * len(modes)
    step_timeout = args.dns_timeout + (0 if args.skip_tcp else args.tcp_timeout) + args.http_timeout
    _log(
        f"jobs={jobs} dns={args.dns_timeout}s tcp={args.skip_tcp and 'skip' or args.tcp_timeout} "
        f"http={args.http_timeout}s est_max~{jobs * step_timeout:.0f}s"
    )
    _log("note: DNS/TCP are local; HTTP uses direct/proxy mode")
    if any(mode == "proxy" for mode, _, _ in modes):
        _log(f"proxy={args.proxy}")
    _log("")

    results = run_suite(
        modes,
        args.dns_timeout,
        args.tcp_timeout,
        args.http_timeout,
        args.skip_tcp,
    )
    _print_summary(results)

    failed = [item for item in results if not item.ok]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
