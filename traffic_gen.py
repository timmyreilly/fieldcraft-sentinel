#!/usr/bin/env python3
"""Generate demo traffic scenarios for Fieldcraft Sentinel to detect.

Deliberately restricted to loopback (127.0.0.1) targets by default so it's
safe to run without accidentally scanning/flooding real network segments.
Requires `nmap` and `hping` (installed via `sudo pacman -S nmap hping`), and
must be run alongside `sudo main.py --interface lo ...` to be observed.

Scenarios:
  port-scan   nmap TCP connect scan across many ports (trips RulesDetector's
              port_scan rule and LLMDetector's recon heuristic)
  syn-flood   hping SYN flood at a single port (trips RulesDetector's
              syn_flood rule)
  exfil       Large repeated payload transfer to simulate high byte volume
              (trips RulesDetector's volume_exfil rule and MLDetector's
              z-score anomaly once a baseline is established)
  baseline    Low, steady request rate to build a normal-traffic baseline
              for MLDetector before running an anomaly scenario
  all         Run baseline, then each attack scenario in sequence

Usage:
  python3 traffic_gen.py --scenario port-scan --target 127.0.0.1
  python3 traffic_gen.py --scenario all
"""
from __future__ import annotations

import argparse
import http.server
import subprocess
import threading
import time


def start_local_http_server(port: int) -> http.server.HTTPServer:
    handler = http.server.SimpleHTTPRequestHandler
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def run(cmd: list[str], **kwargs) -> None:
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=False, **kwargs)


def scenario_port_scan(target: str) -> None:
    print("=== port-scan: nmap TCP connect scan, ports 1-200 ===")
    run(["nmap", "-Pn", "-T4", "--min-rate", "500", "-p", "1-200", target])


def scenario_syn_flood(target: str, port: int, count: int) -> None:
    print(f"=== syn-flood: hping SYN flood at {target}:{port} ({count} packets) ===")
    # -S SYN, -p port, -c count, -i u1000 = 1000 microseconds between packets
    run(["sudo", "hping", "-S", "-p", str(port), "-c", str(count), "-i", "u1000", target])


def scenario_exfil(target: str, port: int, size_mb: int) -> None:
    print(f"=== exfil: {size_mb}MB transfer to {target}:{port} ===")
    server = start_local_http_server(port)
    try:
        payload_path = "/tmp/fieldcraft_exfil_payload.bin"
        run(["dd", "if=/dev/urandom", f"of={payload_path}", "bs=1M", f"count={size_mb}", "status=none"])
        for _ in range(3):
            run(["curl", "-s", "-o", "/dev/null", f"http://{target}:{port}/", "--data-binary", f"@{payload_path}", "-X", "POST"])
    finally:
        server.shutdown()


def scenario_baseline(target: str, port: int, requests: int, delay: float) -> None:
    print(f"=== baseline: {requests} small steady requests to {target}:{port} ===")
    server = start_local_http_server(port)
    try:
        for i in range(requests):
            run(["curl", "-s", "-o", "/dev/null", f"http://{target}:{port}/"])
            time.sleep(delay)
    finally:
        server.shutdown()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--scenario",
        choices=["port-scan", "syn-flood", "exfil", "baseline", "all"],
        required=True,
    )
    p.add_argument("--target", default="127.0.0.1", help="Restrict to loopback/local targets")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--syn-count", type=int, default=100)
    p.add_argument("--exfil-mb", type=int, default=8)
    p.add_argument("--baseline-requests", type=int, default=30)
    p.add_argument("--baseline-delay", type=float, default=0.5)
    args = p.parse_args()

    if not args.target.startswith("127.") and args.target != "localhost":
        print(
            f"Refusing to target {args.target!r}: this generator is restricted to "
            "loopback addresses. Pass --target 127.0.0.1 (default)."
        )
        return 1

    if args.scenario in ("baseline", "all"):
        scenario_baseline(args.target, args.port, args.baseline_requests, args.baseline_delay)
    if args.scenario in ("port-scan", "all"):
        scenario_port_scan(args.target)
    if args.scenario in ("syn-flood", "all"):
        scenario_syn_flood(args.target, args.port, args.syn_count)
    if args.scenario in ("exfil", "all"):
        scenario_exfil(args.target, args.port, args.exfil_mb)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
