#!/usr/bin/env python3
"""Capture a labeled corpus of traffic for data-science backtesting.

Runs each `traffic_gen.py` scenario against loopback while a live capture
(the same tshark/pyshark capture path Sentinel uses) tags per-source-IP flow
feature snapshots with the active scenario name. Produces two artifacts data
scientists can use interchangeably:

  1. A labeled flow-feature CSV (one row per periodic snapshot per src_ip),
     matching the exact feature schema every detector consumes
     (`detectors.FEATURE_NAMES`) — quick to load in pandas for backtesting
     new algorithms without re-parsing packets.
  2. A raw .pcap per scenario (via `tshark -w`) for full-fidelity
     reprocessing/relabeling later.

Snapshots are taken on a fixed wall-clock timer (independent of packet
arrival) so a scenario is always captured even if it completes faster than
the snapshot interval (e.g. an nmap scan finishes in well under a second).
Per-source-IP flow state is reset at every scenario boundary so one
scenario's traffic can't bleed into the next scenario's feature snapshot.

Usage:
  sudo .venv/bin/python corpus_capture.py --interface lo --out-dir corpus/run-001

Must run as root/sudo (same privilege requirement as main.py) since it
opens a live capture.
"""
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from detectors import FEATURE_NAMES, FlowWindow
import main as sentinel_main
import traffic_gen

WINDOW_SECONDS = 10.0
SNAPSHOT_INTERVAL_SECONDS = 1.0
SETTLE_SECONDS = 2.0  # time to let a scenario's packets finish arriving

SCENARIOS = ("baseline", "port-scan", "syn-flood", "exfil")


class LabeledCapture:
    """Consumes live packets on one thread; snapshots flow features to CSV
    on an independent wall-clock timer thread, tagged with whatever
    scenario label is currently active."""

    def __init__(self, interface: str, csv_path: Path):
        self.interface = interface
        self.csv_path = csv_path
        self.current_label = "unlabeled"
        self._windows: dict[str, FlowWindow] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._rows_written = 0
        self._packet_thread = threading.Thread(target=self._consume_packets, daemon=True)
        self._snapshot_thread = threading.Thread(target=self._snapshot_loop, daemon=True)

    def start(self) -> None:
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._csv_file = open(self.csv_path, "w", newline="")
        self._writer = csv.writer(self._csv_file)
        self._writer.writerow(["timestamp", "scenario_label", "src_ip", *FEATURE_NAMES])
        self._packet_thread.start()
        self._snapshot_thread.start()

    def set_label(self, label: str) -> None:
        print(f"[corpus_capture] label -> {label}")
        with self._lock:
            self.current_label = label

    def clear_windows(self) -> None:
        """Reset per-source flow state so the next scenario's snapshot
        can't include packets from a previous scenario."""
        with self._lock:
            self._windows = {}

    def stop(self) -> None:
        self._stop.set()
        self._packet_thread.join(timeout=5)
        self._snapshot_thread.join(timeout=5)
        self._csv_file.close()
        print(f"[corpus_capture] wrote {self._rows_written} rows to {self.csv_path}")

    def _consume_packets(self) -> None:
        for evt in sentinel_main.iter_packets(self.interface):
            if self._stop.is_set():
                break
            with self._lock:
                self._windows.setdefault(evt.src_ip, FlowWindow()).add(evt)

    def _snapshot_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(SNAPSHOT_INTERVAL_SECONDS)
            now = time.time()
            with self._lock:
                label = self.current_label
                for src_ip, window in list(self._windows.items()):
                    window.prune(now, WINDOW_SECONDS)
                    if window.packet_count() == 0:
                        del self._windows[src_ip]
                        continue
                    features = window.to_features()
                    self._writer.writerow(
                        [now, label, src_ip, *(features[f] for f in FEATURE_NAMES)]
                    )
                    self._rows_written += 1
                self._csv_file.flush()


def capture_pcap(interface: str, pcap_path: Path) -> subprocess.Popen:
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    return subprocess.Popen(
        ["tshark", "-i", interface, "-w", str(pcap_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_scenario(name: str, target: str = "127.0.0.1") -> None:
    if name == "baseline":
        traffic_gen.scenario_baseline(target, 8765, requests=30, delay=0.4)
    elif name == "port-scan":
        traffic_gen.scenario_port_scan(target)
    elif name == "syn-flood":
        traffic_gen.scenario_syn_flood(target, 8765, count=100)
    elif name == "exfil":
        traffic_gen.scenario_exfil(target, 8765, size_mb=8)
    else:
        raise ValueError(f"Unknown scenario: {name}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--interface", default="lo")
    p.add_argument("--out-dir", default="corpus/run-001")
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument(
        "--scenarios",
        nargs="+",
        default=list(SCENARIOS),
        choices=list(SCENARIOS),
        help="Scenarios to run in sequence (default: all four)",
    )
    args = p.parse_args()

    if os.geteuid() != 0:
        print("Must run as root/sudo (live capture requires raw-socket privileges).", file=sys.stderr)
        return 1

    out_dir = Path(args.out_dir)
    csv_path = out_dir / "flow_features.csv"
    capture = LabeledCapture(args.interface, csv_path)
    capture.start()
    time.sleep(2)  # let tshark spin up before generating traffic

    for scenario in args.scenarios:
        capture.clear_windows()
        pcap_path = out_dir / "pcap" / f"{scenario}.pcap"
        pcap_proc = capture_pcap(args.interface, pcap_path)
        time.sleep(1)  # let tshark bind before we start generating traffic
        capture.set_label(scenario)
        try:
            run_scenario(scenario, args.target)
        finally:
            time.sleep(SETTLE_SECONDS)  # guarantee >=1 snapshot captures the burst
            pcap_proc.terminate()
            pcap_proc.wait(timeout=5)
        capture.set_label("unlabeled")
        capture.clear_windows()  # don't let this scenario bleed into the next

    capture.stop()
    print(f"[corpus_capture] corpus written to {out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
