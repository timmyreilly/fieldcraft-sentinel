#!/usr/bin/env python3
"""Fieldcraft Sentinel — network intrusion-attempt detector client.

Watches live traffic on a network interface, runs a selected detection
algorithm over rolling per-source-IP flow windows, and reports findings as
incidents to the Fieldcraft Triage API.

Usage:
  sudo .venv/bin/python main.py \\
      --bearer-token "$(cat token.txt)" \\
      --tenant-id smoke-tenant \\
      --algorithm rules \\
      --interface eth0

Run `--dry-run` to submit one synthetic incident without capturing traffic,
to validate credentials/connectivity against the live API.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import uuid
from typing import Optional

from api_client import Evidence, Incident, TriageApiClient, TriageApiError, now_iso
from detectors import DETECTORS, FlowWindow, PacketEvent

logger = logging.getLogger("fieldcraft_sentinel")

DEFAULT_API_BASE = "https://fieldcraft-triage-bqfkc5d6aufme9dc.b02.azurefd.net"
WINDOW_SECONDS = 30.0
EVAL_INTERVAL_SECONDS = 5.0


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fieldcraft Sentinel network intrusion detector")
    p.add_argument(
        "--bearer-token",
        required=True,
        help="Entra access token for api://fieldcraft-triage/Triage.Access "
        "(e.g. output of `az account get-access-token --scope ... --query accessToken -o tsv`)",
    )
    p.add_argument("--tenant-id", required=True, help="triage_tenant_id claim, e.g. smoke-tenant")
    p.add_argument("--api-base", default=DEFAULT_API_BASE, help="Triage API base URL")
    p.add_argument(
        "--algorithm",
        choices=sorted(DETECTORS.keys()),
        required=True,
        help="Detection algorithm: random | rules | ml | llm",
    )
    p.add_argument("--interface", default=None, help="Interface to capture on (default: auto)")
    p.add_argument(
        "--service", default="network-sentinel", help="`service` identifier reported to the API"
    )
    p.add_argument(
        "--source-system",
        default="fieldcraft-sentinel-nva",
        help="`sourceSystem` identifier reported to the API",
    )
    p.add_argument(
        "--min-severity",
        default="info",
        choices=["info", "low", "medium", "high", "critical"],
        help="Suppress detections below this severity before submitting",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Submit one synthetic test incident and exit (no packet capture)",
    )
    p.add_argument(
        "--mlflow",
        dest="mlflow_enabled",
        action="store_true",
        default=True,
        help="Log live detection counts/params to MLflow (default: on, local mlflow.db store)",
    )
    p.add_argument("--no-mlflow", dest="mlflow_enabled", action="store_false")
    p.add_argument(
        "--mlflow-experiment",
        default="fieldcraft-sentinel-live",
        help="MLflow experiment name for live runs",
    )
    p.add_argument(
        "--mlflow-tracking-uri",
        default=None,
        help="Override MLFLOW_TRACKING_URI (defaults to MLflow's local store; see README for "
        "pointing at the Azure ML workspace mlw-fieldcraft-dev instead)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_incident(detection, service: str, source_system: str) -> Incident:
    return Incident(
        service=service,
        symptom=detection.symptom,
        severity=detection.severity,
        source_system=source_system,
        source_event_id=f"{detection.algorithm}-{detection.src_ip}-{uuid.uuid4().hex[:12]}",
        evidence=[
            Evidence(
                kind="metric",
                summary="; ".join(detection.details) or "no additional detail",
                citation=f"algorithm={detection.algorithm};src_ip={detection.src_ip}",
                source=source_system,
            )
        ],
    )


def run_dry_run(client: TriageApiClient, service: str, source_system: str) -> int:
    incident = Incident(
        service=service,
        symptom="Fieldcraft Sentinel dry-run connectivity check.",
        severity="info",
        source_system=source_system,
        source_event_id=f"dry-run-{uuid.uuid4().hex[:12]}",
        evidence=[
            Evidence(
                kind="log_summary",
                summary="Synthetic incident submitted by --dry-run to validate credentials/schema.",
                citation="dry-run",
                source=source_system,
            )
        ],
    )
    try:
        result = client.submit_incident(incident)
    except TriageApiError as e:
        print(f"Dry-run FAILED: {e}", file=sys.stderr)
        return 1
    print(f"Dry-run OK: incident accepted -> {result.get('incidentId', result)}")
    return 0


def iter_packets(interface: Optional[str]):
    """Yield PacketEvent objects from a live tshark capture via pyshark."""
    import asyncio
    import types

    # pyshark (last released for asyncio's pre-3.12 child-watcher API) still
    # calls asyncio.set_child_watcher()/SafeChildWatcher, both removed in
    # Python 3.14. Python 3.14's default child-process reaping (via
    # ThreadedChildWatcher/PidfdChildWatcher under the hood) works fine
    # without those calls, so shim them to no-ops.
    if not hasattr(asyncio, "set_child_watcher"):
        asyncio.set_child_watcher = lambda *_a, **_k: None
    if not hasattr(asyncio, "SafeChildWatcher"):
        asyncio.SafeChildWatcher = type("SafeChildWatcher", (), {})
    if not hasattr(asyncio, "get_child_watcher"):
        _dummy_watcher = types.SimpleNamespace(attach_loop=lambda *_a, **_k: None)
        asyncio.get_child_watcher = lambda: _dummy_watcher

    import pyshark

    # Python 3.14 dropped implicit event-loop creation on the main thread;
    # pyshark still expects one to already exist.
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    # pyshark/tshark requires an explicit interface; "any" captures on all
    # interfaces (Linux libpcap pseudo-interface) when none is specified.
    capture = pyshark.LiveCapture(interface=interface or "any")
    for pkt in capture.sniff_continuously():
        try:
            length = int(pkt.length)
            src_ip = dst_ip = None
            proto = pkt.transport_layer or pkt.highest_layer
            src_port = dst_port = None
            flags = ""
            if hasattr(pkt, "ip"):
                src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            elif hasattr(pkt, "ipv6"):
                src_ip, dst_ip = pkt.ipv6.src, pkt.ipv6.dst
            else:
                continue
            if hasattr(pkt, "tcp"):
                src_port, dst_port = int(pkt.tcp.srcport), int(pkt.tcp.dstport)
                tcp_flags = getattr(pkt.tcp, "flags", "")
                if tcp_flags == "0x0002":
                    flags = "S"
                elif tcp_flags == "0x0012":
                    flags = "SA"
                elif tcp_flags == "0x0010":
                    flags = "A"
            elif hasattr(pkt, "udp"):
                src_port, dst_port = int(pkt.udp.srcport), int(pkt.udp.dstport)
            yield PacketEvent(
                ts=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto=proto,
                length=length,
                flags=flags,
            )
        except AttributeError:
            continue


def start_mlflow_run(args: argparse.Namespace, detector_cls) -> Optional["object"]:
    """Best-effort MLflow session for live detections. Never blocks the
    detector pipeline if MLflow/tracking backend is unavailable."""
    if not args.mlflow_enabled:
        return None
    try:
        os.environ.setdefault("MLFLOW_DISABLE_TELEMETRY", "1")
        import mlflow
    except ImportError:
        logger.warning("mlflow not installed; run `pip install mlflow` to enable --mlflow logging.")
        return None
    try:
        if args.mlflow_tracking_uri:
            mlflow.set_tracking_uri(args.mlflow_tracking_uri)
        elif not mlflow.get_tracking_uri() or mlflow.get_tracking_uri().startswith("file:"):
            import pathlib

            mlflow.set_tracking_uri(f"file:{pathlib.Path('mlruns').resolve()}")
        mlflow.set_experiment(args.mlflow_experiment)
        mlflow.start_run(run_name=f"live-{args.algorithm}-{detector_cls.version}")
        mlflow.log_param("algorithm", args.algorithm)
        mlflow.log_param("version", detector_cls.version)
        mlflow.log_param("interface", args.interface or "auto")
        mlflow.log_param("tenant_id", args.tenant_id)
        mlflow.log_param("min_severity", args.min_severity)
        logger.info("MLflow tracking to %s (experiment=%s)", mlflow.get_tracking_uri(), args.mlflow_experiment)
        return mlflow
    except Exception as e:  # pragma: no cover - best-effort telemetry only
        logger.warning("Failed to start MLflow run (continuing without it): %s", e)
        return None


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    client = TriageApiClient(args.api_base, args.tenant_id, args.bearer_token)

    if args.dry_run:
        return run_dry_run(client, args.service, args.source_system)

    if os.geteuid() != 0:
        logger.warning(
            "Not running as root/sudo — live packet capture will likely fail to open the interface."
        )

    detector = DETECTORS[args.algorithm]()
    logger.info("Starting Fieldcraft Sentinel with algorithm=%s interface=%s", args.algorithm, args.interface or "auto")

    mlflow = start_mlflow_run(args, DETECTORS[args.algorithm])
    severity_counts = {s: 0 for s in SEVERITY_RANK}

    windows: dict[str, FlowWindow] = {}
    last_eval = 0.0
    submitted = 0

    try:
        for evt in iter_packets(args.interface):
            windows.setdefault(evt.src_ip, FlowWindow()).add(evt)
            now = evt.ts
            if now - last_eval < EVAL_INTERVAL_SECONDS:
                continue
            last_eval = now
            for src_ip, window in list(windows.items()):
                window.prune(now, WINDOW_SECONDS)
                if window.packet_count() == 0:
                    del windows[src_ip]
                    continue
                detection = detector.evaluate(src_ip, window, now)
                if detection is None:
                    continue
                if SEVERITY_RANK[detection.severity] < SEVERITY_RANK[args.min_severity]:
                    continue
                incident = build_incident(detection, args.service, args.source_system)
                try:
                    result = client.submit_incident(incident)
                    submitted += 1
                    severity_counts[detection.severity] += 1
                    logger.info(
                        "Reported incident %s (severity=%s, algo=%s, src=%s)",
                        result.get("incidentId", "?"),
                        detection.severity,
                        detection.algorithm,
                        src_ip,
                    )
                    if mlflow is not None:
                        try:
                            mlflow.log_metric("incidents_reported", submitted, step=submitted)
                            mlflow.log_metric(
                                f"severity_{detection.severity}_count",
                                severity_counts[detection.severity],
                                step=submitted,
                            )
                        except Exception as e:  # pragma: no cover - best-effort telemetry only
                            logger.debug("MLflow metric logging failed: %s", e)
                except TriageApiError as e:
                    logger.error("Failed to submit incident: %s", e)
    except KeyboardInterrupt:
        logger.info("Stopping (submitted %d incidents this run).", submitted)
    finally:
        if mlflow is not None:
            try:
                mlflow.log_metric("total_incidents_reported", submitted)
                mlflow.end_run()
            except Exception:  # pragma: no cover - best-effort telemetry only
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
