"""Flow tracking + four pluggable intrusion-detection algorithms.

Each detector consumes rolling per-source-IP flow statistics and returns a
Detection (or None). The pipeline in main.py turns a Detection into a
Fieldcraft Triage incident.
"""
from __future__ import annotations

import random
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PacketEvent:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str
    length: int
    flags: str = ""  # e.g. TCP flags string like "S", "SA", "PA"


@dataclass
class FlowWindow:
    """Rolling window of packet events for a single source IP."""

    packets: deque = field(default_factory=lambda: deque(maxlen=2000))

    def add(self, evt: PacketEvent) -> None:
        self.packets.append(evt)

    def prune(self, now: float, window_seconds: float) -> None:
        while self.packets and now - self.packets[0].ts > window_seconds:
            self.packets.popleft()

    # --- derived features -------------------------------------------------
    def packet_count(self) -> int:
        return len(self.packets)

    def byte_count(self) -> int:
        return sum(p.length for p in self.packets)

    def unique_dst_ports(self) -> set:
        return {p.dst_port for p in self.packets if p.dst_port is not None}

    def unique_dst_ips(self) -> set:
        return {p.dst_ip for p in self.packets}

    def syn_count(self) -> int:
        return sum(1 for p in self.packets if p.flags == "S")

    def mean_packet_size(self) -> float:
        if not self.packets:
            return 0.0
        return statistics.fmean(p.length for p in self.packets)


@dataclass
class Detection:
    algorithm: str
    severity: str  # info|low|medium|high|critical
    symptom: str
    src_ip: str
    details: list[str]
    score: float = 0.0


class BaseDetector:
    name = "base"

    def evaluate(self, src_ip: str, window: FlowWindow, now: float) -> Optional[Detection]:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# 1. basically-random: fires with a small fixed probability per evaluation.
#    Useful for exercising the pipeline/API without needing real attack
#    traffic; NOT a real detector.
# --------------------------------------------------------------------------- #
class RandomDetector(BaseDetector):
    name = "basically-random"

    def __init__(self, fire_probability: float = 0.02):
        self.fire_probability = fire_probability

    def evaluate(self, src_ip: str, window: FlowWindow, now: float) -> Optional[Detection]:
        if window.packet_count() == 0:
            return None
        if random.random() >= self.fire_probability:
            return None
        severity = random.choice(["info", "low", "medium", "high"])
        return Detection(
            algorithm=self.name,
            severity=severity,
            symptom=f"Randomly flagged traffic from {src_ip} (demo/no-signal detector).",
            src_ip=src_ip,
            details=[f"packets={window.packet_count()}", f"bytes={window.byte_count()}"],
            score=random.random(),
        )


# --------------------------------------------------------------------------- #
# 2. deterministic rules: SYN-flood, port-scan, and simple beacon/exfil
#    heuristics over a rolling window.
# --------------------------------------------------------------------------- #
class RulesDetector(BaseDetector):
    name = "deterministic-rules"

    def __init__(
        self,
        syn_flood_threshold: int = 40,
        port_scan_unique_ports: int = 15,
        exfil_byte_threshold: int = 5_000_000,
    ):
        self.syn_flood_threshold = syn_flood_threshold
        self.port_scan_unique_ports = port_scan_unique_ports
        self.exfil_byte_threshold = exfil_byte_threshold

    def evaluate(self, src_ip: str, window: FlowWindow, now: float) -> Optional[Detection]:
        syns = window.syn_count()
        if syns >= self.syn_flood_threshold:
            return Detection(
                algorithm=self.name,
                severity="high",
                symptom=f"Possible SYN flood from {src_ip}: {syns} SYNs in window.",
                src_ip=src_ip,
                details=[f"syn_count={syns}", "rule=syn_flood"],
                score=min(1.0, syns / (self.syn_flood_threshold * 2)),
            )

        ports = window.unique_dst_ports()
        if len(ports) >= self.port_scan_unique_ports:
            return Detection(
                algorithm=self.name,
                severity="medium",
                symptom=f"Possible port scan from {src_ip}: {len(ports)} distinct destination ports.",
                src_ip=src_ip,
                details=[f"unique_ports={len(ports)}", "rule=port_scan"],
                score=min(1.0, len(ports) / (self.port_scan_unique_ports * 2)),
            )

        total_bytes = window.byte_count()
        if total_bytes >= self.exfil_byte_threshold:
            return Detection(
                algorithm=self.name,
                severity="critical",
                symptom=f"Possible data exfiltration from {src_ip}: {total_bytes} bytes in window.",
                src_ip=src_ip,
                details=[f"bytes={total_bytes}", "rule=volume_exfil"],
                score=min(1.0, total_bytes / (self.exfil_byte_threshold * 2)),
            )
        return None


# --------------------------------------------------------------------------- #
# 3. ML model (STUB): placeholder anomaly-score model with a real interface
#    (extract_features -> score) so a trained scikit-learn/joblib model can
#    be dropped in later without changing the pipeline. Currently uses a
#    simple z-score over a running baseline instead of a trained model.
# --------------------------------------------------------------------------- #
class MLDetector(BaseDetector):
    name = "ml-model"

    def __init__(self, z_score_threshold: float = 3.0):
        self.z_score_threshold = z_score_threshold
        self._baseline: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def extract_features(self, window: FlowWindow) -> dict[str, float]:
        return {
            "packet_count": float(window.packet_count()),
            "byte_count": float(window.byte_count()),
            "unique_ports": float(len(window.unique_dst_ports())),
            "mean_packet_size": window.mean_packet_size(),
        }

    def score(self, features: dict[str, float], history: deque) -> float:
        """TODO: replace with model.predict(feature_vector) from a trained
        (e.g. IsolationForest / autoencoder) model loaded via joblib."""
        history.append(features["byte_count"])
        if len(history) < 10:
            return 0.0
        mean = statistics.fmean(history)
        stdev = statistics.pstdev(history) or 1.0
        return abs(features["byte_count"] - mean) / stdev

    def evaluate(self, src_ip: str, window: FlowWindow, now: float) -> Optional[Detection]:
        if window.packet_count() == 0:
            return None
        features = self.extract_features(window)
        z = self.score(features, self._baseline[src_ip])
        if z < self.z_score_threshold:
            return None
        return Detection(
            algorithm=self.name,
            severity="medium" if z < self.z_score_threshold * 1.5 else "high",
            symptom=f"[STUB ML MODEL] Anomalous byte-volume z-score {z:.2f} from {src_ip}.",
            src_ip=src_ip,
            details=[f"z_score={z:.2f}", *(f"{k}={v}" for k, v in features.items())],
            score=min(1.0, z / (self.z_score_threshold * 2)),
        )


# --------------------------------------------------------------------------- #
# 4. LLM (STUB): placeholder for a call to an LLM for reasoning over flow
#    summaries. Wire a real endpoint by setting FIELDCRAFT_LLM_ENDPOINT /
#    FIELDCRAFT_LLM_API_KEY and replacing `_stub_reasoning` with an HTTP call.
# --------------------------------------------------------------------------- #
class LLMDetector(BaseDetector):
    name = "llm"

    SUSPICIOUS_KEYWORDS = ("scan", "flood", "many", "unusual", "spike")

    def __init__(self, min_packets: int = 25):
        self.min_packets = min_packets

    def _summarize(self, src_ip: str, window: FlowWindow) -> str:
        ports = window.unique_dst_ports()
        return (
            f"host {src_ip} sent {window.packet_count()} packets "
            f"({window.byte_count()} bytes) to {len(window.unique_dst_ips())} destinations "
            f"across {len(ports)} unique ports in the recent window"
        )

    def _stub_reasoning(self, summary: str) -> tuple[bool, str, str]:
        """TODO: replace with a real LLM call, e.g.:
            response = requests.post(
                os.environ["FIELDCRAFT_LLM_ENDPOINT"],
                headers={"Authorization": f"Bearer {os.environ['FIELDCRAFT_LLM_API_KEY']}"},
                json={"prompt": PROMPT_TEMPLATE.format(summary=summary)},
            )
        For now, a keyword heuristic simulates "the LLM flagged this".
        """
        many_ports = "unique ports" in summary and any(
            tok.isdigit() and int(tok) >= 15
            for tok in summary.replace("(", " ").replace(")", " ").split()
        )
        if many_ports:
            return True, "high", f"[STUB LLM] Reasoned this looks like reconnaissance: {summary}"
        return False, "info", summary

    def evaluate(self, src_ip: str, window: FlowWindow, now: float) -> Optional[Detection]:
        if window.packet_count() < self.min_packets:
            return None
        summary = self._summarize(src_ip, window)
        flagged, severity, message = self._stub_reasoning(summary)
        if not flagged:
            return None
        return Detection(
            algorithm=self.name,
            severity=severity,
            symptom=message,
            src_ip=src_ip,
            details=[summary],
            score=0.75,
        )


DETECTORS = {
    "random": RandomDetector,
    "rules": RulesDetector,
    "ml": MLDetector,
    "llm": LLMDetector,
}
