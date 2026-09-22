# Fieldcraft Sentinel

Network intrusion-attempt detector client for the Fieldcraft Triage console
(`https://fieldcraft-triage-bqfkc5d6aufme9dc.b02.azurefd.net`).

Captures live traffic on a network interface (via `tshark`/`pyshark`), runs a
selected detection algorithm over rolling per-source-IP flow windows, and
reports findings as incidents to the Triage API
(`POST /tenants/{tenantId}/incidents`).

## Setup (already done on this VM)

```bash
sudo pacman -S wireshark-cli   # provides tshark
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Live capture needs raw-socket privileges — run with `sudo`, or
`sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python3)`
to avoid running the whole process as root.

## Getting a bearer token

```bash
az login --scope api://fieldcraft-triage/Triage.Access
TOKEN=$(az account get-access-token \
  --scope api://fieldcraft-triage/Triage.Access \
  --query accessToken --output tsv)
```

The `triage_tenant_id` claim in that token must match `--tenant-id` (e.g.
`smoke-tenant`).

## Usage

```bash
# Validate credentials/connectivity only (submits one synthetic incident):
python main.py --bearer-token "$TOKEN" --tenant-id smoke-tenant \
  --algorithm rules --dry-run

# Live capture + detection:
sudo .venv/bin/python main.py --bearer-token "$TOKEN" --tenant-id smoke-tenant \
  --algorithm rules --interface eth0
```

`--algorithm` selects one of four pluggable detectors (`detectors.py`):

| Algorithm | Class            | Behavior                                                            |
|-----------|------------------|----------------------------------------------------------------------|
| `random`  | `RandomDetector` | Fires with a small fixed probability; exercises the pipeline/API only. No real signal. |
| `rules`   | `RulesDetector`  | Deterministic thresholds: SYN-flood, port-scan, byte-volume exfil.   |
| `ml`      | `MLDetector`     | **Stub.** Z-score anomaly over a running per-source byte-volume baseline. Interface (`extract_features`/`score`) is ready for a real trained model (e.g. joblib-loaded `IsolationForest`). |
| `llm`     | `LLMDetector`    | **Stub.** Keyword heuristic simulating LLM reasoning over a flow summary. Replace `_stub_reasoning` with a real call to `FIELDCRAFT_LLM_ENDPOINT`/`FIELDCRAFT_LLM_API_KEY`. |

Other flags: `--service`, `--source-system`, `--min-severity`, `--api-base`,
`-v/--verbose`.

## Generating demo traffic (`traffic_gen.py`)

`traffic_gen.py` generates traffic scenarios for Sentinel to detect. It is
restricted to loopback targets (`127.0.0.1`) so it's safe to run without
accidentally scanning/flooding a real network segment. Requires `nmap` and
`hping` (`sudo pacman -S nmap hping` — already installed on this VM).

Run it in a **second terminal**, alongside Sentinel watching `lo`:

```bash
# terminal 1: start Sentinel watching the loopback interface
TOKEN=$(/home/omarchy/.azcli-venv/bin/az account get-access-token \
  --scope api://fieldcraft-triage/Triage.Access --query accessToken -o tsv)
sudo /home/omarchy/fieldcraft-sentinel/.venv/bin/python \
  /home/omarchy/fieldcraft-sentinel/main.py \
  --bearer-token "$TOKEN" --tenant-id smoke-tenant \
  --algorithm rules --interface lo -v

# terminal 2: fire a scenario (give Sentinel ~5s to finish starting tshark first)
python3 /home/omarchy/fieldcraft-sentinel/traffic_gen.py --scenario port-scan
```

Available scenarios (`--scenario`):

| Scenario    | What it does                                              | Trips                                      |
|-------------|------------------------------------------------------------|---------------------------------------------|
| `baseline`  | Steady low-rate requests to a throwaway local HTTP server  | Builds a normal-traffic baseline for `ml`   |
| `port-scan` | `nmap` TCP connect scan across ports 1-200                 | `rules` port-scan rule, `llm` recon heuristic |
| `syn-flood` | `hping` SYN flood at a single port                         | `rules` SYN-flood rule                      |
| `exfil`     | Large repeated payload upload (default 8MB)                | `rules` volume rule, `ml` anomaly z-score   |
| `all`       | Runs `baseline`, then `port-scan`, `syn-flood`, `exfil` in sequence | all of the above |

Useful flags: `--target` (default `127.0.0.1`, refuses non-loopback targets),
`--port` (default `8765`), `--syn-count`, `--exfil-mb`,
`--baseline-requests`, `--baseline-delay`.

Examples:

```bash
python3 traffic_gen.py --scenario syn-flood --syn-count 200
python3 traffic_gen.py --scenario exfil --exfil-mb 20
python3 traffic_gen.py --scenario all
```

You should see Sentinel log lines like:
```
INFO fieldcraft_sentinel: Reported incident incident-<id> (severity=high, algo=deterministic-rules, src=127.0.0.1)
```
and the incident will appear in the Triage console
(`https://fieldcraft-triage-bqfkc5d6aufme9dc.b02.azurefd.net/console`,
tenant `smoke-tenant`).

## Eval-ops: swapping detectors, corpus capture, and MLflow

Fieldcraft Sentinel is built so new detection algorithms can be developed,
backtested against real captured traffic, and shipped without touching the
live pipeline's control flow.

### Detector registry (how algorithms get swapped in)

`detectors.py` exposes `DETECTOR_REGISTRY` (dict of `name -> DetectorClass`),
each with a `version` and `description`. Every detector implements
`evaluate_features(src_ip, features, now)` against the shared
`FEATURE_NAMES` schema (`packet_count`, `byte_count`, `unique_ports`,
`unique_dst_ips`, `syn_count`, `mean_packet_size`) — `evaluate()` (used on
live `FlowWindow`s) is just a thin adapter onto that same method. This means
a corpus of feature rows can replay through any detector without a live
packet capture.

To ship a new/faster algorithm: implement a `BaseDetector` subclass, bump its
`version`, register it in `DETECTOR_REGISTRY`, backtest it with
`eval_harness.py` (below), then select it live with `--algorithm <name>`.

### Capturing a labeled traffic corpus

```bash
sudo .venv/bin/python corpus_capture.py --interface lo --run-id run-002
```

This drives `traffic_gen.py`'s scenarios (`baseline`, `port-scan`,
`syn-flood`, `exfil`) back-to-back, snapshotting flow features on an
independent 1-second wall-clock timer (decoupled from packet arrival so
fast scenarios like port-scan/syn-flood still get sampled), and clears flow
state between scenarios to avoid cross-scenario contamination. Output:

```
corpus/<run-id>/flow_features.csv   # labeled feature rows (data-scientist corpus)
corpus/<run-id>/pcap/<scenario>.pcap  # raw packets per scenario, for reprocessing
```

### Packaging a corpus run to send to data scientists

```bash
python3 - <<'PY'
import json, hashlib
from pathlib import Path
run_dir = Path("corpus/run-001")
manifest = {"run_id": run_dir.name, "files": []}
for p in sorted(run_dir.rglob("*")):
    if p.is_file() and p.name != "MANIFEST.json":
        manifest["files"].append({
            "path": str(p.relative_to(run_dir)),
            "size_bytes": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        })
json.dump(manifest, open(run_dir / "MANIFEST.json", "w"), indent=2)
PY
mkdir -p dist
tar -czf dist/fieldcraft-corpus-run-001.tar.gz -C corpus run-001
```

Ship `dist/fieldcraft-corpus-run-001.tar.gz` — it contains the labeled CSV,
per-scenario pcaps, the `eval_summary.json` baseline metrics, and a
checksummed `MANIFEST.json` for integrity verification. (`corpus/*/pcap/`
and `dist/` are gitignored — pcaps can be large and are meant to be shipped
as artifacts, not committed.)

### Offline backtesting (precision/recall/F1 per algorithm)

```bash
.venv/bin/python eval_harness.py --corpus corpus/run-001/flow_features.csv
```

Replays every labeled row through each registered detector's
`evaluate_features()`, treats `baseline` as the negative class and any other
scenario label as positive/attack, and prints + logs precision/recall/F1/
accuracy plus per-scenario detection rate. One MLflow run is logged per
algorithm (params: algorithm/version/description/corpus path+row count;
metrics: precision/recall/f1/accuracy/confusion-matrix counts). Also writes
`corpus/run-001/eval_summary.json` next to the corpus.

### Live MLflow logging

`main.py` logs live detection activity to MLflow by default (disable with
`--no-mlflow`):

```bash
sudo .venv/bin/python main.py --bearer-token "$TOKEN" --tenant-id smoke-tenant \
  --algorithm rules --interface lo \
  --mlflow-experiment fieldcraft-sentinel-live
```

Logs `incidents_reported` / `severity_<level>_count` per detection and
`total_incidents_reported` at shutdown, plus detector `algorithm`/`version`
as params.

### Where MLflow runs land

By default (no `MLFLOW_TRACKING_URI` set), MLflow 3.x uses its own local
SQLite store at `./mlflow.db` (gitignored) — inspect with:

```bash
.venv/bin/mlflow ui --backend-store-uri sqlite:///$(pwd)/mlflow.db
```

To report into the Azure ML workspace's MLflow tracking server instead
(`mlw-fieldcraft-dev`, subscription `feb19c97-3e24-4bff-a8eb-79400052dc9f`,
resource group `rg-fieldcraft-dev`):

```bash
pip install azureml-mlflow
az login   # needs access to subscription feb19c97-3e24-4bff-a8eb-79400052dc9f
export MLFLOW_TRACKING_URI="azureml://<region>.api.azureml.ms/mlflow/v1.0/subscriptions/feb19c97-3e24-4bff-a8eb-79400052dc9f/resourceGroups/rg-fieldcraft-dev/providers/Microsoft.MachineLearningServices/workspaces/mlw-fieldcraft-dev"
# or: az ml workspace show -n mlw-fieldcraft-dev -g rg-fieldcraft-dev --query mlFlowTrackingUri -o tsv
```

Both `eval_harness.py --tracking-uri <uri>` and `main.py --mlflow-tracking-uri
<uri>` also accept it directly as a flag.

MLflow's anonymous telemetry is disabled by default in this repo
(`MLFLOW_DISABLE_TELEMETRY=1` set in `main.py`/`eval_harness.py`) so no usage
data leaves the machine beyond the tracking store you configure.

## Notes / known constraints

- `pyshark` predates Python 3.14's asyncio changes; `main.py` includes a small
  compatibility shim (`set_child_watcher`/`get_child_watcher` no-ops) — safe
  because we don't rely on asyncio subprocess reaping semantics here.
- Verified end-to-end against the live Triage API on 2026-09-22: `--dry-run`
  and live loopback capture both produced real `202 Accepted` incidents.
