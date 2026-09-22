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

## Notes / known constraints

- `pyshark` predates Python 3.14's asyncio changes; `main.py` includes a small
  compatibility shim (`set_child_watcher`/`get_child_watcher` no-ops) — safe
  because we don't rely on asyncio subprocess reaping semantics here.
- Verified end-to-end against the live Triage API on 2026-09-22: `--dry-run`
  and live loopback capture both produced real `202 Accepted` incidents.
