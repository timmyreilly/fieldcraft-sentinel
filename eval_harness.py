#!/usr/bin/env python3
"""Offline eval-ops harness: replay a labeled corpus through one or more
detector algorithms and log precision/recall/F1 to MLflow.

This is how a new/more-performant algorithm gets backtested and compared
against the current production algorithm *before* shipping it via
`main.py --algorithm <name>`.

By default this logs to MLflow's local tracking store (SQLite `./mlflow.db`
in MLflow 3.x, created next to this script). To report into the Azure ML
workspace's MLflow tracking server instead, set MLFLOW_TRACKING_URI, e.g.:

  export MLFLOW_TRACKING_URI="azureml://<region>.api.azureml.ms/mlflow/v1.0/subscriptions/feb19c97-3e24-4bff-a8eb-79400052dc9f/resourceGroups/rg-fieldcraft-dev/providers/Microsoft.MachineLearningServices/workspaces/mlw-fieldcraft-dev"

(requires `azureml-mlflow` and an authenticated `az login` session; see
README.md "MLflow / eval-ops" section).

Usage:
  python3 eval_harness.py --corpus corpus/run-001/flow_features.csv
  python3 eval_harness.py --corpus corpus/run-001/flow_features.csv --algorithm rules ml
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import defaultdict
from pathlib import Path

os.environ.setdefault("MLFLOW_DISABLE_TELEMETRY", "1")

import mlflow

from detectors import DETECTOR_REGISTRY, FEATURE_NAMES

NEGATIVE_LABELS = {"baseline"}
IGNORED_LABELS = {"unlabeled"}


def load_corpus(csv_path: Path) -> list[dict]:
    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["timestamp"] = float(row["timestamp"])
            for feat in FEATURE_NAMES:
                row[feat] = float(row[feat])
            rows.append(row)
    rows.sort(key=lambda r: r["timestamp"])
    return rows


def evaluate_algorithm(name: str, rows: list[dict]) -> dict:
    detector_cls = DETECTOR_REGISTRY[name]
    detector = detector_cls()

    tp = fp = tn = fn = 0
    per_scenario_detections: dict[str, int] = defaultdict(int)
    per_scenario_totals: dict[str, int] = defaultdict(int)

    for row in rows:
        label = row["scenario_label"]
        if label in IGNORED_LABELS:
            continue
        features = {f: row[f] for f in FEATURE_NAMES}
        detection = detector.evaluate_features(row["src_ip"], features, row["timestamp"])
        detected = detection is not None
        is_attack = label not in NEGATIVE_LABELS

        per_scenario_totals[label] += 1
        if detected:
            per_scenario_detections[label] += 1

        if is_attack and detected:
            tp += 1
        elif is_attack and not detected:
            fn += 1
        elif not is_attack and detected:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0

    return {
        "algorithm": name,
        "version": detector_cls.version,
        "description": detector_cls.description,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "per_scenario_detection_rate": {
            label: per_scenario_detections[label] / total
            for label, total in per_scenario_totals.items()
        },
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--corpus", required=True, help="Path to a labeled flow_features.csv from corpus_capture.py")
    p.add_argument(
        "--algorithm",
        nargs="+",
        default=list(DETECTOR_REGISTRY.keys()),
        choices=list(DETECTOR_REGISTRY.keys()),
        help="Algorithms to evaluate (default: all registered)",
    )
    p.add_argument(
        "--experiment",
        default="fieldcraft-sentinel-detector-eval",
        help="MLflow experiment name",
    )
    p.add_argument(
        "--tracking-uri",
        default=None,
        help="Override MLFLOW_TRACKING_URI (defaults to MLflow's local store if unset)",
    )
    args = p.parse_args()

    if args.tracking_uri:
        mlflow.set_tracking_uri(args.tracking_uri)
    elif not mlflow.get_tracking_uri() or mlflow.get_tracking_uri().startswith("file:"):
        mlflow.set_tracking_uri(f"file:{Path('mlruns').resolve()}")

    mlflow.set_experiment(args.experiment)

    corpus_path = Path(args.corpus)
    rows = load_corpus(corpus_path)
    print(f"Loaded {len(rows)} labeled rows from {corpus_path}")

    results = []
    for name in args.algorithm:
        result = evaluate_algorithm(name, rows)
        results.append(result)
        with mlflow.start_run(run_name=f"{name}-{result['version']}"):
            mlflow.log_param("algorithm", name)
            mlflow.log_param("version", result["version"])
            mlflow.log_param("description", result["description"])
            mlflow.log_param("corpus", str(corpus_path))
            mlflow.log_param("corpus_rows", len(rows))
            mlflow.log_metric("precision", result["precision"])
            mlflow.log_metric("recall", result["recall"])
            mlflow.log_metric("f1", result["f1"])
            mlflow.log_metric("accuracy", result["accuracy"])
            mlflow.log_metric("true_positives", result["true_positives"])
            mlflow.log_metric("false_positives", result["false_positives"])
            mlflow.log_metric("true_negatives", result["true_negatives"])
            mlflow.log_metric("false_negatives", result["false_negatives"])
            for label, rate in result["per_scenario_detection_rate"].items():
                mlflow.log_metric(f"detection_rate_{label}", rate)
            mlflow.log_artifact(str(corpus_path))
            print(
                f"[{name} v{result['version']}] precision={result['precision']:.2f} "
                f"recall={result['recall']:.2f} f1={result['f1']:.2f} "
                f"(tp={result['true_positives']} fp={result['false_positives']} "
                f"tn={result['true_negatives']} fn={result['false_negatives']})"
            )

    summary_path = corpus_path.parent / "eval_summary.json"
    summary_path.write_text(json.dumps(results, indent=2))
    print(f"Summary written to {summary_path}")
    print(f"MLflow tracking URI: {mlflow.get_tracking_uri()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
