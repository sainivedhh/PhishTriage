"""Evaluation engine calculating Precision, Recall, F1, Confusion Matrix, and Rule Attribution."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from rich.console import Console
from rich.table import Table

from phishtriage.models import IncidentReport, Verdict
from phishtriage.pipeline import PhishTriagePipeline


class DatasetEvaluator:
    """Evaluates the pipeline against a ground-truth dataset and computes metrics."""

    def __init__(
        self,
        rules_path: str = "rules/detection_rules.yaml",
        blocklist_path: str = "blocklist_hashes.txt",
        dataset_dir: str = "data/synthetic_dataset",
        labels_file: str = "data/synthetic_dataset/labels.json",
    ) -> None:
        self.dataset_dir = Path(dataset_dir)
        self.labels_file = Path(labels_file)
        self.pipeline = PhishTriagePipeline(rules_path=rules_path, blocklist_path=blocklist_path, db_path=":memory:")
        self.console = Console()

    def run_eval(self) -> Dict[str, Any]:
        with open(self.labels_file, "r", encoding="utf-8") as f:
            ground_truth: Dict[str, str] = json.load(f)

        tp = 0
        fp = 0
        tn = 0
        fn = 0

        false_positives: List[Dict[str, Any]] = []
        false_negatives: List[Dict[str, Any]] = []

        total_samples = len(ground_truth)

        for filename, expected_label in ground_truth.items():
            sample_file = self.dataset_dir / filename
            if not sample_file.exists():
                continue

            report: IncidentReport = self.pipeline.process_file(sample_file)
            
            # Binary classification: 'malicious' and 'suspicious' are treated as positive detections for security review
            is_predicted_positive = report.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            is_actual_positive = expected_label.lower() in ("malicious", "phishing", "bec")

            triggered_rules = [f.rule_id for f in report.score_breakdown]

            if is_actual_positive and is_predicted_positive:
                tp += 1
            elif not is_actual_positive and not is_predicted_positive:
                tn += 1
            elif not is_actual_positive and is_predicted_positive:
                fp += 1
                false_positives.append({
                    "file": filename,
                    "expected": expected_label,
                    "predicted_verdict": report.verdict.value,
                    "score": report.score,
                    "rules": triggered_rules,
                })
            elif is_actual_positive and not is_predicted_positive:
                fn += 1
                false_negatives.append({
                    "file": filename,
                    "expected": expected_label,
                    "predicted_verdict": report.verdict.value,
                    "score": report.score,
                    "rules": triggered_rules,
                })

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / total_samples if total_samples > 0 else 0.0

        return {
            "total": total_samples,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "false_positives": false_positives,
            "false_negatives": false_negatives,
        }

    def run_and_print(self) -> Dict[str, Any]:
        results = self.run_eval()

        # Summary Metrics Table
        table = Table(title="PhishTriage Pipeline Evaluation Results", show_lines=True)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="bold green", justify="right")

        table.add_row("Total Samples Evaluated", str(results["total"]))
        table.add_row("Accuracy", f"{results['accuracy'] * 100:.2f}%")
        table.add_row("Precision", f"{results['precision'] * 100:.2f}%")
        table.add_row("Recall", f"{results['recall'] * 100:.2f}%")
        table.add_row("F1-Score", f"{results['f1']:.4f}")

        self.console.print(table)

        # Confusion Matrix Table
        cm_table = Table(title="Confusion Matrix", show_lines=True)
        cm_table.add_column("Actual \\ Predicted", style="bold")
        cm_table.add_column("Positive (Malicious/Suspicious)", justify="center", style="green")
        cm_table.add_column("Negative (Benign)", justify="center", style="green")

        cm_table.add_row("Actual Positive", f"TP: {results['tp']}", f"FN: {results['fn']}")
        cm_table.add_row("Actual Negative", f"FP: {results['fp']}", f"TN: {results['tn']}")

        self.console.print(cm_table)

        # False Positives Breakdown
        if results["false_positives"]:
            fp_table = Table(title="False Positives (Benign flagged as Positive)", show_lines=True)
            fp_table.add_column("File", style="red")
            fp_table.add_column("Score", justify="center")
            fp_table.add_column("Triggered Rules", style="yellow")
            for fp_item in results["false_positives"]:
                fp_table.add_row(fp_item["file"], str(fp_item["score"]), ", ".join(fp_item["rules"]))
            self.console.print(fp_table)
        else:
            self.console.print("[bold green]Zero False Positives recorded.[/bold green]")

        # False Negatives Breakdown
        if results["false_negatives"]:
            fn_table = Table(title="False Negatives (Malicious missed as Benign)", show_lines=True)
            fn_table.add_column("File", style="red")
            fn_table.add_column("Score", justify="center")
            fn_table.add_column("Triggered Rules", style="yellow")
            for fn_item in results["false_negatives"]:
                fn_table.add_row(fn_item["file"], str(fn_item["score"]), ", ".join(fn_item["rules"]))
            self.console.print(fn_table)
        else:
            self.console.print("[bold green]Zero False Negatives recorded.[/bold green]")

        return results
