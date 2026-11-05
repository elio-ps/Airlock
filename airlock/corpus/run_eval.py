"""
airlock.corpus.run_eval
=========================

Runs the GuardDog source code analyzer on each sample of the reference corpus
(airlock/corpus/samples/{malicious,benign}/) and compares the result with the
expected label (taken from the parent directory).

Decision criterion (consistent with airlock.verdict.aggregate): a sample is
"suspicious" when at least one `threat-*` rule triggers. `capability-*` rules
(file, network, process access...) are ignored here: they describe what code
can do, not malicious behaviour, and almost all legitimate code has them.

Output: a JSON report with a confusion matrix (TP/TN/FP/FN) and per-sample
details.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from guarddog.analyzer.analyzer import Analyzer

CORPUS_DIR = Path(__file__).parent / "samples"
THREAT_PREFIX = "threat-"


def _rule_triggered(value) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, dict)) and len(value) == 0:
        return False
    return True


@dataclass
class SampleVerdict:
    sample_path: str
    expected_label: str        # "malicious" | "benign"
    predicted_label: str       # "malicious" | "benign"
    triggered_threat_rules: list[str] = field(default_factory=list)
    correct: bool = False

    def to_dict(self) -> dict:
        return {
            "sample": self.sample_path,
            "expected": self.expected_label,
            "predicted": self.predicted_label,
            "triggered_threat_rules": self.triggered_threat_rules,
            "correct": self.correct,
        }


def analyze_sample(file_path: Path, analyzer: Analyzer) -> list[str]:
    """
    GuardDog analyses a DIRECTORY, not a single file: each sample is copied
    alone into a temporary directory so that samples cannot contaminate each
    other.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp) / file_path.name
        tmp_path.write_bytes(file_path.read_bytes())
        raw = analyzer.analyze_sourcecode(str(tmp))
        results = raw.get("results", {})
        return [
            rule for rule, value in results.items()
            if rule.startswith(THREAT_PREFIX) and _rule_triggered(value)
        ]


def run_corpus_eval() -> dict:
    analyzer = Analyzer()
    verdicts: list[SampleVerdict] = []

    for label, subdir in (("malicious", "malicious"), ("benign", "benign")):
        folder = CORPUS_DIR / subdir
        for sample_path in sorted(folder.glob("*")):
            if sample_path.name.startswith(("MANIFEST", "THIRD_PARTY")):
                continue
            if not sample_path.is_file():
                continue
            triggered = analyze_sample(sample_path, analyzer)
            predicted = "malicious" if triggered else "benign"
            verdicts.append(SampleVerdict(
                sample_path=str(sample_path.relative_to(CORPUS_DIR)),
                expected_label=label,
                predicted_label=predicted,
                triggered_threat_rules=triggered,
                correct=(predicted == label),
            ))

    tp = sum(1 for v in verdicts if v.expected_label == "malicious" and v.predicted_label == "malicious")
    fn = sum(1 for v in verdicts if v.expected_label == "malicious" and v.predicted_label == "benign")
    tn = sum(1 for v in verdicts if v.expected_label == "benign" and v.predicted_label == "benign")
    fp = sum(1 for v in verdicts if v.expected_label == "benign" and v.predicted_label == "malicious")

    total = len(verdicts)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None

    return {
        "confusion_matrix": {
            "true_positives": tp, "false_negatives": fn,
            "true_negatives": tn, "false_positives": fp,
        },
        "metrics": {"accuracy": accuracy, "precision": precision, "recall": recall},
        "samples": [v.to_dict() for v in verdicts],
    }


if __name__ == "__main__":
    report = run_corpus_eval()
    print(json.dumps(report, indent=2, ensure_ascii=False))

    out_path = CORPUS_DIR.parent / "corpus_eval_report.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    cm = report["confusion_matrix"]
    m = report["metrics"]
    print(
        f"\n--- Summary ---\n"
        f"TP={cm['true_positives']} FN={cm['false_negatives']} "
        f"TN={cm['true_negatives']} FP={cm['false_positives']}\n"
        f"Accuracy={m['accuracy']:.2f} Precision={m['precision']} Recall={m['recall']}\n"
        f"Full report: {out_path}"
    )
