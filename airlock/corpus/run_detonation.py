"""
airlock.corpus.run_detonation
===============================

Detonates every sample of the detonation corpus
(airlock/corpus/detonation/{malicious,benign}/) and measures how the dynamic
stage classifies it. This is the "the corpus becomes a test set: measure false
positives / negatives" deliverable, for the behavioural stage.

A sample is predicted "malicious" when the detonation produced at least one
finding (a Falco behaviour or a sink canary hit), and "benign" otherwise.

Unlike the static corpus, this one needs the whole sandbox:
  - rootless Podman and the `localhost/airlock-sandbox:1` image (build it with
    `podman build -t localhost/airlock-sandbox:1 sandbox/`);
  - the Falco sensor running as root (`sudo sandbox/falco.sh start`), otherwise
    the file-only samples (persistence, dropper) cannot be seen and the run is
    reported as sensor-blind.

Output: airlock/corpus/detonation_eval_report.json.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

from airlock.detonation import sandbox

CORPUS_DIR = Path(__file__).parent / "detonation"
REPORT_PATH = Path(__file__).parent / "detonation_eval_report.json"


def _ecosystem_of(sample_dir: Path) -> str:
    if (sample_dir / "package.json").exists():
        return "npm"
    if (sample_dir / "setup.py").exists() or (sample_dir / "PKG-INFO").exists():
        return "pypi"
    raise ValueError(f"cannot tell the ecosystem of {sample_dir}")


def pack_sample(sample_dir: Path, ecosystem: str, dest_dir: Path) -> Path:
    """
    Build an archive with the layout the real registry would serve:
      - npm: a .tgz whose files live under `package/` (like `npm pack`);
      - pypi: a sdist .tar.gz whose files live under `<name>-<version>/`.
    """
    if ecosystem == "npm":
        prefix, archive = "package", dest_dir / f"{sample_dir.name}.tgz"
    else:
        prefix, archive = f"{sample_dir.name}-1.0.0", dest_dir / f"{sample_dir.name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for path in sorted(sample_dir.rglob("*")):
            if path.is_file():
                tar.add(path, arcname=f"{prefix}/{path.relative_to(sample_dir).as_posix()}")
    return archive


def detonate_sample(sample_dir: Path, dest_dir: Path) -> dict:
    ecosystem = _ecosystem_of(sample_dir)
    archive = pack_sample(sample_dir, ecosystem, dest_dir)
    result = sandbox.detonate(archive, ecosystem)
    predicted = "malicious" if result.findings else "benign"
    return {
        "sample": sample_dir.name,
        "ecosystem": ecosystem,
        "predicted": predicted,
        "sensor_alive": result.sensor_alive,
        "findings": [f.to_dict() for f in result.findings],
        "dns_queries": result.dns_queries,
        "duration_seconds": result.duration_seconds,
        "error_message": result.error_message,
    }


def run_detonation_eval(dest_dir: Path | None = None) -> dict:
    dest_dir = dest_dir or (CORPUS_DIR / ".archives")
    dest_dir.mkdir(parents=True, exist_ok=True)

    samples: list[dict] = []
    for label in ("malicious", "benign"):
        for sample_dir in sorted((CORPUS_DIR / label).iterdir()):
            if not sample_dir.is_dir():
                continue
            record = detonate_sample(sample_dir, dest_dir)
            record["expected"] = label
            record["correct"] = record["predicted"] == label
            samples.append(record)

    tp = sum(1 for s in samples if s["expected"] == "malicious" and s["predicted"] == "malicious")
    fn = sum(1 for s in samples if s["expected"] == "malicious" and s["predicted"] == "benign")
    tn = sum(1 for s in samples if s["expected"] == "benign" and s["predicted"] == "benign")
    fp = sum(1 for s in samples if s["expected"] == "benign" and s["predicted"] == "malicious")
    total = len(samples) or 1

    return {
        "sensor_alive_for_all": all(s["sensor_alive"] for s in samples),
        "confusion_matrix": {
            "true_positives": tp, "false_negatives": fn,
            "true_negatives": tn, "false_positives": fp,
        },
        "metrics": {
            "accuracy": (tp + tn) / total,
            "precision": tp / (tp + fp) if (tp + fp) else None,
            "recall": tp / (tp + fn) if (tp + fn) else None,
        },
        "samples": samples,
    }


if __name__ == "__main__":
    report = run_detonation_eval()
    REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    cm = report["confusion_matrix"]
    if not report["sensor_alive_for_all"]:
        print("WARNING: Falco did not see every detonation. File-only samples "
              "(persistence, dropper) need `sudo sandbox/falco.sh start`.\n")
    print(
        f"--- Summary ---\n"
        f"TP={cm['true_positives']} FN={cm['false_negatives']} "
        f"TN={cm['true_negatives']} FP={cm['false_positives']}\n"
        f"Full report: {REPORT_PATH}"
    )
