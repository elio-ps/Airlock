"""
Tests of the detonation logic that need neither Podman nor Falco. Real
detonations are covered by `airlock.corpus.run_detonation`.

Run: python3 -m pytest airlock/tests/test_detonation.py -v
"""

from __future__ import annotations

import base64
import json

from airlock.detonation import sandbox
from airlock.detonation.sandbox import DetonationFinding, DetonationResult, analyse_sink_log
from airlock.verdict.aggregate import Policy, StageStatus, Verdict, aggregate

CANARY = "AIRLOCKCANARY0123456789abcdef"


def _tcp_line(payload: bytes) -> str:
    return json.dumps({"kind": "tcp", "port": 80, "data": base64.b64encode(payload).decode()})


def _dns_line(name: str) -> str:
    return json.dumps({"kind": "dns", "name": name})


def test_sink_finds_plain_canary():
    findings, _ = analyse_sink_log(_tcp_line(f"POST / HTTP/1.1\r\n\r\nkey={CANARY}".encode()), CANARY)
    assert [f.rule for f in findings] == ["canary_exfiltrated"]


def test_sink_finds_base64_encoded_canary():
    encoded = base64.b64encode(f"secret={CANARY}".encode())
    findings, _ = analyse_sink_log(_tcp_line(b"data=" + encoded), CANARY)
    assert findings


def test_sink_reassembles_canary_split_across_dns_queries():
    """The home-made grabber chunks hex across many queries to one base domain."""
    hexa = f"token={CANARY}".encode().hex()
    chunks = [hexa[i:i + 20] for i in range(0, len(hexa), 20)]
    log = "\n".join(_dns_line(f"{chunk}.exfil.example.invalid") for chunk in chunks)
    findings, names = analyse_sink_log(log, CANARY)
    assert [f.rule for f in findings] == ["canary_exfiltrated"]
    assert len(names) == len(chunks)


def test_sink_does_not_merge_two_different_base_domains():
    """Chunks must reassemble per domain, not across unrelated queries."""
    hexa = f"token={CANARY}".encode().hex()
    log = "\n".join([
        _dns_line(f"{hexa[:20]}.one.example.invalid"),
        _dns_line(f"{hexa[20:]}.two.example.invalid"),
    ])
    findings, _ = analyse_sink_log(log, CANARY)
    assert findings == []


def test_sink_ignores_traffic_without_canary():
    log = _tcp_line(b"GET / HTTP/1.1\r\n\r\n") + "\n" + _dns_line("registry.npmjs.org") + "\nnot json"
    findings, names = analyse_sink_log(log, CANARY)
    assert findings == [] and names == ["registry.npmjs.org"]


def _falco_line(rule: str, container: str = "abc123def456", priority: str = "Critical") -> str:
    return json.dumps({"rule": rule, "priority": priority, "output": "x",
                       "output_fields": {"container.id": container}})


def test_events_before_sentinel_and_of_other_containers_are_dropped(tmp_path, monkeypatch):
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join([
        _falco_line("airlock_persistence_write"),          # harness writing the decoys
        _falco_line(sandbox.SENTINEL_RULE),
        _falco_line("airlock_decoy_secret_read"),
        _falco_line("airlock_decoy_secret_read", container="ffffffffffff"),
    ]) + "\n")
    monkeypatch.setattr(sandbox, "FALCO_EVENTS", events)
    kept = sandbox._read_falco_events(0, "abc123def456" + "0" * 52)
    assert [e["rule"] for e in kept] == [sandbox.SENTINEL_RULE, "airlock_decoy_secret_read"]


def test_no_sentinel_means_no_event_is_trusted(tmp_path, monkeypatch):
    events = tmp_path / "events.jsonl"
    events.write_text(_falco_line("airlock_decoy_secret_read") + "\n")
    monkeypatch.setattr(sandbox, "FALCO_EVENTS", events)
    monkeypatch.setattr(sandbox, "FALCO_FLUSH_TIMEOUT", 0)
    assert sandbox._read_falco_events(0, "abc123def456" + "0" * 52) == []


def _verdict(result: DetonationResult, hooks=None, policy=None):
    return aggregate(package_name="p", version="1", ecosystem="npm", detonation_result=result,
                     install_hooks=hooks, policy=policy)


def test_critical_behaviour_blocks():
    result = DetonationResult(sensor_alive=True, findings=[
        DetonationFinding("falco", "airlock_decoy_secret_read", "Critical", "file=/home/dev/.npmrc"),
    ])
    assert _verdict(result).verdict == Verdict.BLOCK


def test_warning_behaviour_quarantines():
    result = DetonationResult(sensor_alive=True, findings=[
        DetonationFinding("falco", "airlock_outbound_connection", "Warning", "dest=10.0.0.1"),
    ])
    assert _verdict(result).verdict == Verdict.QUARANTINE


def test_clean_detonation_clears_the_hook_quarantine():
    verdict = _verdict(DetonationResult(sensor_alive=True), hooks=["postinstall: echo ok"])
    assert verdict.verdict == Verdict.ALLOW


def test_blind_sensor_is_unavailable_and_keeps_the_hook_quarantine():
    blind = DetonationResult(scan_failed=True, error_message="Falco did not see the sentinel")
    verdict = _verdict(blind, hooks=["postinstall: echo ok"])
    assert verdict.verdict == Verdict.QUARANTINE
    assert {s.name: s.status for s in verdict.stages}["detonation"] == StageStatus.UNAVAILABLE


def test_sink_proof_blocks_even_with_a_blind_sensor():
    blind = DetonationResult(scan_failed=True, error_message="blind", findings=[
        DetonationFinding("sink", "canary_exfiltrated", "Critical", "canary token sent over DNS"),
    ])
    assert _verdict(blind).verdict == Verdict.BLOCK


def test_clean_detonation_never_improves_a_static_quarantine():
    threat = type("F", (), {"rule_name": "threat-x"})()
    guarddog = type("G", (), {"threat_findings": [threat], "issue_count": 1,
                              "scan_failed": False, "error_message": None})()
    verdict = aggregate(package_name="p", version="1", ecosystem="npm", guarddog_result=guarddog,
                        detonation_result=DetonationResult(sensor_alive=True))
    assert verdict.verdict == Verdict.QUARANTINE


def test_detonation_priorities_are_configurable():
    result = DetonationResult(sensor_alive=True, findings=[
        DetonationFinding("falco", "airlock_outbound_connection", "Warning", "dest=10.0.0.1"),
    ])
    assert _verdict(result, policy=Policy(block_on_detonation_priority=("Warning",))).verdict == Verdict.BLOCK
