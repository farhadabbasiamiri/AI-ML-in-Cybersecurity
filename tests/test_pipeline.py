"""Unit tests for the deterministic pipeline. Run with: pytest"""
import sys
sys.path.insert(0, ".")
from triage.parser import parse_alert, is_external_ip
from triage.scorer import score_alert
from triage.pipeline import triage_one


def test_parser_handles_missing_fields():
    parsed = parse_alert({"alert_id": "X1"})
    assert parsed["host"] == "unknown"
    assert parsed["src_ip"] is None
    assert parsed["alert_id"] == "X1"


def test_parser_reads_nested():
    a = {"alert_id": "X2", "host": {"name": "SRV-01"}, "source": {"ip": "10.0.0.5"}}
    parsed = parse_alert(a)
    assert parsed["host"] == "SRV-01"
    assert parsed["src_ip"] == "10.0.0.5"


def test_external_ip():
    assert is_external_ip("203.0.113.5") is True
    assert is_external_ip("10.0.0.5") is False
    assert is_external_ip(None) is False


def test_ransomware_scores_critical_or_high():
    a = {"alert_id": "R1", "rule_name": "Shadow copies deleted",
         "raw_log": "vssadmin delete shadows /all /quiet", "vendor_severity": "critical",
         "host": {"name": "SRV-FILE01"}, "user": {"name": "jsmith"}}
    out = triage_one(a)
    assert out["category_guess"] == "ransomware"
    assert out["priority"] in ("High", "Critical")


def test_benign_scores_low():
    a = {"alert_id": "B1", "rule_name": "Successful user login",
         "raw_log": "EventID=4624 LogonType=2 status=success", "vendor_severity": "low",
         "host": {"name": "WS-010"}, "user": {"name": "jsmith"},
         "source": {"ip": "10.0.1.5"}}
    out = triage_one(a)
    assert out["priority"] == "Low"


def test_every_alert_gets_a_priority():
    out = triage_one({"alert_id": "E1"})
    assert out["priority"] in ("Low", "Medium", "High", "Critical")
    assert out["ml_category"]
    assert 0.0 <= out["ml_confidence"] <= 1.0


def test_mitre_lookup_maps_known_techniques():
    from triage.mitre import mitre_lookup
    assert mitre_lookup("vssadmin delete shadows")["technique_id"] == "T1490"
    assert mitre_lookup("comsvcs minidump lsass")["technique_id"] == "T1003.001"
    assert mitre_lookup("totally normal login")["technique_id"] is None


def test_llm_fallback_never_crashes():
    # With no Ollama running, analyze_with_llm must return a usable result.
    from triage.llm import analyze_with_llm
    e = {"rule_name": "Shadow copies deleted", "host": "SRV-01", "user": "x",
         "src_ip": None, "log_source": "Security", "raw_log": "vssadmin delete shadows",
         "priority": "Critical", "score": 90, "category_guess": "ransomware",
         "reasons": ["matched ransomware signal (+55)"],
         "mitre_id": "T1490", "mitre_name": "Inhibit System Recovery", "mitre_tactic": "Impact"}
    out = analyze_with_llm(e)
    assert out["priority"] in ("Low", "Medium", "High", "Critical")
    assert isinstance(out["next_steps"], list) and len(out["next_steps"]) >= 1


def test_rag_retrieves_correct_technique():
    from triage.rag import retrieve
    hits = retrieve("vssadmin delete shadows /all /quiet", k=1)
    assert hits and "T1490" in hits[0]["source"]
    hits = retrieve("rundll32 comsvcs MiniDump lsass", k=1)
    assert hits and "T1003.001" in hits[0]["source"]


def test_rag_always_returns_a_source():
    from triage.rag import retrieve
    for q in ["schtasks create", "wmiprvse powershell", "mimikatz dcsync"]:
        hits = retrieve(q, k=2)
        assert all(h.get("source") for h in hits)


def test_llm_analysis_includes_citations():
    from triage.pipeline import triage_one
    from triage.llm import analyze_with_llm
    a = triage_one({"alert_id": "X", "rule_name": "Shadow copies deleted",
                    "raw_log": "vssadmin delete shadows /all /quiet",
                    "vendor_severity": "critical", "host": {"name": "SRV-1"},
                    "user": {"name": "a"}})
    out = analyze_with_llm(a)
    assert isinstance(out.get("citations"), list) and len(out["citations"]) >= 1
