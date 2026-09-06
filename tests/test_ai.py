"""Optional AI layer — provider fail-safe, analyst fallback + mock-model paths,
self-learning feedback + confidence model, and endpoints."""
import json, tempfile
import pytest
from pentestiq.models import Engagement, Scope, Asset, AssetType, Finding, Severity, Confidence, Evidence, Enforcement
from pentestiq.core.analysis import analyze
from pentestiq.ai import provider as PV
from pentestiq.ai import analyst as AN
from pentestiq.ai.feedback import FeedbackStore, ConfidenceModel, featurize


def _finding(title="SQL injection (error-based) in 'id'", sev=Severity.CRITICAL, **kw):
    a = Asset(type=AssetType.WEB, identifier="https://app.example.com")
    return Finding(asset=a, title=title, category=kw.get("category", "A03:2021"), severity=sev,
                   confidence=kw.get("confidence", Confidence.HIGH), location="GET /x?id",
                   source_tools=["pentestiq-fuzz"], status=kw.get("status", "detected"),
                   evidence=[Evidence(type="injection", ref="GET /x?id=1'", description="db error")])


class FakeProvider(PV.AIProvider):
    name = "fake"
    def __init__(self, payload): self.payload = payload
    def available(self): return True
    def chat(self, system, prompt, **kw): return self.payload


# ---- provider ----
def test_null_provider_unavailable():
    assert PV.NullProvider().available() is False
    assert PV.NullProvider().chat("s", "p") is None


def test_parse_json_extracts_object():
    assert PV.parse_json('noise {"a":1} tail') == {"a": 1}
    assert PV.parse_json("[1,2,3]") == [1, 2, 3]
    assert PV.parse_json("not json") is None


# ---- analyst fallbacks (no model) ----
def test_enrich_falls_back_without_model():
    out = AN.enrich_finding(_finding(), PV.NullProvider())
    assert out["ai"] is False and out["description"] and out["remediation"]


def test_enrich_uses_model_json():
    p = FakeProvider(json.dumps({"description": "AI desc", "impact": "AI impact",
                                 "remediation": [{"label": "Immediate", "text": "fix it"}]}))
    out = AN.enrich_finding(_finding(), p)
    assert out["ai"] is True and out["description"] == "AI desc"
    assert out["remediation"][0] == ("Immediate", "fix it")


def test_verify_heuristic_and_model():
    v = AN.verify_finding(_finding(status="validated"), PV.NullProvider())
    assert v["ai"] is False and v["confidence"] >= 0.9
    p = FakeProvider(json.dumps({"is_false_positive": True, "confidence": 0.2, "rationale": "no proof"}))
    v2 = AN.verify_finding(_finding(), p)
    assert v2["ai"] is True and v2["is_false_positive"] is True


def test_correlate_chains_model():
    f1 = _finding("SSRF to internal service", Severity.HIGH); f1.correlation_id = None
    f2 = _finding("Eureka service registry exposed", Severity.HIGH)
    payload = json.dumps([{"name": "Infra compromise", "severity": "critical",
                           "refs": ["F1", "F2"], "narrative": "SSRF then Eureka."}])
    chains = AN.correlate_chains([f1, f2], FakeProvider(payload))
    assert chains and chains[0]["ai"] is True and len(chains[0]["refs"]) == 2


# ---- self-learning ----
def test_feedback_and_confidence_model():
    d = tempfile.mkdtemp()
    fb = FeedbackStore(d + "/fb.db")
    # 8 confirmed criticals-with-evidence, 8 dismissed info-no-evidence
    for _ in range(8):
        fb.record("t", "e", _finding(sev=Severity.CRITICAL, status="validated"), "confirmed")
    for _ in range(8):
        f = Finding(asset=Asset(type=AssetType.WEB, identifier="x"), title="Banner",
                    category="A05:2021", severity=Severity.INFO, confidence=Confidence.LOW)
        fb.record("t", "e", f, "false_positive")
    counts = fb.counts("t")
    assert counts == {"total": 16, "confirmed": 8, "false_positive": 8}
    cm = ConfidenceModel(d + "/m.pkl")
    res = cm.train(fb, "t")
    assert res["trained"] is True
    hi = cm.predict_real(_finding(sev=Severity.CRITICAL, status="validated"))
    lo = cm.predict_real(Finding(asset=Asset(type=AssetType.WEB, identifier="x"),
                                 title="Banner", category="A05:2021", severity=Severity.INFO,
                                 confidence=Confidence.LOW))
    assert 0 <= lo <= 1 and 0 <= hi <= 1 and hi > lo


def test_confidence_heuristic_without_training():
    d = tempfile.mkdtemp()
    cm = ConfidenceModel(d + "/none.pkl")
    assert cm.is_trained is False
    assert 0.0 < cm.predict_real(_finding()) <= 1.0
