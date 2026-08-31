from pathlib import Path
from pentestiq.integrations.openapi_tool import OpenApiIntegration
from pentestiq.models import Asset, AssetType, Severity

FIX = Path(__file__).parent / "fixtures"


def _api():
    return Asset(type=AssetType.API, identifier="http://api.example.com/openapi.json")


def test_openapi_enumerates_and_flags_auth():
    raw = (FIX / "openapi_sample.json").read_text()
    findings = OpenApiIntegration().parse(raw, _api())
    endpoints = [f for f in findings if f.category == "api-endpoint"]
    assert len(endpoints) == 2                      # /users and /health
    unauth = [f for f in findings if f.category == "api-auth"]
    # POST /users (no security) and GET /health (no security) are unauthenticated;
    # GET /users has bearer security so it is NOT flagged
    titles = " ".join(f.title for f in unauth)
    assert "POST /users" in titles
    assert "GET /health" in titles
    assert "GET /users" not in titles
    assert all(f.severity == Severity.LOW for f in unauth)


def test_openapi_flags_missing_scheme():
    # a spec with no securitySchemes -> MEDIUM finding
    raw = '{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}'
    findings = OpenApiIntegration().parse(raw, _api())
    assert any(f.category == "api-auth" and f.severity == Severity.MEDIUM
               and "no authentication scheme" in f.title for f in findings)


def test_openapi_is_available():
    assert OpenApiIntegration().is_available() is True
