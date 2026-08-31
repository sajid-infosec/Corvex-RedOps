from pentestiq.engine import parse_scope_entry, load_scope
from pentestiq.models import AssetType


def test_explicit_type_prefix():
    assert parse_scope_entry("wordpress=http://blog") == (AssetType.WORDPRESS, "http://blog")
    assert parse_scope_entry("api=https://api/openapi.json") == (AssetType.API, "https://api/openapi.json")


def test_inferred_when_no_prefix():
    t, tgt = parse_scope_entry("http://site")
    assert t == AssetType.WEB and tgt == "http://site"


def test_load_scope_strips_type_prefix(tmp_path):
    f = tmp_path / "s.yaml"
    f.write_text("engagement:\n  name: T\nscope:\n  in_scope:\n"
                 "    - wordpress=http://blog\n    - http://site\n")
    scope, assets = load_scope(f)
    # scope.in_scope must hold clean targets (so matching works)
    assert "http://blog" in scope.in_scope and "wordpress=http://blog" not in scope.in_scope
    assert scope.is_in_scope("http://blog/wp-login.php") is True
    types = {a.type for a in assets}
    assert AssetType.WORDPRESS in types and AssetType.WEB in types
