"""The console must not reference CSS custom properties it never defines.

An undefined `var(--x)` fails silently: the declaration is dropped, so a stroke,
fill or colour simply disappears. That is how the posture-trend line, its legend
swatch and the "Open now" figure vanished (they used --accent; the theme
defines --acc).
"""
import re
from pathlib import Path

CONSOLE = Path(__file__).resolve().parents[1] / "pentestiq" / "api" / "static" / "index.html"


def test_every_css_var_used_is_defined():
    html = CONSOLE.read_text(encoding="utf-8")
    defined = set(re.findall(r"(--[A-Za-z0-9_-]+)\s*:", html))
    # var(--x) with no fallback; var(--x, fallback) is allowed to be undefined
    used = set(re.findall(r"var\(\s*(--[A-Za-z0-9_-]+)\s*\)", html))
    missing = sorted(used - defined)
    assert not missing, f"undefined CSS custom properties used in the console: {missing}"

