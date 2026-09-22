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


def _light_block(html: str) -> str:
    start = html.index(':root[data-theme="light"]{')
    return html[start:html.index("}", start)]


def test_light_theme_uses_the_brand_blue_not_the_retired_purple():
    light = _light_block(CONSOLE.read_text(encoding="utf-8")).lower()
    for retired in ("#9333ea", "#5457e6", "#4f46e5"):
        assert retired not in light, f"light theme still uses retired accent {retired}"


def test_light_theme_active_nav_is_readable():
    html = CONSOLE.read_text(encoding="utf-8")
    rule = next(l for l in html.splitlines() if ':root[data-theme="light"] .nav a.active{' in l)
    assert "color:" in rule, "light active nav inherits white text from the dark rule"


def test_severity_donut_text_follows_the_theme():
    html = CONSOLE.read_text(encoding="utf-8")
    assert 'fill="#eaf1fb"' not in html and 'stroke="#1e2c49"' not in html
    assert "fill:var(--txt)" in html
