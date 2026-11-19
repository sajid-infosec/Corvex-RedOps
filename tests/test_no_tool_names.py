"""User-facing text names no bundled third-party tools, competitors or practice apps.

Scans the prose of the docs and the visible text of the web console. Functional identifiers
are left alone: fenced code blocks, inline code spans and the dependency-extras table in the
docs, and <script>, <style>, attributes, comments and <code>/<pre> in the console. Names are
matched case-sensitively as whole words, so identifiers such as NucleiTemplateManager or
/tools/nuclei/update pass. Slack, Jira and ServiceNow are integrations, not bundled tools, and
are not listed.
"""
import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NAMES = ["Typer", "Juice Shop", "DVWA", "apktool", "jadx", "subfinder", "httpx", "Gitleaks",
         "trufflehog", "Nuclei", "Nmap", "OWASP ZAP", "Burp", "Frida", "scikit-learn", "Acunetix",
         "Tenable", "Intruder"]
PATTERN = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(n) for n in NAMES) + r")(?!\w)")

CONSOLE = ROOT / "pentestiq/api/static/index.html"


def _markdown_files():
    files = [ROOT / p for p in ("README.md", "INSTALL.md", "CHANGELOG.md", "lab/README.md",
                                "bench/README.md")]
    files += sorted((ROOT / "docs").glob("*.md"))
    files += sorted((ROOT / "examples").rglob("*.md"))
    files += sorted((ROOT / "pentestiq/kit").rglob("README.md"))
    return [f for f in files if f.is_file()]


def _blank(match):
    """Replace a stripped span with its newlines only, so line numbers stay true."""
    return "\n" * match.group(0).count("\n")


def markdown_prose(text):
    """The text with fenced code blocks, the extras table and inline code spans removed."""
    out, fence, in_extras = [], None, False
    for line in text.split("\n"):
        stripped = line.lstrip()
        if fence:
            if stripped.startswith(fence):
                fence = None
            out.append("")
            continue
        m = re.match(r"(`{3,}|~{3,})", stripped)
        if m:
            fence = m.group(1)
            out.append("")
            continue
        if re.match(r"\|\s*Extra\s*\|", stripped):
            in_extras = True
        elif in_extras and not stripped.startswith("|"):
            in_extras = False
        out.append("" if in_extras else line)
    return re.sub(r"(`+)(?!`).+?(?<!`)\1(?!`)", _blank, "\n".join(out), flags=re.S)


class _VisibleText(HTMLParser):
    SKIP = {"script", "style", "code", "pre"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth, self.chunks = 0, []

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.depth += 1

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.depth:
            self.depth -= 1

    def handle_data(self, data):
        if not self.depth:
            self.chunks.append((self.getpos()[0], data))


def console_text(html):
    """(line, text) for every run of text the console shows outside scripts and code."""
    parser = _VisibleText()
    parser.feed(html)
    parser.close()
    return parser.chunks


def _hits_in_markdown(path):
    prose = markdown_prose(path.read_text(encoding="utf-8"))
    rel = path.relative_to(ROOT)
    return [f"{rel}:{n}: {m.group(0)}" for n, line in enumerate(prose.split("\n"), 1)
            for m in PATTERN.finditer(line)]


def _hits_in_console():
    hits = []
    for start, data in console_text(CONSOLE.read_text(encoding="utf-8")):
        for m in PATTERN.finditer(data):
            line = start + data[:m.start()].count("\n")
            hits.append(f"{CONSOLE.relative_to(ROOT)}:{line}: {m.group(0)}")
    return hits


def test_docs_name_no_third_party_tools():
    hits = [h for f in _markdown_files() for h in _hits_in_markdown(f)]
    assert hits == []


def test_console_names_no_third_party_tools():
    assert _hits_in_console() == []


# ---- the scanner itself -----------------------------------------------------------------
def test_scanner_skips_code_and_the_extras_table_but_not_prose():
    text = ("Uses Nmap here.\n"
            "```bash\nnmap -sV  # Nmap\n```\n"
            "Run `Typer --help` or ``Burp`` first.\n"
            "| Extra | Adds |\n|---|---|\n| `dev` | pytest, httpx |\n\n"
            "NucleiTemplateManager and /tools/nuclei/update are fine; so is Slack.\n"
            "An Intruder tab.\n")
    lines = markdown_prose(text).split("\n")
    found = [(n, m.group(0)) for n, line in enumerate(lines, 1) for m in PATTERN.finditer(line)]
    assert found == [(1, "Nmap"), (11, "Intruder")]


def test_console_scan_skips_scripts_attributes_and_code():
    html = ('<div title="Burp">Intruder</div>\n<script>toast("Nmap")</script>\n'
            '<code>Typer</code><button data-tab="intruder">Fuzzer</button><!-- Frida -->')
    text = " ".join(d for _, d in console_text(html))
    assert PATTERN.findall(text) == ["Intruder"]
