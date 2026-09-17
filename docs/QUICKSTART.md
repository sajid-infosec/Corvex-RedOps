# Corvex-RedOps — Quickstart (first 15 minutes)

> ⚠️ **Authorized use only.** Run Corvex-RedOps only against systems you own or are
> explicitly authorized to test. See [LEGAL_AND_ETHICS.md](LEGAL_AND_ETHICS.md).

## 1. Install (Python 3.10+)

```bash
git clone https://github.com/sajid-infosec/PentestIQ.git
cd Corvex-RedOps
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## 2. Run the tests

```bash
pytest -q          # 66 tests should pass
```

## 3. Meet the CLI

```bash
pentestiq version
pentestiq modules   # infra, web, wordpress, api
```

## 4. Stand up the lab (needs Docker)

```bash
cd lab && docker compose up -d && cd ..
#  Juice Shop -> http://localhost:3000
#  DVWA       -> http://localhost:8080
```

## 5. Write a scope file

`myscope.yaml`:

```yaml
engagement:
  name: "Local Lab Engagement"
  authorized_by: "self (isolated lab)"
scope:
  in_scope:
    - web=http://localhost:3000        # Juice Shop
    - infra=127.0.0.1                  # local host
  allowed_actions: [discover, assess, validate_safe]
safe_mode: true
enforcement: warn                       # 'block' to hard-enforce scope
```

## 6. Run an engagement + generate a report

```bash
pentestiq run -s myscope.yaml -o out/
#  -> out/report.html   (open in a browser)
#  -> out/report.md
#  -> out/engagement.json
```

## Real scanning (on Kali / Parrot)

Corvex-RedOps orchestrates these tools — install the ones you need and Corvex-RedOps
picks them up automatically (missing tools are skipped, never fatal):

| Module | Engines |
|---|---|
| infra | port & service discovery, template-based scanning |
| web | DAST baseline scan, template-based scanning |
| wordpress | WordPress scanning, template-based scanning |
| api | OpenAPI (built-in), template-based scanning |

```bash
# Kali examples — install the engines your modules need
sudo apt install -y nmap wpscan
# other engines (template-based scanner, DAST web scanner) install per their upstream docs
```

## What you get

- One **normalized findings model** across every tool (deduplicated, provenance-tracked).
- **Safe validation** that confirms real issues and dismisses false positives.
- **Risk scoring** (0–100) and **attack-chain correlation**.
- A **client-ready report** (HTML + Markdown) in one command.

Next: read [ARCHITECTURE.md](ARCHITECTURE.md) to write your own module or tool integration.
