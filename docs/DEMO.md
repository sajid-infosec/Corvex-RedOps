# Corvex-RedOps — Demo

A walk-through of what Corvex-RedOps produces. (Output below is from the bundled test
fixtures — port & service discovery, DAST web-scan, and template-based scan results
for one host — so you can see the pipeline without a live target. On Kali with real
tools, the same flow runs live.)

## 1. Cross-tool, scored, correlated findings

Three tools feed one normalized model. Findings are deduplicated, risk-scored
(0–100), and correlated into attack chains by host:port:

```
RISK  SEV       CHAIN         ENGINE      TITLE
  90  critical  10.0.0.5:80   tmpl-scan   Example RCE
  82  high      10.0.0.5:80   dast        SQL Injection
  50  medium    10.0.0.5:443  tmpl-scan   Weak TLS
  28  low       10.0.0.5:23   port-scan   Open port 23/tcp — telnet
  25  low       10.0.0.5:80   dast        X-Content-Type-Options Header Missing
   6  info      10.0.0.5:80   port-scan   Open port 80/tcp — http (nginx 1.18.0)
   6  info      10.0.0.5:22   port-scan   Open port 22/tcp — ssh (OpenSSH 8.2p1)
   5  info      10.0.0.5:80   tmpl-scan   nginx detected
```

The `10.0.0.5:80` chain links the open HTTP service, the RCE, the SQLi, and the
missing header into one story.

## 2. Safe exploit validation

Corvex-RedOps doesn't just report — it **confirms**. Non-destructive validators turn
`detected` into `validated` (with evidence) or dismiss false positives:

```
BEFORE:  detected  medium  Reflected XSS @ /search
         detected  medium  Reflected XSS @ /safe
         detected  high    SQL Injection @ /item

AFTER:   risk 95  validated       SQL Injection   ← boolean-inference evidence
         risk 63  validated       Reflected XSS   ← reflected-marker evidence
         risk  0  false_positive  Reflected XSS   ← dismissed
```

## 3. Client-ready report

```bash
pentestiq run -s myscope.yaml -o out/
```

Produces `out/report.html` (self-contained, styled), `out/report.md`, and
`out/engagement.json`. A rendered example lives in
[`../examples/sample-report/`](../examples/sample-report/).

The executive summary is generated from the findings data (no API key needed);
wire up an LLM provider to enrich it.
