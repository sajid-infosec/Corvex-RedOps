# PentestIQ benchmark

A reproducible, fully-local benchmark that scores PentestIQ's native check engine
against a deliberately-vulnerable target with **known planted vulnerabilities** —
the same way you'd validate Acunetix / Tenable WAS / Burp Suite Enterprise against
a test app (their public equivalents are `testphp.vulnweb.com`, `demo.testfire.net`).

Everything runs on `127.0.0.1` — no external target, no authorization needed.

```bash
python bench/run_benchmark.py
```

`vuln_target.py` serves an intentionally-vulnerable API (missing headers, CORS
credential reflection, weak-secret JWT with an embedded token, BOLA, password-hash
in response, account enumeration, stack-trace leakage, dangerous methods).
`run_benchmark.py` points the engine at it and prints a detected-vs-planted
scorecard plus the OWASP coverage.

**Result:** 13/13 planted vulnerabilities detected (100%).
