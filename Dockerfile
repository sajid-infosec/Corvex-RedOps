# PentestIQ API + console. The native scanning engine (crawler, OWASP checks,
# injection fuzzer, OAST) needs no external tools and is always available. The
# extras below make the orchestrated tools real in the container:
#   - nmap        : network/service discovery
#   - chromium    : headless SPA crawl (renders JS apps like crAPI/Convay)
#   - nuclei      : templated vulnerability checks
# nuclei + the browser download over the network at build time; both are
# best-effort so the image still builds on locked-down networks — the native
# engine covers the full OWASP surface without them.
FROM python:3.11-slim

WORKDIR /app
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers \
    PIP_ROOT_USER_ACTION=ignore

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
RUN pip install --no-cache-dir -e ".[api,reports,ai]"

# Headless browser for the SPA crawler (best-effort; native crawl still works).
RUN pip install --no-cache-dir playwright \
    && (playwright install --with-deps chromium || playwright install chromium || \
        echo "playwright chromium unavailable — SPA crawl will fall back to static") || true

# Nuclei templated scanner (best-effort static binary install).
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) NA=amd64;; arm64) NA=arm64;; *) NA=amd64;; esac; \
    ( curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -oE '\"tag_name\": \"v[0-9.]+\"' | grep -oE '[0-9.]+')_linux_${NA}.zip" -o /tmp/nuclei.zip \
      && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
      && chmod +x /usr/local/bin/nuclei \
      && rm -f /tmp/nuclei.zip \
      && (nuclei -update-templates || true) ) \
    || echo "nuclei unavailable — native check engine covers this surface"

# subfinder (best-effort) for richer external subdomain discovery (EASM). The
# discovery module works without it via crt.sh + native DNS/HTTP probing;
# subfinder just adds many more passive sources.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) NA=amd64;; arm64) NA=arm64;; *) NA=amd64;; esac; \
    ( curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(curl -fsSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep -oE '\"tag_name\": \"v[0-9.]+\"' | grep -oE '[0-9.]+')_linux_${NA}.zip" -o /tmp/subfinder.zip \
      && unzip -o /tmp/subfinder.zip -d /usr/local/bin subfinder \
      && chmod +x /usr/local/bin/subfinder \
      && rm -f /tmp/subfinder.zip ) \
    || echo "subfinder unavailable - crt.sh + native probing cover discovery"

# WPScan (best-effort) for WordPress CVE data. The native WordPress checks work
# without it; WPScan layers on core/plugin/theme CVEs when a WPSCAN_API_TOKEN is
# configured. Kept optional so a failure never breaks the build.
RUN ( apt-get update \
      && apt-get install -y --no-install-recommends ruby ruby-dev build-essential libcurl4-openssl-dev libz-dev \
      && gem install wpscan --no-document \
      && rm -rf /var/lib/apt/lists/* ) \
    || echo "wpscan unavailable — native WordPress checks cover this surface"

EXPOSE 8080
VOLUME ["/app/data"]
CMD ["pentestiq", "serve", "--host", "0.0.0.0", "--port", "8080"]
