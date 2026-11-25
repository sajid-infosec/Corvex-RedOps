# Corvex-RedOps API + console. The native scanning engine (crawler, OWASP checks,
# injection fuzzer, OAST) needs no external tools and is always available. The
# extras below make the orchestrated tools real in the container:
#   - nmap        : network/service discovery
#   - chromium    : headless SPA crawl (renders JavaScript single-page apps)
#   - nuclei      : templated vulnerability checks
# The template engine and the subdomain finder are pinned releases checked against
# SHA-256 (amd64 and arm64); a mismatch fails the build. Downloads stay best-effort so
# the image still builds on locked-down networks — the native engine covers the full
# OWASP surface without them. The console runs as an unprivileged user (uid 10001).
FROM python:3.11-slim

# Pinned third-party scanners (versions + SHA-256 of the linux zip, per architecture).
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG SUBFINDER_VERSION=2.17.0
ARG SUBFINDER_SHA256_AMD64=a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37
ARG SUBFINDER_SHA256_ARM64=24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190

WORKDIR /app
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1

# libatomic1: the headless browser's arm64 build links against it (without it the SPA
# crawl can't launch on arm64).
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap ca-certificates curl unzip libatomic1 \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
# The console runs as an unprivileged user, so the code must be readable whatever permissions
# the checkout had (a private copy, a restrictive umask). Only files that need it are touched,
# so the layer stays small.
RUN find /app \( ! -perm -0444 -o -type d ! -perm -0111 \) -exec chmod a+rX {} + \
    && pip install --no-cache-dir -e ".[api,reports,ai]"

# Headless browser for the SPA crawler (best-effort; native crawl still works).
RUN pip install --no-cache-dir playwright \
    && (playwright install --with-deps chromium || playwright install chromium || \
        echo "headless browser unavailable — SPA crawl will fall back to static") || true \
    && chmod -R a+rX /opt/pw-browsers 2>/dev/null || true

# pinned_zip NAME VERSION SHA_AMD64 SHA_ARM64 — install a ProjectDiscovery release binary
# into /usr/local/bin after checking its SHA-256. Mismatch = build failure.
RUN set -eu; \
    pinned_zip() { \
      name="$1"; ver="$2"; arch="$(dpkg --print-architecture)"; \
      case "$arch" in amd64) sha="$3";; arm64) sha="$4";; \
        *) echo "$name: no pinned build for $arch — skipped"; return 0;; esac; \
      url="https://github.com/projectdiscovery/$name/releases/download/v$ver/${name}_${ver}_linux_${arch}.zip"; \
      if ! curl -fsSL --retry 3 "$url" -o "/tmp/$name.zip"; then \
        echo "$name: download failed — skipped (the native engine covers this surface)"; return 0; fi; \
      echo "$sha  /tmp/$name.zip" | sha256sum -c - || { echo "$name: SHA-256 mismatch for $url"; exit 1; }; \
      unzip -o "/tmp/$name.zip" -d /usr/local/bin "$name"; chmod 755 "/usr/local/bin/$name"; rm -f "/tmp/$name.zip"; \
    }; \
    pinned_zip nuclei "$NUCLEI_VERSION" "$NUCLEI_SHA256_AMD64" "$NUCLEI_SHA256_ARM64"; \
    pinned_zip subfinder "$SUBFINDER_VERSION" "$SUBFINDER_SHA256_AMD64" "$SUBFINDER_SHA256_ARM64"

# WPScan (best-effort) for WordPress CVE data. The native WordPress checks work
# without it; WPScan layers on core/plugin/theme CVEs when a WPSCAN_API_TOKEN is
# configured. Kept optional so a failure never breaks the build.
RUN ( apt-get update \
      && apt-get install -y --no-install-recommends ruby ruby-dev build-essential libcurl4-openssl-dev libz-dev \
      && gem install wpscan --no-document \
      && rm -rf /var/lib/apt/lists/* ) \
    || echo "wpscan unavailable — native WordPress checks cover this surface"

# Unprivileged runtime user. /app stays root-owned (read-only for the app); only the data
# volume is writable. Templates for the template engine land in the user's home.
RUN useradd --system --uid 10001 --user-group --home-dir /home/corvex --create-home --shell /usr/sbin/nologin corvex \
    && mkdir -p /app/data && chown -R corvex:corvex /app/data
USER corvex
RUN (command -v nuclei >/dev/null && nuclei -update-templates -silent) \
    || echo "template set not downloaded — run 'nuclei -update-templates' in the container later"

EXPOSE 8080
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4).status == 200 else 1)"
CMD ["corvex", "serve", "--host", "0.0.0.0", "--port", "8080"]
