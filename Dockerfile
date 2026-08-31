# PentestIQ API + console. MobSF runs as a separate co-located service (see
# deploy/docker-compose.yml) and is reached over HTTP via MOBSF_URL.
FROM python:3.11-slim

WORKDIR /app
# nmap is the one scanner small enough to bundle; nuclei/zap/wpscan can be added
# to this image or run on a dedicated scanning host as your deployment grows.
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
RUN pip install --no-cache-dir -e ".[api,reports]"

EXPOSE 8080
VOLUME ["/app/data"]
CMD ["pentestiq", "serve", "--host", "0.0.0.0", "--port", "8080"]
