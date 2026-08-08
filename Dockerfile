# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Management Tool — Docker Image
# Base:     kalilinux/kali-rolling
# Scanners: nmap, nikto, wapiti (CLI), ZAP baseline tooling, nuclei v3.7.1 (pinned binary)
# Adapters: Python HTTP/2 bridge support
# Python:   app dependencies managed by uv (no wapiti3 package — wapiti runs as a subprocess)
# ─────────────────────────────────────────────────────────────────────────────

FROM kalilinux/kali-rolling

LABEL maintainer="vuln-manager" \
      description="Vulnerability Management Tool on Kali Linux"

# ── 1. System packages ────────────────────────────────────────────────────────
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        python3-dev \
        nmap \
        nikto \
        wapiti \
        zaproxy \
        curl \
        wget \
        unzip \
        jq \
        git \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Nuclei — pinned binary download (reproducible, no Go toolchain needed) ─
# Pin version explicitly: bump this line to upgrade.
ENV NUCLEI_VERSION=v3.7.1

RUN ARCH="$(uname -m)" && \
    case "$ARCH" in \
        x86_64)  GOARCH="amd64" ;; \
        aarch64) GOARCH="arm64" ;; \
        *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL \
        "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_${GOARCH}.zip" \
        -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    # Pre-fetch nuclei templates at build time so first scan is fast
    nuclei -update-templates -silent || true

# ── 3. Python virtual environment + uv dependencies ──────────────────────────
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV UV_PROJECT_ENVIRONMENT="$VIRTUAL_ENV" \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# ── 4. Application code ───────────────────────────────────────────────────────
WORKDIR /app
COPY pyproject.toml uv.lock README.md /app/
RUN uv sync --locked --no-dev --no-install-project
COPY . /app

# Ensure the output directory exists (volume mount point)
RUN mkdir -p /app/data

# ── 5. Runtime configuration ──────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Safe default: list scanners + their availability
CMD ["python3", "main.py", "--list-scanners"]
