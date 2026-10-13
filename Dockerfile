# ──────────────────────────────────────────────────────────────────
# ARES — Imagen Docker
#
# Contiene la API de ARES y todas las herramientas de seguridad:
#   Nmap, WhatWeb, Gobuster, Nuclei, wordlists para Gobuster
#
# Build:  docker-compose up --build
# ──────────────────────────────────────────────────────────────────

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# ── 1. Sistema base ──────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    ruby \
    ruby-dev \
    curl \
    unzip \
    wget \
    ca-certificates \
    # dirb incluye wordlists en /usr/share/dirb/wordlists/
    dirb \
    && rm -rf /var/lib/apt/lists/*

# ── 2. WhatWeb ───────────────────────────────────────────────────
RUN gem install whatweb --no-document 2>&1 | tail -3

# ── 3. Gobuster ──────────────────────────────────────────────────
RUN GOBUSTER_VERSION="3.6.0" && \
    curl -sSL \
    "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_x86_64.tar.gz" \
    -o /tmp/gobuster.tar.gz && \
    tar xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster && \
    chmod +x /usr/local/bin/gobuster && \
    rm -f /tmp/gobuster.tar.gz

# ── 4. Nuclei ────────────────────────────────────────────────────
RUN NUCLEI_VERSION="3.2.4" && \
    curl -sSL \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f /tmp/nuclei.zip

# Descargar templates de Nuclei (puede fallar sin internet, continúa igual)
RUN nuclei -update-templates -silent 2>/dev/null || true

# ── 5. Python ────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 6. Aplicación ────────────────────────────────────────────────
COPY api.py ares.py modelos.py correlacion.py orquestador.py vhosts.py ./
COPY parsers/ ./parsers/
COPY base_datos/ ./base_datos/
COPY reportes/ ./reportes/

RUN mkdir -p /app/data /app/evidencias /app/reportes/salida

# ── 7. Configuración ─────────────────────────────────────────────
ENV ARES_DATABASE_URL=sqlite:////app/data/ares.db
ENV PYTHONUNBUFFERED=1

# Symlink de wordlists para que el orquestador las encuentre
RUN mkdir -p /usr/share/wordlists/dirb && \
    ln -sf /usr/share/dirb/wordlists/common.txt \
           /usr/share/wordlists/dirb/common.txt

EXPOSE 8000
CMD ["python", "api.py"]
