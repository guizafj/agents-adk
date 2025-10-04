FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema incluyendo herramientas de compilación
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar archivos de configuración
COPY . .

# Instalar uv y dependencias
RUN pip install --upgrade pip && pip install uv

RUN uv sync

cmd ["uv", "run", "adk", "web", "--host", "0.0.0.0"]