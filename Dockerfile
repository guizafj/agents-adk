# ============================================================================
# Cybersecurity Tutor — Dockerfile
#
# Build en dos etapas:
#   1. builder: instala uv y resuelve dependencias
#   2. runtime: imagen final limpia sin herramientas de build
#
# El .venv queda dentro de la imagen — no se tapa con volúmenes externos.
# La BD SQLite se monta como volumen nombrado en /app/data/persistence/.
# ============================================================================

# ── ETAPA 1: builder ────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Instalar uv con el installer oficial de Astral (fija versión, más seguro)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Copiar solo los archivos de dependencias primero
# (aprovecha el caché de Docker: si no cambian, no reinstala nada)
COPY pyproject.toml uv.lock ./

# Instalar dependencias en /app/.venv
# --frozen: usar exactamente lo que dice uv.lock, sin resolver de nuevo
# --no-dev: excluir dependencias de desarrollo
# --no-install-project: solo dependencias, el código del proyecto lo copiamos después
RUN uv sync --frozen --no-dev --no-install-project

# Copiar el código del proyecto e instalar el proyecto en el .venv
COPY . .
RUN uv sync --frozen --no-dev

# ── ETAPA 2: runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Solo lo estrictamente necesario en runtime:
# curl para el healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar uv (necesario para 'uv run')
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Copiar el proyecto completo (código + .venv ya construido)
COPY --from=builder /app /app

# Directorio de persistencia — el volumen se monta aquí
RUN mkdir -p /app/data/persistence && chmod 755 /app/data/persistence

# Variables de entorno por defecto
# Sobreescribibles desde docker-compose.yml o docker run -e
ENV OLLAMA_API_BASE="http://localhost:11434" \
    OLLAMA_MODEL="ollama_chat/gemma4:12b" \
    PERSISTENCE_DB_PATH="/app/data/persistence/sessions.db" \
    ADK_LOG_LEVEL="DEBUG" \
    # uv: usar el .venv del proyecto, no crear uno nuevo
    UV_PROJECT_ENVIRONMENT="/app/.venv"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Sin '/' al final — es un argumento inválido para adk web
# --session_service_uri: usa la BD SQLite del volumen nombrado (no .adk/ local)
#   así las sesiones sobreviven a reinicios y rebuilds del contenedor.
# IMPORTANTE: sqlite://// (4 slashes) = ruta ABSOLUTA. Con 3 slashes la ruta
#   es relativa al CWD (/app) → busca /app/app/data/... y falla con
#   "unable to open database file" al crear la sesión.
CMD ["uv", "run", "adk", "web", "--session_service_uri=sqlite:////app/data/persistence/sessions.db", "--host", "0.0.0.0", "--port", "8000"]
