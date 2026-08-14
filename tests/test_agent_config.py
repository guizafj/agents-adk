"""Tests de configuración de Cybersegurity_tutor/agent.py.

Verifican los defaults de entorno (modelo, num_ctx, persistencia), el cálculo
del umbral de compactación y — clave para la depuración — la coherencia entre
el nombre del agente, el del App y el del directorio del paquete.
"""

import importlib
import pathlib


from Cybersegurity_tutor import agent

PACKAGE_DIR = pathlib.Path(agent.__file__).parent

# Variables de entorno que agent.py lee (además de las del .env)
ENV_VARS = (
    "OLLAMA_API_BASE",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "PERSISTENCE_DB_PATH",
    "OLLAMA_NUM_CTX",
    "LITELLM_REQUEST_TIMEOUT",
    "LITELLM_CONNECT_TIMEOUT",
    "COMPACTION_TOKEN_THRESHOLD",
    "COMPACTION_THRESHOLD_RATIO",
    "COMPACTION_RETENTION_SIZE",
)


def _reload_agent_clean(monkeypatch, **env) -> None:
    """Recarga agent.py con un entorno controlado y sin .env.

    Parchea load_dotenv para que no inyecte el .env real del paquete y
    fija (o limpia) las variables de entorno según lo pedido.
    """
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    importlib.reload(agent)


# ---------------------------------------------------------------------------
# Defaults de entorno
# ---------------------------------------------------------------------------


def test_default_model_is_gemma4_12b(monkeypatch) -> None:
    _reload_agent_clean(monkeypatch)
    assert agent.OLLAMA_MODEL == "ollama_chat/gemma4:12b"


def test_default_num_ctx_8192(monkeypatch) -> None:
    _reload_agent_clean(monkeypatch)
    assert agent.NUM_CTX == 8192


def test_default_persistence_db(monkeypatch) -> None:
    _reload_agent_clean(monkeypatch)
    assert agent.PERSISTENCE_DB == "/app/data/persistence/sessions.db"


def test_env_overrides_model(monkeypatch) -> None:
    _reload_agent_clean(monkeypatch, OLLAMA_MODEL="ollama_chat/otro:9b")
    assert agent.OLLAMA_MODEL == "ollama_chat/otro:9b"


def test_env_overrides_num_ctx(monkeypatch) -> None:
    _reload_agent_clean(monkeypatch, OLLAMA_NUM_CTX="4096")
    assert agent.NUM_CTX == 4096


# ---------------------------------------------------------------------------
# Compactación (Fase 3-5)
# ---------------------------------------------------------------------------


def test_compaction_threshold_derived_from_ratio(monkeypatch) -> None:
    _reload_agent_clean(
        monkeypatch, OLLAMA_NUM_CTX="8192", COMPACTION_THRESHOLD_RATIO="0.5"
    )
    assert agent.COMPACTION_TOKEN_THRESHOLD == 4096


def test_compaction_threshold_absolute_override(monkeypatch) -> None:
    _reload_agent_clean(
        monkeypatch,
        COMPACTION_TOKEN_THRESHOLD="5000",
        COMPACTION_THRESHOLD_RATIO="0.5",
    )
    assert agent.COMPACTION_TOKEN_THRESHOLD == 5000


def test_compaction_retention_default(monkeypatch) -> None:
    _reload_agent_clean(monkeypatch)
    assert agent.COMPACTION_RETENTION_SIZE == 4


# ---------------------------------------------------------------------------
# Nombres (clave para el bug de sesión no generada)
# ---------------------------------------------------------------------------


def test_root_agent_name_matches_package_directory() -> None:
    """El nombre del agente debe coincidir con el directorio del paquete.

    ADK usa el nombre del directorio como app_name implícito cuando carga el
    agente; si root_agent.name difiere, las sesiones se guardan bajo un
    app_name distinto al que la web/CLI buscan.
    """
    assert agent.root_agent.name == PACKAGE_DIR.name


def test_app_name_matches_root_agent() -> None:
    assert agent.app.name == agent.root_agent.name


def test_root_agent_has_lab_tools() -> None:
    tool_names = {
        getattr(t, "__name__", None) or getattr(t, "name", None)
        for t in agent.root_agent.tools
    }
    assert "record_phase" in tool_names
    assert "record_port" in tool_names
    assert "search_lab_memory" in tool_names
