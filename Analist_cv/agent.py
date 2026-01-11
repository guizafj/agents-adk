from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
import os
from typing import Optional
from dotenv import load_dotenv

from .prompt import get_prompt

from Cybersegurity_tutor.database import AgentPersistence

# Cargar variables del archivo .env
load_dotenv()

# Configurar URL de Ollama (priorizar OLLAMA_API_BASE del .env)
ollama_url = os.getenv("OLLAMA_API_BASE") or os.getenv(
    "OLLAMA_BASE_URL", "http://localhost:11434"
)


# ============================================================================
# PERSISTENCIA - Inicialización Global
# ============================================================================

# Usar ruta persistente que sobrevive reconstrucciones del contenedor
DB_PATH = os.getenv("PERSISTENCE_DB_PATH", "/app/data/persistence/sessions.db")

# Crear directorio si no existe
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

persistence = AgentPersistence(DB_PATH)
current_session_id: Optional[str] = None


# ============================================================================
# FUNCIONES DE GESTIÓN DE SESIONES
# ============================================================================


def create_agent_with_persistence(
    session_id: Optional[str] = None,
) -> tuple[Agent, str]:
    """Crea un agente con persistencia habilitada.

    Si se proporciona session_id, reanuda esa sesión.
    Si no, crea una nueva sesión.

    Args:
        session_id: ID de sesión existente o None para nueva sesión

    Returns:
        Tupla (agent, session_id)
    """
    global current_session_id

    # Reanudar o crear sesión
    if session_id:
        try:
            persistence.resume_session(session_id)
            current_session_id = session_id
        except ValueError:
            # Si la sesión no existe, crear una nueva
            current_session_id = persistence.start_session(
                session_name="Nueva sesión de chat"
            )
    else:
        current_session_id = persistence.start_session(
            session_name="Nueva sesión de chat"
        )

    # Obtener contexto persistente para incluir en el prompt
    context = persistence.get_context_summary()

    # Crear prompt mejorado con contexto
    base_prompt = get_prompt(option="version_1")
    enhanced_prompt = f"""{base_prompt}

--- CONTEXTO DE SESIÓN ---
{context}

IMPORTANTE: Usa este contexto para mantener continuidad en la conversación.
Si hay información de sesiones anteriores (puertos, servicios, vulnerabilidades),
refiérete a ella y construye sobre ese conocimiento.
"""

    # Crear agente con contexto persistente
    agent = Agent(
        name="Analist_CV",
        description="Expert in human resources, recruitment, and professional resume writing",
        model=LiteLlm(
            model="ollama_chat/qwen3:8b",
            instruction=enhanced_prompt,
            api_base=ollama_url,
        ),
    )

    return agent, current_session_id


def get_session_history(max_messages: int = 20):
    """Obtiene el historial de la sesión actual.

    Args:
        max_messages: Número máximo de mensajes a recuperar

    Returns:
        Lista de mensajes
    """
    return persistence.get_history(max_messages=max_messages)


def end_current_session(completed: bool = False):
    """Finaliza la sesión actual.

    Args:
        completed: Si True, marca como completada; si False, como pausada
    """
    global current_session_id
    persistence.end_session(mark_as_completed=completed)
    current_session_id = None


# ============================================================================
# HOOKS PARA GUARDAR MENSAJES
# ============================================================================


def save_user_message(message: str):
    """Guarda un mensaje del usuario en la base de datos.

    Args:
        message: Contenido del mensaje
    """
    if current_session_id:
        persistence.add_user_message(message)


def save_assistant_message(
    response: str,
    tool_calls: Optional[list] = None,
    tool_results: Optional[list] = None,
):
    """Guarda un mensaje del asistente en la base de datos.

    Args:
        response: Contenido de la respuesta
        tool_calls: Lista de herramientas llamadas
        tool_results: Resultados de las herramientas
    """
    if current_session_id:
        persistence.add_assistant_message(
            content=response, tool_calls=tool_calls, tool_results=tool_results
        )


# ============================================================================
# UTILIDADES DE CONSULTA
# ============================================================================


def search_history(search_term: str, limit: int = 10):
    """Busca en el historial de todas las conversaciones.

    Args:
        search_term: Término a buscar
        limit: Número máximo de resultados

    Returns:
        Lista de mensajes que coinciden con la búsqueda
    """
    return persistence.search(search_term, limit=limit)


def get_current_context():
    """Obtiene el contexto completo de la sesión actual.

    Returns:
        Diccionario con sesión y contexto del lab
    """
    return persistence.get_full_context()


def export_session_report():
    """Exporta un reporte completo de la sesión actual.

    Returns:
        Diccionario con toda la información de la sesión
    """
    return persistence.export_report()


def get_session_stats():
    """Obtiene estadísticas de la sesión actual.

    Returns:
        Diccionario con estadísticas
    """
    return persistence.get_statistics()


# ============================================================================
# AGENTE POR DEFECTO (Sin persistencia para compatibilidad)
# ============================================================================

root_agent = Agent(
    name="Analist_CV",
    description="Expert in human resources, recruitment, and professional resume writing",
    model=LiteLlm(
        model="ollama_chat/qwen3:8b",
        instruction=get_prompt(option="version_4"),
        api_base=ollama_url,
    ),
)


# ============================================================================
# EXPORTACIONES
# ============================================================================


__all__ = [
    # Agente
    "root_agent",
    # Gestión de sesiones
    "create_agent_with_persistence",
    "get_session_history",
    "end_current_session",
    # Guardar mensajes
    "save_user_message",
    "save_assistant_message",
    # Consultas
    "search_history",
    "get_current_context",
    "export_session_report",
    "get_session_stats",
    # Persistencia directa
    "persistence",
    "current_session_id",
]
