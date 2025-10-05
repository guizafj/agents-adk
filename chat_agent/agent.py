from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
import os
from typing import Optional, Dict, Any
from dotenv import load_dotenv

from .prompt import get_prompt
from .tools import (
    nmap_scan,
    ping_check,
    gobuster_dir,
    whois_lookup,
    dns_lookup,
    search_exploit,
    get_cheatsheet
)
from .database import AgentPersistence

# Cargar variables del archivo .env
load_dotenv()

# Configurar URL de Ollama (priorizar OLLAMA_API_BASE del .env)
ollama_url = os.getenv("OLLAMA_API_BASE") or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

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

def create_agent_with_persistence(session_id: Optional[str] = None) -> tuple[Agent, str]:
    """
    Crea un agente con persistencia habilitada.
    
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
    base_prompt = get_prompt()
    enhanced_prompt = f"""{base_prompt}

--- CONTEXTO DE SESIÓN ---
{context}

IMPORTANTE: Usa este contexto para mantener continuidad en la conversación.
Si hay información de sesiones anteriores (puertos, servicios, vulnerabilidades),
refiérete a ella y construye sobre ese conocimiento.
"""
    
    # Crear agente con contexto persistente
    agent = Agent(
        name="chat_agent",
        description="Cybersecurity mentor agent specialized in ethical hacking, penetration testing, and security analysis",
        model=LiteLlm(
            model="ollama_chat/qwen3:8b",
            instruction=enhanced_prompt,
            tools=[
                # Reconocimiento y escaneo
                nmap_scan,
                ping_check,
                gobuster_dir,
                # Análisis y enumeración
                whois_lookup,
                dns_lookup,
                # Utilidad y referencia
                search_exploit,
                get_cheatsheet
            ],
            api_base=ollama_url
        ),
    )
    
    return agent, current_session_id


def start_new_lab_session(
    lab_name: str,
    lab_environment: str = "Local",
    lab_target: str = None,
    lab_objective: str = None
) -> str:
    """
    Inicia una nueva sesión específica para un lab de pentesting.
    
    Args:
        lab_name: Nombre del lab (ej: "HTB - Nibbles")
        lab_environment: Plataforma (HTB, TryHackMe, CTF, etc.)
        lab_target: IP o hostname del objetivo
        lab_objective: Descripción del objetivo
    
    Returns:
        session_id de la nueva sesión
    """
    global current_session_id
    
    current_session_id = persistence.start_session(
        session_name=lab_name,
        lab_environment=lab_environment,
        lab_target=lab_target,
        lab_objective=lab_objective
    )
    
    return current_session_id


def list_active_sessions():
    """
    Lista todas las sesiones activas.
    
    Returns:
        Lista de diccionarios con información de sesiones
    """
    return persistence.get_active_sessions(limit=20)


def get_session_history(max_messages: int = 20):
    """
    Obtiene el historial de la sesión actual.
    
    Args:
        max_messages: Número máximo de mensajes a recuperar
    
    Returns:
        Lista de mensajes
    """
    return persistence.get_history(max_messages=max_messages)


def end_current_session(completed: bool = False):
    """
    Finaliza la sesión actual.
    
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
    """
    Guarda un mensaje del usuario en la base de datos.
    
    Args:
        message: Contenido del mensaje
    """
    if current_session_id:
        persistence.add_user_message(message)


def save_assistant_message(
    response: str,
    tool_calls: Optional[list] = None,
    tool_results: Optional[list] = None
):
    """
    Guarda un mensaje del asistente en la base de datos.
    
    Args:
        response: Contenido de la respuesta
        tool_calls: Lista de herramientas llamadas
        tool_results: Resultados de las herramientas
    """
    if current_session_id:
        persistence.add_assistant_message(
            content=response,
            tool_calls=tool_calls,
            tool_results=tool_results
        )


# ============================================================================
# HOOKS PARA ACTUALIZAR CONTEXTO DEL LAB
# ============================================================================

def update_lab_phase(phase: str):
    """
    Actualiza la fase actual del pentesting.
    
    Args:
        phase: reconnaissance | enumeration | exploitation | post-exploitation
    """
    if current_session_id:
        persistence.update_phase(phase)


def save_nmap_results(results: Dict[str, Any]):
    """
    Procesa y guarda resultados de nmap en el contexto.
    
    Args:
        results: Diccionario con resultados de nmap
    """
    if not current_session_id or results.get('status') != 'success':
        return
    
    # Extraer y guardar puertos abiertos
    if 'open_ports' in results:
        persistence.add_ports(results['open_ports'])
    
    # Extraer y guardar servicios
    if 'services' in results:
        for service in results['services']:
            persistence.add_service(
                port=service.get('port'),
                service=service.get('name', 'unknown'),
                version=service.get('version', 'unknown')
            )


def save_vulnerability(name: str, description: str, severity: str = "medium"):
    """
    Guarda una vulnerabilidad encontrada.
    
    Args:
        name: Nombre de la vulnerabilidad
        description: Descripción detallada
        severity: info | low | medium | high | critical
    """
    if current_session_id:
        persistence.add_vulnerability(name, description, severity)


def save_credentials(username: str, password: str, service: str = None):
    """
    Guarda credenciales obtenidas durante el pentesting.
    
    Args:
        username: Usuario
        password: Contraseña
        service: Servicio asociado
    """
    if current_session_id:
        persistence.add_credential(username, password, service)


def save_flag(flag_type: str, flag_value: str):
    """
    Guarda una flag capturada.
    
    Args:
        flag_type: Tipo de flag (user_flag, root_flag, etc.)
        flag_value: Valor de la flag
    """
    if current_session_id:
        persistence.set_flag(flag_type, flag_value)


def add_lab_notes(notes: str):
    """
    Añade notas al contexto del lab actual.
    
    Args:
        notes: Texto de las notas
    """
    if current_session_id:
        persistence.add_notes(notes)


# ============================================================================
# UTILIDADES DE CONSULTA
# ============================================================================

def search_history(search_term: str, limit: int = 10):
    """
    Busca en el historial de todas las conversaciones.
    
    Args:
        search_term: Término a buscar
        limit: Número máximo de resultados
    
    Returns:
        Lista de mensajes que coinciden con la búsqueda
    """
    return persistence.search(search_term, limit=limit)


def get_current_context():
    """
    Obtiene el contexto completo de la sesión actual.
    
    Returns:
        Diccionario con sesión y contexto del lab
    """
    return persistence.get_full_context()


def export_session_report():
    """
    Exporta un reporte completo de la sesión actual.
    
    Returns:
        Diccionario con toda la información de la sesión
    """
    return persistence.export_report()


def get_session_stats():
    """
    Obtiene estadísticas de la sesión actual.
    
    Returns:
        Diccionario con estadísticas
    """
    return persistence.get_statistics()


# ============================================================================
# AGENTE POR DEFECTO (Sin persistencia para compatibilidad)
# ============================================================================

root_agent = Agent(
    name="chat_agent",
    description="Cybersecurity mentor agent specialized in ethical hacking, penetration testing, and security analysis",
    model=LiteLlm(
        model="ollama_chat/qwen3:8b",
        instruction=get_prompt(),
        tools=[
            # Reconocimiento y escaneo
            nmap_scan,
            ping_check,
            gobuster_dir,
            # Análisis y enumeración
            whois_lookup,
            dns_lookup,
            # Utilidad y referencia
            search_exploit,
            get_cheatsheet
        ],
        api_base=ollama_url
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
    "start_new_lab_session",
    "list_active_sessions",
    "get_session_history",
    "end_current_session",
    
    # Guardar mensajes
    "save_user_message",
    "save_assistant_message",
    
    # Actualizar contexto
    "update_lab_phase",
    "save_nmap_results",
    "save_vulnerability",
    "save_credentials",
    "save_flag",
    "add_lab_notes",
    
    # Consultas
    "search_history",
    "get_current_context",
    "export_session_report",
    "get_session_stats",
    
    # Persistencia directa
    "persistence",
    "current_session_id",
]