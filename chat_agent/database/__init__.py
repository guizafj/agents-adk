"""
Database package for chat agent persistence.

Módulos:
- persistence: Gestor de base de datos de bajo nivel (SessionManager)
- agent_wrapper: Wrapper de alto nivel para integración con Google ADK (AgentPersistence)

Uso rápido:
    from chat_agent.database import AgentPersistence
    
    persistence = AgentPersistence("persistence.db")
    session_id = persistence.start_session(
        session_name="HTB - Nibbles",
        lab_environment="HackTheBox",
        lab_target="10.10.10.75"
    )
"""
from .persistence import SessionManager
from .agent_wrapper import AgentPersistence

__all__ = ["SessionManager", "AgentPersistence"]
