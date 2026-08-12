"""Memoria recuperable: búsqueda ligera sobre el historial persistido (Fase 4).

Cuando la compactación reduce el contexto a resúmenes, los detalles concretos
de sesiones anteriores quedan fuera del chat. Esta tool permite recuperarlos
a demanda consultando el historial de eventos que ADK guarda en SQLite
(sessions.db), devolviendo fragmentos relevantes sin cargar la sesión entera.
"""

import json
import os
import sqlite3
from typing import Any, Dict, List

DEFAULT_DB = "/app/data/persistence/sessions.db"


def _text_parts(event_data: Dict[str, Any]) -> List[str]:
    """Extrae los fragmentos de texto legible de un evento.

    Args:
        event_data: Dict con el evento serializado de ADK.

    Returns:
        Lista de textos user/assistant del evento.
    """
    content = event_data.get("content")
    if not content or not isinstance(content, dict):
        return []
    parts = content.get("parts") or []
    return [p.get("text") for p in parts if isinstance(p, dict) and p.get("text")]


def _find_db() -> str:
    """Devuelve la ruta de la BD de sesiones a consultar.

    Usa PERSISTENCE_DB_PATH si existe; si no, busca session.db en el .adk del
    agente (ruta local usada por el CLI cuando no se pasa --session_service_uri).

    Returns:
        Ruta absoluta de la BD SQLite de sesiones.
    """
    env_db = os.getenv("PERSISTENCE_DB_PATH")
    if env_db and os.path.exists(env_db):
        return env_db

    default = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".adk", "session.db"
    )
    return default if os.path.exists(default) else DEFAULT_DB


def search_lab_memory(query: str, limit: int = 5) -> Dict[str, Any]:
    """Busca fragmentos del historial persistido que coincidan con una consulta.

    Busca en los eventos user/assistant de todas las sesiones guardadas y
    devuelve los fragmentos más recientes, sin cargar la conversación completa.
    Es memoria a demanda (RAG ligero): útil para recuperar detalles que ya
    quedaron fuera del prompt por compactación o entre sesiones.

    Args:
        query: Términos a buscar (se divide por espacios; el fragmento debe
            contener todos los términos para considerarse relevante).
        limit: Máximo de fragmentos a devolver (default 5, máximo 20).

    Returns:
        Dict con lista de resultados: session_id, timestamp y fragmento.
    """
    db_path = _find_db()
    if not os.path.exists(db_path):
        return {"results": [], "error": f"BD no encontrada: {db_path}"}

    limit = max(1, min(int(limit), 20))
    terms = [t.lower() for t in query.split() if len(t) >= 2]
    results: List[Dict[str, Any]] = []

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.execute(
            """
            SELECT session_id, timestamp, event_data
            FROM events
            ORDER BY timestamp DESC
            """
        )
        for session_id, timestamp, event_data in cursor.fetchall():
            raw = event_data if isinstance(event_data, str) else json.dumps(event_data)
            if not all(t in raw.lower() for t in terms):
                continue
            try:
                parsed = (
                    json.loads(event_data)
                    if isinstance(event_data, str)
                    else event_data
                )
            except json.JSONDecodeError:
                continue
            for text in _text_parts(parsed):
                if all(t in text.lower() for t in terms):
                    results.append(
                        {
                            "session_id": str(session_id)[:8],
                            "timestamp": float(timestamp),
                            "snippet": text[:400],
                        }
                    )
            if len(results) >= limit:
                break
        conn.close()
    except sqlite3.Error as exc:
        return {"results": [], "error": f"Error consultando {db_path}: {exc}"}

    if not results:
        return {"results": [], "message": "Sin coincidencias en el historial."}
    return {"results": results[:limit]}
