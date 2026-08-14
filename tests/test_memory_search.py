"""Tests unitarios de Cybersegurity_tutor/memory_search.py (Fase 4).

Cubren la extracción de texto de eventos, la localización de la BD y la
búsqueda multi-término sobre una BD SQLite temporal.
"""

import json
import os
import sqlite3

import pytest

from Cybersegurity_tutor import memory_search

# Evento estilo ADK con contenido user/assistant
EVENT_USER = {
    "content": {"parts": [{"text": "He encontrado el puerto 80 abierto con Apache"}]}
}
EVENT_ASSISTANT = {
    "content": {
        "parts": [{"text": "Enumera /manager con las credenciales por defecto"}]
    }
}


def _create_db(path: str, rows: list) -> None:
    """Crea una BD temporal con la tabla events (esquema ADK mínimo)."""
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            app_name TEXT,
            user_id TEXT,
            session_id TEXT,
            event_id TEXT,
            timestamp REAL,
            invocation_id TEXT,
            author TEXT,
            event_data TEXT,
            is_escalated INTEGER,
            PRIMARY KEY (app_name, user_id, session_id, event_id)
        )
        """
    )
    for i, (session_id, ts, data) in enumerate(rows):
        conn.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "Cybersegurity_tutor",
                "test_user",
                session_id,
                f"evt{i}",
                ts,
                "inv0",
                "user",
                json.dumps(data),
                0,
            ),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def tmp_db_path(tmp_path) -> str:
    """Crea una BD temporal con 3 sesiones y datos de ejemplo."""
    db_path = str(tmp_path / "sessions.db")
    rows = [
        ("sess-a", 3.0, EVENT_USER),
        ("sess-a", 4.0, EVENT_ASSISTANT),
        ("sess-b", 2.0, EVENT_USER),
        ("sess-b", 5.0, EVENT_ASSISTANT),
    ]
    _create_db(db_path, rows)
    return db_path


def test_text_parts_extracts_user_assistant() -> None:
    parts = memory_search._text_parts(EVENT_ASSISTANT)
    assert parts == ["Enumera /manager con las credenciales por defecto"]


def test_text_parts_handles_missing_content() -> None:
    assert memory_search._text_parts({}) == []
    assert memory_search._text_parts({"content": {"parts": []}}) == []
    assert memory_search._text_parts({"content": {"parts": [{"x": 1}]}}) == []


def test_find_db_prefers_env(tmp_db_path, monkeypatch) -> None:
    monkeypatch.setenv("PERSISTENCE_DB_PATH", tmp_db_path)
    assert memory_search._find_db() == tmp_db_path


def test_find_db_falls_back_to_adk(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("PERSISTENCE_DB_PATH", raising=False)
    adk_dir = os.path.join(
        os.path.dirname(os.path.abspath(memory_search.__file__)), ".adk"
    )
    session_db = os.path.join(adk_dir, "session.db")
    if os.path.exists(session_db):
        monkeypatch.setattr(memory_search, "DEFAULT_DB", str(tmp_path / "missing.db"))
        assert memory_search._find_db() == session_db
    else:
        monkeypatch.setattr(memory_search, "DEFAULT_DB", str(tmp_path / "x.db"))
        assert memory_search._find_db() == str(tmp_path / "x.db")


def test_search_finds_match(tmp_db_path, monkeypatch) -> None:
    monkeypatch.setenv("PERSISTENCE_DB_PATH", tmp_db_path)
    result = memory_search.search_lab_memory("/manager credenciales")
    assert result["results"]
    snippet = result["results"][0]["snippet"]
    assert "/manager" in snippet


def test_search_empty_db_returns_message(tmp_path, monkeypatch) -> None:
    db_path = str(tmp_path / "empty.db")
    _create_db(db_path, [])
    monkeypatch.setenv("PERSISTENCE_DB_PATH", db_path)
    result = memory_search.search_lab_memory("apache")
    assert result["results"] == []
    assert "Sin coincidencias" in result.get("message", "")


def test_search_no_match(tmp_db_path, monkeypatch) -> None:
    monkeypatch.setenv("PERSISTENCE_DB_PATH", tmp_db_path)
    result = memory_search.search_lab_memory("neologismoxxx")
    assert result["results"] == []
    assert "Sin coincidencias" in result.get("message", "")


def test_search_limit_respected(tmp_db_path, monkeypatch) -> None:
    monkeypatch.setenv("PERSISTENCE_DB_PATH", tmp_db_path)
    result = memory_search.search_lab_memory("puerto", limit=1)
    assert len(result["results"]) == 1


def test_search_missing_db_returns_error(tmp_path, monkeypatch) -> None:
    missing = str(tmp_path / "no-existe.db")
    monkeypatch.setattr(memory_search, "_find_db", lambda: missing)
    result = memory_search.search_lab_memory("apache")
    assert result["results"] == []
    assert "BD no encontrada" in result.get("error", "")
