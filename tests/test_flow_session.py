"""Test de flujo de sesión (Fase 5).

Reproduce el ciclo completo del CLI: crear un Runner a partir del App del
agente, ejecutar un turno con un stub model (sin Ollama) y verificar que la
sesión se crea/guarda bajo el app_name esperado. Es la depuración de la causa:
si root_agent.name no coincide con el directorio, las sesiones quedan bajo un
app_name que la web no lista.
"""

import asyncio
from typing import AsyncGenerator

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from Cybersegurity_tutor import agent


class StubModel(BaseLlm):
    """Modelo que devuelve una respuesta fija sin llamar a Ollama."""

    model: str = "stub/test"

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        content = genai_types.Content(
            parts=[genai_types.Part(text="Respuesta del stub.")], role="model"
        )
        yield LlmResponse(content=content, turn_complete=True)


def _run(coro) -> None:
    """Ejecuta una corutina en un loop limpio (los tests son síncronos)."""
    return asyncio.run(coro)


def _get_session(session_service, app_name: str, user_id: str, session_id: str):
    """Lee una sesión (async) de forma síncrona."""
    return _run(
        session_service.get_session(
            app_name=app_name, user_id=user_id, session_id=session_id
        )
    )


def _patch_stub_model(monkeypatch) -> None:
    """Sustituye el modelo real del root_agent por el stub (evita Ollama)."""
    monkeypatch.setattr(agent.root_agent, "model", StubModel())
    monkeypatch.setattr(agent.app.root_agent, "model", StubModel())


def _create_session(session_service, app_name: str, user_id: str = "test_user"):
    """Crea una sesión (async) de forma síncrona."""
    return _run(session_service.create_session(app_name=app_name, user_id=user_id))


def _build_runner(
    session_service: InMemorySessionService, app_name: str | None = None
) -> Runner:
    """Construye un Runner desde agent.app, opcionalmente forzando app_name."""
    return Runner(
        app=agent.app,
        app_name=app_name,
        session_service=session_service,
    )


def test_session_created_under_app_name(session_service) -> None:
    """Una sesión creada vía el runner usa el app_name del App.

    El App exportado por agent.py tiene name=root_agent.name. Si ese nombre
    no coincide con el directorio del paquete, la web (que lista por
    directorio) no encontrará la sesión.
    """
    session = _create_session(session_service, agent.app.name)
    runner = _build_runner(session_service)
    assert runner.app_name == agent.app.name
    assert session.app_name == agent.app.name


def test_runner_uses_app_name_of_app(session_service) -> None:
    """El Runner derivado del App adopta su app_name."""
    runner = _build_runner(session_service)
    assert runner.app_name == agent.app.name


def test_app_name_override_wins(session_service) -> None:
    """app_name explícito gana sobre el nombre del App."""
    runner = _build_runner(session_service, app_name="otro_nombre")
    assert runner.app_name == "otro_nombre"


def test_flow_executes_and_saves_session(session_service, monkeypatch) -> None:
    """Un turno completo crea sesión + eventos con el stub model."""
    _patch_stub_model(monkeypatch)

    async def _create():
        return await session_service.create_session(
            app_name=agent.app.name, user_id="test_user"
        )

    session = _run(_create())
    runner = Runner(app=agent.app, session_service=session_service)
    events = list(
        runner.run(
            session_id=session.id,
            user_id="test_user",
            new_message=genai_types.Content(
                parts=[genai_types.Part(text="Hola")], role="user"
            ),
        )
    )
    assert events, "El runner debería emitir eventos"
    stored = _get_session(session_service, agent.app.name, "test_user", session.id)
    assert stored is not None


def test_session_state_persists_between_turns(session_service, monkeypatch) -> None:
    """El estado (lab_facts) persiste entre turnos de la misma sesión."""
    _patch_stub_model(monkeypatch)

    async def _create():
        return await session_service.create_session(
            app_name=agent.app.name, user_id="test_user"
        )

    session = _run(_create())
    runner = Runner(app=agent.app, session_service=session_service)
    user = genai_types.Content(parts=[genai_types.Part(text="Hola")], role="user")
    list(runner.run(session_id=session.id, user_id="test_user", new_message=user))
    session_after = _get_session(
        session_service, agent.app.name, "test_user", session.id
    )
    assert session_after is not None
    assert session_after.state is not None
