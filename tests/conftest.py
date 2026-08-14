"""Fixtures compartidos de los tests.

Proporcionan un ToolContext real de ADK (sobre InMemorySessionService) para
testear las tools de lab_memory sin tocar el modelo ni la BD.
"""

import asyncio
from typing import Any, Dict

import pytest

from google.adk.agents.invocation_context import InvocationContext
from google.adk.sessions import InMemorySessionService
from google.adk.tools import ToolContext

APP_NAME = "Cybersegurity_tutor"
USER_ID = "test_user"


@pytest.fixture
def session_service() -> InMemorySessionService:
    """Servicio de sesiones en memoria para los tests."""
    return InMemorySessionService()


def _build_tool_context(
    session_service: InMemorySessionService,
    state: Dict[str, Any],
) -> ToolContext:
    """Construye un ToolContext real sobre una sesión con estado dado."""

    async def _build() -> ToolContext:
        session = await session_service.create_session(
            app_name=APP_NAME, user_id=USER_ID, state=state
        )
        invocation_context = InvocationContext(
            session_service=session_service,
            invocation_id="test-invocation",
            session=session,
        )
        return ToolContext(invocation_context)

    return asyncio.run(_build())


@pytest.fixture
def tool_context(session_service: InMemorySessionService) -> ToolContext:
    """Crea un contexto de tool real con estado de sesión vacío."""
    return _build_tool_context(session_service, {})


@pytest.fixture
def tool_context_with_state(session_service: InMemorySessionService) -> ToolContext:
    """Crea un contexto de tool con estado de sesión pre-poblado (lab_facts)."""
    initial_state = {
        "lab_facts": {
            "target": "10.10.10.5",
            "environment": "HTB",
            "phase": "reconnaissance",
        }
    }
    return _build_tool_context(session_service, initial_state)
