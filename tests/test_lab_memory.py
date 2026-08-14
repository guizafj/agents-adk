"""Tests unitarios de Cybersegurity_tutor/lab_memory.py (Fase 2).

Cubren las 7 tools de registro de hechos, el formateo del bloque compacto
(build_lab_facts_block) y el callback de inyección (inject_lab_facts).
"""

from google.adk.tools import ToolContext

from Cybersegurity_tutor.lab_memory import (
    LAB_FACTS_KEY,
    build_lab_facts_block,
    inject_lab_facts,
    record_credential,
    record_finding,
    record_flag,
    record_notes,
    record_phase,
    record_port,
    record_target,
)


def _facts(tool_context: ToolContext) -> dict:
    return tool_context.state.get(LAB_FACTS_KEY) or {}


def test_record_phase_sets_phase(tool_context: ToolContext) -> None:
    result = record_phase("exploitation", tool_context)
    assert result == {"ok": True, "phase": "exploitation"}
    assert _facts(tool_context)["phase"] == "exploitation"


def test_record_phase_overwrites(tool_context: ToolContext) -> None:
    record_phase("reconnaissance", tool_context)
    record_phase("enumeration", tool_context)
    assert _facts(tool_context)["phase"] == "enumeration"


def test_record_port_adds_new(tool_context: ToolContext) -> None:
    result = record_port(22, "ssh", "OpenSSH 8.2", tool_context)
    assert result["ok"] is True
    assert result["updated"] is False
    ports = _facts(tool_context)["ports"]
    assert ports == [{"port": 22, "service": "ssh", "version": "OpenSSH 8.2"}]


def test_record_port_updates_existing(tool_context: ToolContext) -> None:
    record_port(22, "ssh", tool_context=tool_context)
    result = record_port(22, "ssh", "OpenSSH 9.0", tool_context)
    assert result["updated"] is True
    ports = _facts(tool_context)["ports"]
    assert len(ports) == 1
    assert ports[0]["version"] == "OpenSSH 9.0"


def test_record_finding_appends(tool_context: ToolContext) -> None:
    result = record_finding("vulnerability", "SQLi en login", "high", tool_context)
    assert result["ok"] is True
    findings = _facts(tool_context)["findings"]
    assert len(findings) == 1
    assert findings[0] == {
        "type": "vulnerability",
        "description": "SQLi en login",
        "severity": "high",
    }


def test_record_credential_appends(tool_context: ToolContext) -> None:
    record_credential("admin", "admin123", "http", tool_context)
    creds = _facts(tool_context)["credentials"]
    assert creds == [{"username": "admin", "password": "admin123", "service": "http"}]


def test_record_flag_stores_by_type(tool_context: ToolContext) -> None:
    record_flag("user_flag", "HTB{user}", tool_context)
    assert _facts(tool_context)["flags"] == {"user_flag": "HTB{user}"}


def test_record_notes_appends_text(tool_context: ToolContext) -> None:
    record_notes("primera nota", tool_context)
    record_notes("segunda nota", tool_context)
    notes = _facts(tool_context)["notes"]
    assert "primera nota" in notes
    assert "segunda nota" in notes


def test_record_target_sets_fields(tool_context: ToolContext) -> None:
    record_target("10.10.11.42", "HTB", "pwned", tool_context)
    facts = _facts(tool_context)
    assert facts["target"] == "10.10.11.42"
    assert facts["environment"] == "HTB"
    assert facts["objective"] == "pwned"


def test_record_tools_require_tool_context() -> None:
    cases = (
        (record_port, (22, "ssh")),
        (record_finding, ("vulnerability", "desc")),
        (record_credential, ("admin", "admin123")),
        (record_flag, ("user_flag", "HTB{user}")),
        (record_notes, ("nota",)),
        (record_target, ("10.0.0.1",)),
    )
    for fn, args in cases:
        try:
            fn(*args, tool_context=None)
        except ValueError as exc:
            assert "tool_context" in str(exc)
        else:
            raise AssertionError(f"{fn.__name__} debería exigir tool_context")


# ---------------------------------------------------------------------------
# build_lab_facts_block
# ---------------------------------------------------------------------------


def test_build_block_empty_returns_empty_string() -> None:
    assert build_lab_facts_block({}) == ""


def test_build_block_full(tool_context: ToolContext) -> None:
    record_target("10.10.10.5", "HTB", "root", tool_context)
    record_phase("exploitation", tool_context)
    record_port(80, "http", "Apache 2.4", tool_context)
    record_finding("vulnerability", "path traversal", "critical", tool_context)
    record_credential("root", "toor", "ssh", tool_context)
    record_flag("root_flag", "HTB{root}", tool_context)

    block = build_lab_facts_block(_facts(tool_context))
    assert "=== ESTADO DEL LABORATORIO" in block
    assert "Objetivo: 10.10.10.5" in block
    assert "Plataforma: HTB" in block
    assert "Fase: exploitation" in block
    assert "80/http (Apache 2.4)" in block
    assert "[critical] vulnerability: path traversal" in block
    assert "root / toor (ssh)" in block
    assert "Flag root_flag: HTB{root}" in block


def test_inject_lab_facts_injects_block(
    tool_context_with_state: ToolContext,
) -> None:
    class FakeRequest:
        def __init__(self) -> None:
            self.instructions = []

        def append_instructions(self, blocks) -> None:
            self.instructions.extend(blocks)

    class FakeCallbackContext:
        state = tool_context_with_state.state

    request = FakeRequest()
    result = inject_lab_facts(FakeCallbackContext(), request)
    assert result is None
    assert len(request.instructions) == 1
    assert "Objetivo: 10.10.10.5" in request.instructions[0]


def test_inject_lab_facts_noop_without_facts(tool_context: ToolContext) -> None:
    class FakeRequest:
        def __init__(self) -> None:
            self.instructions = []

        def append_instructions(self, blocks) -> None:
            self.instructions.extend(blocks)

    class FakeCallbackContext:
        state = tool_context.state

    request = FakeRequest()
    inject_lab_facts(FakeCallbackContext(), request)
    assert request.instructions == []
