"""Memoria estructurada del laboratorio (Fase 2).

Desacopla los "hechos del lab" del historial de chat: los hallazgos clave
(puertos, servicios, vulnerabilidades, fase, flags) se guardan en el estado
persistente de la sesión ADK y se inyectan como bloque compacto antes de cada
llamada al modelo. Así el contexto sobrevive a compactaciones y conversaciones
largas sin duplicar información en cada turno.
"""

from typing import Any, Dict, List, Optional

from google.adk.tools import ToolContext

LAB_FACTS_KEY = "lab_facts"


def _get_facts(tool_context: ToolContext) -> Dict[str, Any]:
    """Obtiene o inicializa el dict de hechos del lab en el estado.

    Args:
        tool_context: Contexto de la tool que da acceso al estado de sesión.

    Returns:
        El dict lab_facts actualizado (creado si no existía).
    """
    facts = tool_context.state.get(LAB_FACTS_KEY) or {}
    tool_context.state[LAB_FACTS_KEY] = facts
    return facts


def _append(facts: Dict[str, Any], key: str, value: Any):
    """Añade un valor a una lista existente o crea una nueva.

    Args:
        facts: Dict de hechos del lab.
        key: Clave de la lista.
        value: Valor a añadir.
    """
    items = facts.get(key) or []
    items.append(value)
    facts[key] = items


# ============================================================================
# TOOLS DE REGISTRO DE HECHOS
# ============================================================================


def record_phase(phase: str, tool_context: ToolContext) -> Dict[str, Any]:
    """Registra la fase actual del pentesting.

    Args:
        phase: Fase: reconnaissance | enumeration | exploitation |
            post-exploitation.
        tool_context: Contexto de la tool.

    Returns:
        Confirmación con la fase registrada.
    """
    facts = _get_facts(tool_context)
    facts["phase"] = phase
    return {"ok": True, "phase": phase}


def record_port(
    port: int,
    service: str,
    version: Optional[str] = None,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """Registra un puerto abierto y su servicio.

    Args:
        port: Número de puerto.
        service: Nombre del servicio (ssh, http, etc.).
        version: Versión detectada del servicio.
        tool_context: Contexto de la tool.

    Returns:
        Confirmación con puerto y servicio registrados.
    """
    if tool_context is None:
        raise ValueError("tool_context es requerido")
    facts = _get_facts(tool_context)
    ports = facts.get("ports") or []
    entry = {"port": port, "service": service, "version": version}
    for p in ports:
        if p.get("port") == port:
            p.update(entry)
            facts["ports"] = ports
            return {
                "ok": True,
                "port": port,
                "service": service,
                "updated": True,
            }
    ports.append(entry)
    facts["ports"] = ports
    return {"ok": True, "port": port, "service": service, "updated": False}


def record_finding(
    finding_type: str,
    description: str,
    severity: str = "info",
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """Registra un hallazgo (vulnerabilidad o información relevante).

    Args:
        finding_type: Tipo (vulnerability, service, credential, etc.).
        description: Descripción del hallazgo.
        severity: severity: info | low | medium | high | critical.
        tool_context: Contexto de la tool.

    Returns:
        Confirmación con el hallazgo registrado.
    """
    if tool_context is None:
        raise ValueError("tool_context es requerido")
    facts = _get_facts(tool_context)
    _append(
        facts,
        "findings",
        {
            "type": finding_type,
            "description": description,
            "severity": severity,
        },
    )
    return {"ok": True, "finding_type": finding_type, "severity": severity}


def record_credential(
    username: str,
    password: str,
    service: Optional[str] = None,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """Registra una credencial obtenida durante el pentesting.

    Args:
        username: Usuario.
        password: Contraseña.
        service: Servicio asociado.
        tool_context: Contexto de la tool.

    Returns:
        Confirmación con la credencial registrada.
    """
    if tool_context is None:
        raise ValueError("tool_context es requerido")
    facts = _get_facts(tool_context)
    _append(
        facts,
        "credentials",
        {"username": username, "password": password, "service": service},
    )
    return {"ok": True, "username": username, "service": service}


def record_flag(
    flag_type: str, flag_value: str, tool_context: ToolContext = None
) -> Dict[str, Any]:
    """Guarda una flag capturada.

    Args:
        flag_type: user_flag | root_flag | etc.
        flag_value: Valor de la flag.
        tool_context: Contexto de la tool.

    Returns:
        Confirmación con la flag guardada.
    """
    if tool_context is None:
        raise ValueError("tool_context es requerido")
    facts = _get_facts(tool_context)
    flags = facts.get("flags") or {}
    flags[flag_type] = flag_value
    facts["flags"] = flags
    return {"ok": True, "flag_type": flag_type}


def record_notes(notes: str, tool_context: ToolContext = None) -> Dict[str, Any]:
    """Añade notas libres al contexto del lab.

    Args:
        notes: Texto de las notas.
        tool_context: Contexto de la tool.

    Returns:
        Confirmación con las notas guardadas.
    """
    if tool_context is None:
        raise ValueError("tool_context es requerido")
    facts = _get_facts(tool_context)
    existing = facts.get("notes") or ""
    facts["notes"] = f"{existing}\n\n{notes}".strip()
    return {"ok": True, "notes_added": len(notes)}


def record_target(
    target: str,
    environment: Optional[str] = None,
    objective: Optional[str] = None,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """Define el objetivo del lab (IP/host, plataforma, meta).

    Args:
        target: IP o nombre del objetivo.
        environment: Plataforma (HTB, TryHackMe, propio, etc.).
        objective: Descripción de la meta.
        tool_context: Contexto de la tool.

    Returns:
        Confirmación con el objetivo registrado.
    """
    if tool_context is None:
        raise ValueError("tool_context es requerido")
    facts = _get_facts(tool_context)
    if target:
        facts["target"] = target
    if environment:
        facts["environment"] = environment
    if objective:
        facts["objective"] = objective
    return {"ok": True, "target": target}


LAB_TOOLS = [
    record_phase,
    record_port,
    record_finding,
    record_credential,
    record_flag,
    record_notes,
    record_target,
]


# ============================================================================
# INYECCIÓN DE CONTEXTO EN CADA TURNO
# ============================================================================


def build_lab_facts_block(facts: Dict[str, Any]) -> str:
    """Construye un bloque compacto de hechos del lab.

    Args:
        facts: Dict con los hechos estructurados del lab.

    Returns:
        Texto formateado listo para inyectar en el prompt.
    """
    if not facts:
        return ""

    lines: List[str] = ["=== ESTADO DEL LABORATORIO (resumen fiel) ==="]

    if facts.get("target"):
        lines.append(f"Objetivo: {facts['target']}")
    if facts.get("environment"):
        lines.append(f"Plataforma: {facts['environment']}")
    if facts.get("objective"):
        lines.append(f"Meta: {facts['objective']}")
    if facts.get("phase"):
        lines.append(f"Fase: {facts['phase']}")

    ports = facts.get("ports") or []
    if ports:
        port_str = ", ".join(
            f"{p['port']}/{p.get('service', '?')}"
            + (f" ({p['version']})" if p.get("version") else "")
            for p in ports
        )
        lines.append(f"Puertos abiertos: {port_str}")

    findings = facts.get("findings") or []
    if findings:
        lines.append("Hallazgos:")
        for f in findings:
            lines.append(
                f"  - [{f.get('severity', 'info')}] {f.get('type')}: "
                f"{f.get('description')}"
            )

    creds = facts.get("credentials") or []
    for c in creds:
        service = c.get("service") or ""
        lines.append(
            f"Credencial: {c.get('username')} / {c.get('password')}"
            f"{f' ({service})' if service else ''}"
        )

    flags = facts.get("flags") or {}
    for flag_type, value in flags.items():
        lines.append(f"Flag {flag_type}: {value}")

    notes = facts.get("notes")
    if notes:
        lines.append(f"Notas:\n{notes}")

    return "\n".join(lines)


def inject_lab_facts(callback_context, llm_request) -> None:
    """Inyecta el bloque compacto de hechos del lab al prompt.

    Se ejecuta como before_model_callback: añade el estado estructurado al
    system instruction sin escribir en el historial de chat. No interrumpe
    la llamada al modelo (siempre devuelve None).

    Args:
        callback_context: Contexto de la invocación ADK.
        llm_request: Request del modelo; se muta con append_instructions.

    Returns:
        None: no sustituye la respuesta del modelo.
    """
    block = build_lab_facts_block(callback_context.state.get(LAB_FACTS_KEY) or {})
    if block:
        llm_request.append_instructions([block])
    return None
