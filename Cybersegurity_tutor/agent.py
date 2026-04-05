"""Agente principal del Cybersecurity Tutor.

Tutor pedagógico de hacking ético y pentesting profesional.
No ejecuta herramientas — analiza output, genera comandos explicados
y guía el razonamiento del estudiante a través del flujo completo.

Cobertura:
    - Análisis de output: nmap, gobuster, enum4linux, nikto, wpscan, linpeas, hashes
    - Comandos por fase: recon, web, smb, privesc Linux/Windows, passwords,
                        pivoting, OSINT, Active Directory completo, reporting, API
    - Cheatsheets (25+): herramientas base + impacket, mimikatz, msfvenom,
                        docker-escape, cloud AWS, ligolo, OWASP Top 10, OWASP API
    - Conceptos (18+): web vulns, AD attacks, técnicas avanzadas
    - Metodologías: PTES, OWASP WSTG, reporting profesional

Fixes v3:
    - DatabaseSessionService: historial de conversación persiste en SQLite
        entre reinicios del agente. Resuelve la pérdida de contexto.
    - LiteLlm timeouts explícitos: evita que silencios largos de qwen3.5
        (thinking tokens) rompan la conexión y creen una sesión nueva.
    - OLLAMA_NUM_CTX propagado como extra_body: garantiza que Ollama
        use la ventana de contexto correcta sin depender solo de la var de entorno.
    - thinking=False: suprime los tokens <think> de qwen3.5 en el chat.
        El modelo sigue razonando internamente; solo se omite el bloque visible.
"""

import os
from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.sessions import DatabaseSessionService

from .prompt import get_prompt
from .tools import (
    # ── Análisis de output ──────────────────────────────────────────────────
    analyze_nmap_output,
    analyze_gobuster_output,
    analyze_service_version,
    analyze_enum4linux_output,
    analyze_nikto_output,
    analyze_wpscan_output,
    analyze_linpeas_output,
    analyze_hash,
    # ── Comandos por fase — base ─────────────────────────────────────────────
    generate_pentest_commands,
    # ── Comandos por fase — extendido ────────────────────────────────────────
    generate_pentest_commands_extended,
    # ── Cheatsheets — base ───────────────────────────────────────────────────
    get_cheatsheet,
    # ── Cheatsheets — extendido ──────────────────────────────────────────────
    get_cheatsheet_extended,
    # ── Conceptos — base ─────────────────────────────────────────────────────
    explain_concept,
    # ── Conceptos — extendido ────────────────────────────────────────────────
    explain_concept_extended,
)
from .tools_tutorials import generate_tool_tutorial

# ============================================================================
# CONFIGURACIÓN
# ============================================================================

load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_API_BASE") or os.getenv(
    "OLLAMA_BASE_URL", "http://localhost:11434"
)
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "ollama_chat/qwen3.5:latest")
PERSISTENCE_DB = os.getenv("PERSISTENCE_DB_PATH", "/app/data/persistence/sessions.db")
NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "8192"))
REQUEST_TIMEOUT = int(os.getenv("LITELLM_REQUEST_TIMEOUT", "300"))
CONNECT_TIMEOUT = int(os.getenv("LITELLM_CONNECT_TIMEOUT", "30"))


# ============================================================================
# PERSISTENCIA DE SESIÓN
# ============================================================================
# DatabaseSessionService guarda el historial de conversación en SQLite.
# El historial sobrevive a:
#   - reinicios del contenedor Docker
#   - timeouts de Ollama / cold starts
#   - pérdidas de conexión temporales
#
# ADK crea la tabla automáticamente si no existe.
# La ruta está en el volumen nombrado del compose → persiste entre builds.

os.makedirs(os.path.dirname(PERSISTENCE_DB), exist_ok=True)

session_service = DatabaseSessionService(db_url=f"sqlite+aiosqlite:///{PERSISTENCE_DB}")

# ============================================================================
# MODELO
# ============================================================================
# extra_body propaga los parámetros directamente al payload de Ollama.
# Esto garantiza que num_ctx se aplique aunque la var de entorno no llegue
# al servidor Ollama correctamente (comportamiento inconsistente según versión).
#
# think=False suprime el bloque <think>...</think> que qwen3.5 genera antes
# de cada respuesta. El razonamiento interno sigue ocurriendo — solo se
# omite el bloque visible. Sin esto, el thinking puede:
#   - aparecer en el chat como texto crudo con etiquetas XML
#   - consumir tokens de contexto innecesariamente
#   - confundir a ADK al parsear la respuesta

model = LiteLlm(
    model=OLLAMA_MODEL,
    api_base=OLLAMA_URL,
    timeout=REQUEST_TIMEOUT,
    extra_body={
        "options": {
            "num_ctx": NUM_CTX,  # ventana de contexto explícita
        },
        "think": False,  # suprimir thinking tokens visibles de qwen3.5
    },
)

# ============================================================================
# AGENTE PRINCIPAL
# ============================================================================

root_agent = Agent(
    name="Cybersecurity_Tutor",
    description=(
        "Mentor experto en hacking ético y pentesting profesional. "
        "Guía el flujo completo de auditorías: reconocimiento, enumeración, "
        "explotación, post-explotación Linux/Windows, Active Directory, "
        "pivoting, OSINT y reporting. "
        "siguiendo estándares PTES, OWASP WSTG y metodología profesional. "
        "Cubre: reconocimiento, enumeración web/SMB/AD, explotación, "
        "post-explotación Linux/Windows, Active Directory attacks completo, "
        "pivoting, OSINT y documentación/reporting. "
        "Analiza output de herramientas (nmap, gobuster, enum4linux, nikto, "
        "wpscan, linpeas), genera comandos explicados y construye el razonamiento del estudiante paso a paso."
    ),
    model=model,
    instruction=get_prompt(),
    tools=[
        # Análisis de output — el estudiante pega, el tutor interpreta
        analyze_nmap_output,
        analyze_gobuster_output,
        analyze_service_version,
        analyze_enum4linux_output,
        analyze_nikto_output,
        analyze_wpscan_output,
        analyze_linpeas_output,
        analyze_hash,
        # Flujo profesional por fases
        generate_pentest_commands,  # recon, web, smb, privesc, passwords, pivoting
        generate_pentest_commands_extended,  # osint, active_directory, reporting, api_testing
        # Referencia técnica
        get_cheatsheet,  # nmap, gobuster, ffuf, metasploit, smb, etc.
        get_cheatsheet_extended,  # impacket, mimikatz, msfvenom, docker, owasp, etc.
        explain_concept,  # SUID, SQLi, reverse shell, SSRF, IDOR, JWT, etc.
        explain_concept_extended,  # XXE, CSRF, SSTI, LFI, deserialization, AD, etc.
        # ── Tutoriales estructurados ─────────────────────────────────────────
        generate_tool_tutorial,  # tutorial completo por herramienta y nivel
    ],
)
