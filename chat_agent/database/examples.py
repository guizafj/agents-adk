"""
Ejemplos de uso del sistema de persistencia.
Muestra cómo integrar la persistencia con el agente de ciberseguridad.
"""

from chat_agent.database import AgentPersistence


# ============================================================================
# EJEMPLO 1: INICIO BÁSICO DE SESIÓN
# ============================================================================

def example_basic_session():
    """Ejemplo de creación y uso básico de una sesión."""
    
    # Inicializar persistencia
    persistence = AgentPersistence("demo_persistence.db")
    
    # Crear nueva sesión de pentesting
    session_id = persistence.start_session(
        session_name="HTB - Nibbles",
        lab_environment="HackTheBox",
        lab_target="10.10.10.75",
        lab_objective="Capturar user.txt y root.txt"
    )
    
    print(f"✓ Sesión creada: {session_id}")
    
    # Simular conversación
    persistence.add_user_message("Vamos a empezar con un nmap scan del objetivo")
    persistence.add_assistant_message(
        content="Perfecto, voy a ejecutar un escaneo básico con nmap.",
        tool_calls=[{"tool": "nmap_scan", "target": "10.10.10.75"}],
        tool_results=[{"status": "success", "open_ports": [22, 80]}]
    )
    
    # Actualizar contexto con hallazgos
    persistence.add_ports([22, 80])
    persistence.add_service(22, "ssh", "OpenSSH 7.2p2")
    persistence.add_service(80, "http", "Apache 2.4.18")
    
    print("✓ Contexto actualizado con puertos y servicios")
    
    # Obtener resumen del contexto
    context = persistence.get_context_summary()
    print("\n" + context)
    
    # Finalizar sesión
    persistence.end_session(mark_as_completed=False)
    print("\n✓ Sesión pausada")


# ============================================================================
# EJEMPLO 2: TRACKING COMPLETO DE UN LAB
# ============================================================================

def example_full_lab_tracking():
    """Ejemplo de tracking completo durante un pentesting lab."""
    
    persistence = AgentPersistence("demo_persistence.db")
    
    # Iniciar sesión
    session_id = persistence.start_session(
        session_name="HTB - Lame",
        lab_environment="HackTheBox",
        lab_target="10.10.10.3",
        lab_objective="Root access en máquina Linux"
    )
    
    print(f"🎯 Iniciando pentesting de HTB - Lame")
    print(f"   Session ID: {session_id}\n")
    
    # FASE 1: RECONNAISSANCE
    print("📡 FASE: RECONNAISSANCE")
    persistence.update_phase("reconnaissance")
    
    persistence.add_user_message("Empecemos con reconocimiento del objetivo 10.10.10.3")
    persistence.add_assistant_message(
        content="Ejecutando nmap con detección de versiones...",
        tool_calls=[{"tool": "nmap_scan", "target": "10.10.10.3", "flags": "-sV"}]
    )
    
    # Actualizar hallazgos
    persistence.add_ports([21, 22, 139, 445, 3632])
    persistence.add_service(21, "ftp", "vsftpd 2.3.4")
    persistence.add_service(22, "ssh", "OpenSSH 4.7p1")
    persistence.add_service(139, "netbios-ssn", "Samba 3.0.20")
    persistence.add_service(445, "microsoft-ds", "Samba 3.0.20")
    
    persistence.add_finding(
        finding_type="service",
        description="vsftpd 2.3.4 en puerto 21 - Versión con backdoor conocido",
        severity="high"
    )
    
    print("   ✓ Puertos y servicios identificados")
    print("   ✓ Hallazgo: vsftpd 2.3.4 vulnerable\n")
    
    # FASE 2: ENUMERATION
    print("🔍 FASE: ENUMERATION")
    persistence.update_phase("enumeration")
    
    persistence.add_user_message("Busquemos exploits conocidos para vsftpd 2.3.4")
    persistence.add_assistant_message(
        content="Buscando en Exploit-DB...",
        tool_calls=[{"tool": "search_exploit", "query": "vsftpd 2.3.4"}],
        tool_results=[{
            "status": "success",
            "exploits_found": [
                {"id": "17491", "title": "vsftpd 2.3.4 - Backdoor Command Execution"}
            ]
        }]
    )
    
    persistence.add_vulnerability(
        name="vsftpd 2.3.4 Backdoor",
        description="Backdoor en vsftpd permite ejecución remota de comandos",
        severity="critical"
    )
    
    print("   ✓ Vulnerabilidad identificada: vsftpd backdoor")
    print("   ✓ Exploit disponible: EDB-17491\n")
    
    # FASE 3: EXPLOITATION
    print("💥 FASE: EXPLOITATION")
    persistence.update_phase("exploitation")
    
    persistence.add_notes(
        "Intentamos exploit de vsftpd pero no funcionó. "
        "Probando Samba 3.0.20 usermap script vulnerability..."
    )
    
    persistence.add_vulnerability(
        name="Samba 3.0.20 - Username Map Script",
        description="CVE-2007-2447 - Command injection via username",
        severity="critical"
    )
    
    persistence.add_credential("root", "N/A", "samba_exploit")
    
    print("   ✓ Explotación exitosa vía Samba")
    print("   ✓ Acceso root obtenido\n")
    
    # FASE 4: POST-EXPLOITATION
    print("🏆 FASE: POST-EXPLOITATION")
    persistence.update_phase("post-exploitation")
    
    persistence.set_flag("user_flag", "e3d0796d002a446c0e622226f42e9672")
    persistence.set_flag("root_flag", "92caac3be140ef409e45721348a4e9df")
    
    print("   ✓ User flag capturada")
    print("   ✓ Root flag capturada\n")
    
    # Finalizar sesión
    persistence.end_session(mark_as_completed=True)
    
    # Mostrar estadísticas
    stats = persistence.get_statistics()
    print("📊 ESTADÍSTICAS FINALES:")
    print(f"   Total de mensajes: {stats['total_messages']}")
    print(f"   Herramientas usadas: {stats['tool_usage_count']}")
    print(f"   Duración: {stats['duration_days']:.2f} días")
    
    # Exportar reporte
    report = persistence.export_report()
    print(f"\n✓ Reporte exportado con {len(report['messages'])} mensajes")


# ============================================================================
# EJEMPLO 3: REANUDAR SESIÓN EXISTENTE
# ============================================================================

def example_resume_session():
    """Ejemplo de cómo reanudar una sesión pausada."""
    
    persistence = AgentPersistence("demo_persistence.db")
    
    # Listar sesiones activas
    active_sessions = persistence.get_active_sessions()
    
    print("📋 SESIONES DISPONIBLES:")
    for i, session in enumerate(active_sessions, 1):
        print(f"{i}. {session['session_name']} - {session['lab_target']}")
        print(f"   Última actividad: {session['last_active']}")
        print(f"   Estado: {session['status']}\n")
    
    if active_sessions:
        # Reanudar la primera sesión
        session_id = active_sessions[0]['session_id']
        persistence.resume_session(session_id)
        
        print(f"✓ Sesión reanudada: {active_sessions[0]['session_name']}")
        
        # Obtener historial
        history = persistence.get_history(max_messages=5)
        print("\n📜 ÚLTIMOS MENSAJES:")
        for msg in history[-5:]:
            role_icon = "👤" if msg['role'] == 'user' else "🤖"
            content_preview = msg['content'][:80] + "..." if len(msg['content']) > 80 else msg['content']
            print(f"{role_icon} {content_preview}")
        
        # Mostrar contexto actual
        print("\n" + "="*60)
        print(persistence.get_context_summary())


# ============================================================================
# EJEMPLO 4: BÚSQUEDA EN HISTORIAL
# ============================================================================

def example_search_history():
    """Ejemplo de búsqueda en el historial de conversaciones."""
    
    persistence = AgentPersistence("demo_persistence.db")
    
    # Buscar menciones de vulnerabilidades
    search_terms = ["exploit", "vulnerability", "nmap", "flag"]
    
    for term in search_terms:
        results = persistence.search(term, limit=3)
        
        if results:
            print(f"\n🔎 Resultados para '{term}': {len(results)} encontrados")
            for result in results[:3]:
                print(f"   📍 {result['session_name']} - {result['lab_environment']}")
                preview = result['content'][:100] + "..." if len(result['content']) > 100 else result['content']
                print(f"      {preview}\n")


# ============================================================================
# EJEMPLO 5: INTEGRACIÓN CON GOOGLE ADK AGENT
# ============================================================================

def example_adk_integration():
    """
    Ejemplo de cómo integrar la persistencia con el agente de Google ADK.
    Este código muestra cómo modificar agent.py para usar persistencia.
    """
    
    # PSEUDOCÓDIGO - No ejecutar directamente
    print("""
# En chat_agent/agent.py:

from google.adk import Agent, LiteLlm
from .database import AgentPersistence

# Inicializar persistencia global
persistence = AgentPersistence("persistence.db")

# Crear agente con contexto persistente
def create_agent_with_persistence(session_id: str = None):
    # Reanudar o crear sesión
    if session_id:
        persistence.resume_session(session_id)
    else:
        session_id = persistence.start_session(
            session_name="New Chat Session"
        )
    
    # Obtener contexto de la sesión
    context = persistence.get_context_summary()
    
    # Añadir contexto al prompt
    enhanced_prompt = f'''
{SYSTEM_PROMPT}

{context}

Mantén este contexto en mente durante la conversación.
'''
    
    # Crear agente
    agent = Agent(
        model=LiteLlm("ollama_chat/qwen3:8b"),
        system_instruction=enhanced_prompt,
        # ... resto de configuración
    )
    
    return agent, session_id

# Hook para guardar mensajes
def on_user_message(message: str):
    persistence.add_user_message(message)

def on_assistant_response(response: str, tool_calls=None, tool_results=None):
    persistence.add_assistant_message(
        content=response,
        tool_calls=tool_calls,
        tool_results=tool_results
    )

# Hook para actualizar contexto cuando se usan herramientas
def on_nmap_scan_complete(target: str, results: dict):
    if 'open_ports' in results:
        persistence.add_ports(results['open_ports'])
    
    if 'services' in results:
        for service in results['services']:
            persistence.add_service(
                port=service['port'],
                service=service['name'],
                version=service.get('version')
            )

def on_exploit_found(exploit_name: str, description: str):
    persistence.add_vulnerability(
        name=exploit_name,
        description=description,
        severity="high"
    )
    """)


# ============================================================================
# EJECUTAR EJEMPLOS
# ============================================================================

if __name__ == "__main__":
    print("="*70)
    print(" SISTEMA DE PERSISTENCIA - EJEMPLOS DE USO")
    print("="*70)
    
    print("\n" + "="*70)
    print(" EJEMPLO 1: SESIÓN BÁSICA")
    print("="*70)
    example_basic_session()
    
    print("\n\n" + "="*70)
    print(" EJEMPLO 2: TRACKING COMPLETO DE LAB")
    print("="*70)
    example_full_lab_tracking()
    
    print("\n\n" + "="*70)
    print(" EJEMPLO 3: REANUDAR SESIÓN")
    print("="*70)
    example_resume_session()
    
    print("\n\n" + "="*70)
    print(" EJEMPLO 4: BÚSQUEDA EN HISTORIAL")
    print("="*70)
    example_search_history()
    
    print("\n\n" + "="*70)
    print(" EJEMPLO 5: INTEGRACIÓN CON GOOGLE ADK")
    print("="*70)
    example_adk_integration()
    
    print("\n" + "="*70)
    print(" EJEMPLOS COMPLETADOS")
    print("="*70)
