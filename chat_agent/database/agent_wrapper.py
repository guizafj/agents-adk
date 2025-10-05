"""
Wrapper para integrar el sistema de persistencia con Google ADK.
Permite que el agente mantenga y recupere contexto automáticamente.
"""

from typing import Optional, List, Dict, Any
from .persistence import SessionManager


class AgentPersistence:
    """
    Wrapper de alto nivel para integración con Google ADK.
    Simplifica el uso de persistencia en el agente.
    """
    
    def __init__(self, db_path: str = "persistence.db"):
        """
        Inicializa el sistema de persistencia.
        
        Args:
            db_path: Ruta a la base de datos
        """
        self.manager = SessionManager(db_path)
        self.current_session_id: Optional[str] = None
    
    # ========================================================================
    # GESTIÓN SIMPLIFICADA DE SESIONES
    # ========================================================================
    
    def start_session(
        self,
        session_name: Optional[str] = None,
        lab_environment: Optional[str] = None,
        lab_target: Optional[str] = None,
        lab_objective: Optional[str] = None
    ) -> str:
        """
        Inicia una nueva sesión y la establece como actual.
        
        Args:
            session_name: Nombre descriptivo
            lab_environment: Plataforma (HTB, TryHackMe, etc.)
            lab_target: IP o nombre del objetivo
            lab_objective: Descripción del objetivo
        
        Returns:
            session_id: ID de la sesión creada
        """
        session_id = self.manager.create_session(
            session_name=session_name,
            lab_environment=lab_environment,
            lab_target=lab_target,
            lab_objective=lab_objective
        )
        self.current_session_id = session_id
        return session_id
    
    def resume_session(self, session_id: str):
        """
        Reanuda una sesión existente.
        
        Args:
            session_id: ID de la sesión a reanudar
        """
        session = self.manager.get_session(session_id)
        if session:
            self.current_session_id = session_id
            self.manager.update_session_status(session_id, 'active')
        else:
            raise ValueError(f"Session {session_id} not found")
    
    def end_session(self, mark_as_completed: bool = False):
        """
        Finaliza la sesión actual.
        
        Args:
            mark_as_completed: Si es True, marca como 'completed', sino como 'paused'
        """
        if self.current_session_id:
            status = 'completed' if mark_as_completed else 'paused'
            self.manager.update_session_status(self.current_session_id, status)
            self.current_session_id = None
    
    def get_active_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Lista sesiones activas.
        
        Returns:
            Lista de sesiones activas
        """
        return self.manager.list_sessions(status='active', limit=limit)
    
    # ========================================================================
    # GESTIÓN DE MENSAJES
    # ========================================================================
    
    def add_user_message(self, content: str) -> int:
        """
        Añade un mensaje del usuario.
        
        Args:
            content: Contenido del mensaje
        
        Returns:
            message_id
        """
        if not self.current_session_id:
            raise ValueError("No active session. Call start_session() first.")
        
        return self.manager.add_message(
            session_id=self.current_session_id,
            role="user",
            content=content
        )
    
    def add_assistant_message(
        self,
        content: str,
        tool_calls: Optional[List[Dict]] = None,
        tool_results: Optional[List[Dict]] = None
    ) -> int:
        """
        Añade un mensaje del asistente.
        
        Args:
            content: Contenido de la respuesta
            tool_calls: Herramientas que se llamaron
            tool_results: Resultados de las herramientas
        
        Returns:
            message_id
        """
        if not self.current_session_id:
            raise ValueError("No active session. Call start_session() first.")
        
        return self.manager.add_message(
            session_id=self.current_session_id,
            role="assistant",
            content=content,
            tool_calls=tool_calls,
            tool_results=tool_results
        )
    
    def get_history(self, max_messages: int = 20) -> List[Dict[str, str]]:
        """
        Obtiene el historial de conversación de la sesión actual.
        
        Args:
            max_messages: Número máximo de mensajes
        
        Returns:
            Lista de mensajes en formato {role, content}
        """
        if not self.current_session_id:
            return []
        
        return self.manager.get_conversation_history(
            session_id=self.current_session_id,
            max_messages=max_messages
        )
    
    # ========================================================================
    # CONTEXTO DEL LAB
    # ========================================================================
    
    def update_phase(self, phase: str):
        """
        Actualiza la fase actual del pentesting.
        
        Args:
            phase: reconnaissance | enumeration | exploitation | post-exploitation
        """
        if not self.current_session_id:
            return
        
        self.manager.update_lab_context(
            session_id=self.current_session_id,
            phase=phase
        )
    
    def add_finding(
        self,
        finding_type: str,
        description: str,
        severity: Optional[str] = None
    ):
        """
        Añade un hallazgo al contexto.
        
        Args:
            finding_type: Tipo (service, vulnerability, credential, etc.)
            description: Descripción del hallazgo
            severity: info | low | medium | high | critical
        """
        if not self.current_session_id:
            return
        
        context = self.manager.get_lab_context(self.current_session_id)
        findings = context.get('findings') if context else None
        if findings is None:
            findings = []
        
        findings.append({
            "type": finding_type,
            "description": description,
            "severity": severity,
            "timestamp": None  # Se añadirá automáticamente
        })
        
        self.manager.update_lab_context(
            session_id=self.current_session_id,
            findings=findings
        )
    
    def add_ports(self, ports: List[int]):
        """
        Añade puertos abiertos descubiertos.
        
        Args:
            ports: Lista de números de puerto
        """
        if not self.current_session_id:
            return
        
        context = self.manager.get_lab_context(self.current_session_id)
        existing_ports = set(context.get('open_ports', []) if context and context.get('open_ports') else [])
        existing_ports.update(ports)
        
        self.manager.update_lab_context(
            session_id=self.current_session_id,
            open_ports=sorted(list(existing_ports))
        )
    
    def add_service(self, port: int, service: str, version: Optional[str] = None):
        """
        Añade información de un servicio descubierto.
        
        Args:
            port: Número de puerto
            service: Nombre del servicio
            version: Versión del servicio
        """
        if not self.current_session_id:
            return
        
        context = self.manager.get_lab_context(self.current_session_id)
        services = context.get('services') if context else None
        if services is None:
            services = []
        
        # Actualizar si ya existe o añadir nuevo
        service_info = {"port": port, "service": service, "version": version}
        
        # Buscar si ya existe
        for i, s in enumerate(services):
            if s.get('port') == port:
                services[i] = service_info
                break
        else:
            services.append(service_info)
        
        self.manager.update_lab_context(
            session_id=self.current_session_id,
            services=services
        )
    
    def add_vulnerability(self, name: str, description: str, severity: str):
        """
        Añade una vulnerabilidad encontrada.
        
        Args:
            name: Nombre de la vulnerabilidad
            description: Descripción
            severity: info | low | medium | high | critical
        """
        if not self.current_session_id:
            return
        
        context = self.manager.get_lab_context(self.current_session_id)
        vulns = context.get('vulnerabilities') if context else None
        if vulns is None:
            vulns = []
        
        vulns.append({
            "name": name,
            "description": description,
            "severity": severity
        })
        
        self.manager.update_lab_context(
            session_id=self.current_session_id,
            vulnerabilities=vulns
        )
    
    def add_credential(self, username: str, password: str, service: Optional[str] = None):
        """
        Añade credenciales obtenidas.
        
        Args:
            username: Usuario
            password: Contraseña
            service: Servicio asociado
        """
        if not self.current_session_id:
            return
        
        context = self.manager.get_lab_context(self.current_session_id)
        creds = context.get('credentials') if context else None
        if creds is None:
            creds = []
        
        creds.append({
            "username": username,
            "password": password,
            "service": service
        })
        
        self.manager.update_lab_context(
            session_id=self.current_session_id,
            credentials=creds
        )
    
    def set_flag(self, flag_type: str, flag_value: str):
        """
        Guarda una flag capturada.
        
        Args:
            flag_type: user_flag | root_flag | etc.
            flag_value: Valor de la flag
        """
        if not self.current_session_id:
            return
        
        context = self.manager.get_lab_context(self.current_session_id)
        flags = context.get('flags') if context else None
        if flags is None:
            flags = {}
        
        flags[flag_type] = flag_value
        
        self.manager.update_lab_context(
            session_id=self.current_session_id,
            flags=flags
        )
    
    def add_notes(self, notes: str):
        """
        Añade notas al contexto del lab.
        
        Args:
            notes: Texto de las notas
        """
        if not self.current_session_id:
            return
        
        context = self.manager.get_lab_context(self.current_session_id)
        existing_notes = context.get('notes') if context else None
        if existing_notes is None:
            existing_notes = ''
        
        new_notes = f"{existing_notes}\n\n{notes}".strip()
        
        self.manager.update_lab_context(
            session_id=self.current_session_id,
            notes=new_notes
        )
    
    # ========================================================================
    # RECUPERACIÓN DE CONTEXTO
    # ========================================================================
    
    def get_context_summary(self) -> str:
        """
        Obtiene un resumen del contexto para el agente.
        
        Returns:
            String con el resumen del contexto
        """
        if not self.current_session_id:
            return "No hay sesión activa."
        
        return self.manager.get_context_for_agent(self.current_session_id)
    
    def get_full_context(self) -> Dict[str, Any]:
        """
        Obtiene el contexto completo de la sesión actual.
        
        Returns:
            Dict con toda la información
        """
        if not self.current_session_id:
            return {}
        
        session = self.manager.get_session(self.current_session_id)
        lab_context = self.manager.get_lab_context(self.current_session_id)
        
        return {
            "session": session,
            "lab_context": lab_context
        }
    
    # ========================================================================
    # UTILIDADES
    # ========================================================================
    
    def search(self, search_term: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Busca en el historial de conversaciones.
        
        Args:
            search_term: Término a buscar
            limit: Número máximo de resultados
        
        Returns:
            Lista de mensajes que coinciden
        """
        return self.manager.search_messages(search_term, limit=limit)
    
    def get_statistics(self) -> Optional[Dict[str, Any]]:
        """
        Obtiene estadísticas de la sesión actual.
        
        Returns:
            Dict con estadísticas o None si no hay sesión activa
        """
        if not self.current_session_id:
            return None
        
        return self.manager.get_session_statistics(self.current_session_id)
    
    def export_report(self) -> Optional[Dict[str, Any]]:
        """
        Exporta un reporte completo de la sesión actual.
        
        Returns:
            Dict con el reporte completo
        """
        if not self.current_session_id:
            return None
        
        return self.manager.export_session_report(self.current_session_id)
