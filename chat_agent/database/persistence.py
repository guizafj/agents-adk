"""
Sistema de persistencia para el agente de ciberseguridad.
Maneja la gestión de sesiones, mensajes y contexto de laboratorios.
"""

import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager


class SessionManager:
    """
    Gestor de persistencia para sesiones de pentesting.
    
    Características:
    - Gestión completa de sesiones con contexto de labs
    - Almacenamiento de conversaciones con herramientas
    - Tracking de hallazgos y progreso
    - Búsqueda y recuperación de contexto histórico
    """
    
    def __init__(self, db_path: str = "persistence.db"):
        """
        Inicializa el gestor de sesiones.
        
        Args:
            db_path: Ruta al archivo de base de datos SQLite
        """
        self.db_path = Path(db_path)
        self._initialize_database()
    
    @contextmanager
    def _get_connection(self):
        """Context manager para conexiones a la base de datos."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row  # Para acceder a columnas por nombre
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _initialize_database(self):
        """Inicializa la base de datos con el esquema."""
        schema_path = Path(__file__).parent / "schema.sql"
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Leer y ejecutar el esquema
            if schema_path.exists():
                with open(schema_path, 'r', encoding='utf-8') as f:
                    schema_sql = f.read()
                    cursor.executescript(schema_sql)
            else:
                raise FileNotFoundError(f"Schema file not found: {schema_path}")
    
    # ========================================================================
    # GESTIÓN DE SESIONES
    # ========================================================================
    
    def create_session(
        self,
        user_id: str = "default_user",
        session_name: Optional[str] = None,
        lab_environment: Optional[str] = None,
        lab_target: Optional[str] = None,
        lab_objective: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Crea una nueva sesión de pentesting.
        
        Args:
            user_id: Identificador del usuario
            session_name: Nombre descriptivo (ej: "HTB - Nibbles")
            lab_environment: Plataforma (HTB, TryHackMe, etc.)
            lab_target: IP o nombre del objetivo
            lab_objective: Descripción del objetivo
            metadata: Metadata adicional en formato dict
        
        Returns:
            session_id: ID único de la sesión creada
        """
        session_id = str(uuid.uuid4())
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (
                    session_id, user_id, session_name, lab_environment,
                    lab_target, lab_objective, session_metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                user_id,
                session_name,
                lab_environment,
                lab_target,
                lab_objective,
                json.dumps(metadata) if metadata else None
            ))
            
            # Crear contexto inicial del lab
            cursor.execute("""
                INSERT INTO lab_context (session_id, phase)
                VALUES (?, 'reconnaissance')
            """, (session_id,))
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene información de una sesión.
        
        Args:
            session_id: ID de la sesión
        
        Returns:
            Dict con información de la sesión o None si no existe
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            
            if row:
                session = dict(row)
                if session.get('session_metadata'):
                    session['session_metadata'] = json.loads(session['session_metadata'])
                return session
            return None
    
    def list_sessions(
        self,
        user_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Lista sesiones con filtros opcionales.
        
        Args:
            user_id: Filtrar por usuario
            status: Filtrar por estado (active, completed, archived)
            limit: Número máximo de resultados
        
        Returns:
            Lista de sesiones
        """
        query = "SELECT * FROM sessions WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY last_active DESC LIMIT ?"
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            sessions = []
            for row in cursor.fetchall():
                session = dict(row)
                if session.get('session_metadata'):
                    session['session_metadata'] = json.loads(session['session_metadata'])
                sessions.append(session)
            
            return sessions
    
    def update_session_status(self, session_id: str, status: str):
        """
        Actualiza el estado de una sesión.
        
        Args:
            session_id: ID de la sesión
            status: Nuevo estado (active, paused, completed, archived)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sessions 
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE session_id = ?
            """, (status, session_id))
    
    def archive_session(self, session_id: str):
        """Archiva una sesión."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sessions 
                SET is_archived = 1, status = 'archived', updated_at = CURRENT_TIMESTAMP
                WHERE session_id = ?
            """, (session_id,))
    
    def delete_session(self, session_id: str):
        """
        Elimina una sesión y todos sus datos relacionados.
        CASCADE borrará mensajes, contexto, etc.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    
    # ========================================================================
    # GESTIÓN DE MENSAJES
    # ========================================================================
    
    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        tool_calls: Optional[List[Dict]] = None,
        tool_results: Optional[List[Dict]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Añade un mensaje a la sesión.
        
        Args:
            session_id: ID de la sesión
            role: Rol del mensaje (user, assistant, system, tool)
            content: Contenido del mensaje
            tool_calls: Lista de herramientas llamadas
            tool_results: Resultados de las herramientas
            metadata: Metadata adicional
        
        Returns:
            message_id: ID del mensaje creado
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO messages (
                    session_id, role, content, tool_calls, tool_results, message_metadata
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                role,
                content,
                json.dumps(tool_calls) if tool_calls else None,
                json.dumps(tool_results) if tool_results else None,
                json.dumps(metadata) if metadata else None
            ))
            
            # Actualizar last_active de la sesión
            cursor.execute("""
                UPDATE sessions 
                SET last_active = CURRENT_TIMESTAMP
                WHERE session_id = ?
            """, (session_id,))
            
            return cursor.lastrowid
    
    def get_messages(
        self,
        session_id: str,
        limit: Optional[int] = None,
        role: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Obtiene mensajes de una sesión.
        
        Args:
            session_id: ID de la sesión
            limit: Número máximo de mensajes (None = todos)
            role: Filtrar por rol
        
        Returns:
            Lista de mensajes ordenados por timestamp
        """
        query = "SELECT * FROM messages WHERE session_id = ?"
        params = [session_id]
        
        if role:
            query += " AND role = ?"
            params.append(role)
        
        query += " ORDER BY timestamp ASC"
        
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            messages = []
            for row in cursor.fetchall():
                message = dict(row)
                # Deserializar JSON
                if message.get('tool_calls'):
                    message['tool_calls'] = json.loads(message['tool_calls'])
                if message.get('tool_results'):
                    message['tool_results'] = json.loads(message['tool_results'])
                if message.get('message_metadata'):
                    message['message_metadata'] = json.loads(message['message_metadata'])
                messages.append(message)
            
            return messages
    
    def get_conversation_history(
        self,
        session_id: str,
        max_messages: int = 20
    ) -> List[Dict[str, str]]:
        """
        Obtiene el historial de conversación en formato simplificado para el agente.
        
        Args:
            session_id: ID de la sesión
            max_messages: Número máximo de mensajes recientes
        
        Returns:
            Lista de mensajes en formato {role, content}
        """
        messages = self.get_messages(session_id, limit=max_messages)
        return [
            {"role": msg["role"], "content": msg["content"]}
            for msg in messages
        ]
    
    # ========================================================================
    # GESTIÓN DE CONTEXTO DE LAB
    # ========================================================================
    
    def update_lab_context(
        self,
        session_id: str,
        phase: Optional[str] = None,
        findings: Optional[List[Dict]] = None,
        open_ports: Optional[List[int]] = None,
        services: Optional[List[Dict]] = None,
        vulnerabilities: Optional[List[Dict]] = None,
        credentials: Optional[List[Dict]] = None,
        flags: Optional[Dict] = None,
        notes: Optional[str] = None
    ):
        """
        Actualiza el contexto del laboratorio.
        
        Args:
            session_id: ID de la sesión
            phase: Fase actual (reconnaissance, enumeration, exploitation, post-exploitation)
            findings: Lista de hallazgos
            open_ports: Lista de puertos abiertos
            services: Servicios identificados
            vulnerabilities: Vulnerabilidades encontradas
            credentials: Credenciales obtenidas
            flags: Flags capturadas {user_flag, root_flag, etc.}
            notes: Notas adicionales
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Obtener contexto actual
            cursor.execute("""
                SELECT * FROM lab_context 
                WHERE session_id = ? 
                ORDER BY context_id DESC 
                LIMIT 1
            """, (session_id,))
            
            current_context = cursor.fetchone()
            
            if current_context:
                # Actualizar contexto existente
                update_fields = []
                params = []
                
                if phase is not None:
                    update_fields.append("phase = ?")
                    params.append(phase)
                
                if findings is not None:
                    update_fields.append("findings = ?")
                    params.append(json.dumps(findings))
                
                if open_ports is not None:
                    update_fields.append("open_ports = ?")
                    params.append(json.dumps(open_ports))
                
                if services is not None:
                    update_fields.append("services = ?")
                    params.append(json.dumps(services))
                
                if vulnerabilities is not None:
                    update_fields.append("vulnerabilities = ?")
                    params.append(json.dumps(vulnerabilities))
                
                if credentials is not None:
                    update_fields.append("credentials = ?")
                    params.append(json.dumps(credentials))
                
                if flags is not None:
                    update_fields.append("flags = ?")
                    params.append(json.dumps(flags))
                
                if notes is not None:
                    update_fields.append("notes = ?")
                    params.append(notes)
                
                if update_fields:
                    update_fields.append("updated_at = CURRENT_TIMESTAMP")
                    params.append(current_context['context_id'])
                    
                    query = f"UPDATE lab_context SET {', '.join(update_fields)} WHERE context_id = ?"
                    cursor.execute(query, params)
    
    def get_lab_context(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene el contexto actual del laboratorio.
        
        Args:
            session_id: ID de la sesión
        
        Returns:
            Dict con el contexto o None si no existe
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM lab_context 
                WHERE session_id = ? 
                ORDER BY context_id DESC 
                LIMIT 1
            """, (session_id,))
            
            row = cursor.fetchone()
            if row:
                context = dict(row)
                # Deserializar campos JSON
                json_fields = ['findings', 'open_ports', 'services', 'vulnerabilities', 'credentials', 'flags']
                for field in json_fields:
                    if context.get(field):
                        context[field] = json.loads(context[field])
                return context
            return None
    
    # ========================================================================
    # BÚSQUEDA Y ANÁLISIS
    # ========================================================================
    
    def search_messages(
        self,
        search_term: str,
        user_id: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Busca mensajes que contengan un término específico.
        
        Args:
            search_term: Término a buscar en el contenido
            user_id: Filtrar por usuario
            limit: Número máximo de resultados
        
        Returns:
            Lista de mensajes que coinciden
        """
        query = """
            SELECT m.*, s.session_name, s.lab_environment, s.lab_target
            FROM messages m
            JOIN sessions s ON m.session_id = s.session_id
            WHERE m.content LIKE ?
        """
        params = [f"%{search_term}%"]
        
        if user_id:
            query += " AND s.user_id = ?"
            params.append(user_id)
        
        query += " ORDER BY m.timestamp DESC LIMIT ?"
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                results.append(dict(row))
            
            return results
    
    def get_session_statistics(self, session_id: str) -> Dict[str, Any]:
        """
        Obtiene estadísticas de una sesión.
        
        Args:
            session_id: ID de la sesión
        
        Returns:
            Dict con estadísticas
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Contar mensajes por rol
            cursor.execute("""
                SELECT role, COUNT(*) as count
                FROM messages
                WHERE session_id = ?
                GROUP BY role
            """, (session_id,))
            
            message_counts = {row['role']: row['count'] for row in cursor.fetchall()}
            
            # Contar herramientas usadas
            cursor.execute("""
                SELECT COUNT(*) as tool_usage_count
                FROM messages
                WHERE session_id = ? AND tool_calls IS NOT NULL
            """, (session_id,))
            
            tool_usage = cursor.fetchone()['tool_usage_count']
            
            # Obtener duración de la sesión
            cursor.execute("""
                SELECT 
                    created_at,
                    last_active,
                    julianday(last_active) - julianday(created_at) as duration_days
                FROM sessions
                WHERE session_id = ?
            """, (session_id,))
            
            session_info = dict(cursor.fetchone())
            
            return {
                "message_counts": message_counts,
                "total_messages": sum(message_counts.values()),
                "tool_usage_count": tool_usage,
                "duration_days": session_info['duration_days'],
                "created_at": session_info['created_at'],
                "last_active": session_info['last_active']
            }
    
    # ========================================================================
    # INTEGRACIÓN CON GOOGLE ADK
    # ========================================================================
    
    def get_context_for_agent(self, session_id: str) -> str:
        """
        Genera un resumen del contexto para incluir en el prompt del agente.
        
        Args:
            session_id: ID de la sesión
        
        Returns:
            String con contexto formateado
        """
        session = self.get_session(session_id)
        lab_context = self.get_lab_context(session_id)
        
        if not session:
            return "Nueva sesión sin contexto previo."
        
        context_parts = [
            f"=== SESIÓN ACTUAL: {session['session_name'] or session_id} ===\n"
        ]
        
        if session.get('lab_environment'):
            context_parts.append(f"Plataforma: {session['lab_environment']}")
        
        if session.get('lab_target'):
            context_parts.append(f"Objetivo: {session['lab_target']}")
        
        if session.get('lab_objective'):
            context_parts.append(f"Meta: {session['lab_objective']}")
        
        if lab_context:
            context_parts.append(f"\nFase actual: {lab_context.get('phase', 'reconnaissance')}")
            
            if lab_context.get('open_ports'):
                ports = lab_context['open_ports']
                context_parts.append(f"Puertos abiertos: {', '.join(map(str, ports))}")
            
            if lab_context.get('services'):
                services_list = [f"{s.get('port', '?')}/{s.get('service', '?')}" for s in lab_context['services'][:5]]
                context_parts.append(f"Servicios: {', '.join(services_list)}")
            
            if lab_context.get('vulnerabilities'):
                vuln_count = len(lab_context['vulnerabilities'])
                context_parts.append(f"Vulnerabilidades encontradas: {vuln_count}")
            
            if lab_context.get('flags'):
                flags = lab_context['flags']
                if flags.get('user_flag'):
                    context_parts.append("✓ User flag capturada")
                if flags.get('root_flag'):
                    context_parts.append("✓ Root flag capturada")
        
        return "\n".join(context_parts)
    
    def export_session_report(self, session_id: str) -> Dict[str, Any]:
        """
        Exporta un reporte completo de la sesión.
        
        Args:
            session_id: ID de la sesión
        
        Returns:
            Dict con toda la información de la sesión
        """
        session = self.get_session(session_id)
        messages = self.get_messages(session_id)
        lab_context = self.get_lab_context(session_id)
        statistics = self.get_session_statistics(session_id)
        
        return {
            "session": session,
            "messages": messages,
            "lab_context": lab_context,
            "statistics": statistics,
            "exported_at": datetime.now().isoformat()
        }
