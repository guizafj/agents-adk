-- ============================================================================
-- ESQUEMA DE BASE DE DATOS - AGENTE DE CIBERSEGURIDAD CON PERSISTENCIA
-- ============================================================================
-- Versión: 2.0 (Mejorado)
-- Base de datos: SQLite
-- Propósito: Persistencia completa de sesiones, conversaciones y contexto de pentesting
-- ============================================================================

-- Tabla de sesiones de usuario
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT 'default_user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_name TEXT,  -- Nombre descriptivo (ej: "HTB - Nibbles")
    lab_environment TEXT,  -- TryHackMe, HTB, CTF, Local, etc.
    lab_target TEXT,  -- IP o nombre de la máquina objetivo
    lab_objective TEXT,  -- Objetivo del laboratorio
    status TEXT DEFAULT 'active',  -- active, paused, completed, archived
    session_metadata TEXT,  -- JSON con metadata adicional
    is_archived BOOLEAN DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices para sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_active ON sessions(last_active);

-- Tabla de mensajes de conversación
CREATE TABLE IF NOT EXISTS messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,  -- 'user', 'assistant', 'system', 'tool'
    content TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tool_calls TEXT,  -- JSON con las herramientas llamadas
    tool_results TEXT,  -- JSON con resultados de herramientas
    message_metadata TEXT,  -- JSON con metadata adicional
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Índices para messages
CREATE INDEX IF NOT EXISTS idx_messages_session_id ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_role ON messages(role);

-- Tabla de contexto de laboratorio
CREATE TABLE IF NOT EXISTS lab_context (
    context_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    phase TEXT,  -- 'reconnaissance', 'enumeration', 'exploitation', 'post-exploitation'
    findings TEXT,  -- Hallazgos importantes (JSON)
    open_ports TEXT,  -- Puertos descubiertos (JSON)
    services TEXT,  -- Servicios identificados (JSON)
    vulnerabilities TEXT,  -- Vulnerabilidades encontradas (JSON)
    credentials TEXT,  -- Credenciales obtenidas (JSON)
    flags TEXT,  -- Flags capturadas (JSON)
    notes TEXT,  -- Notas adicionales
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Índices para lab_context
CREATE INDEX IF NOT EXISTS idx_lab_context_session_id ON lab_context(session_id);
CREATE INDEX IF NOT EXISTS idx_lab_context_phase ON lab_context(phase);

-- Tabla de progreso del estudiante
CREATE TABLE IF NOT EXISTS user_progress (
    progress_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    skill_area TEXT,  -- 'nmap', 'web-enum', 'privilege-escalation', etc.
    activity_type TEXT,  -- 'tool-usage', 'vulnerability-found', 'flag-captured'
    activity_details TEXT,  -- JSON con detalles
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Tabla de herramientas ejecutadas
CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    tool_params TEXT,  -- JSON con parámetros
    tool_result TEXT,  -- JSON con resultado
    execution_time REAL,  -- Tiempo de ejecución en segundos
    status TEXT,  -- 'success', 'error', 'timeout'
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES messages(message_id) ON DELETE CASCADE
);

-- Tabla de recursos y referencias
CREATE TABLE IF NOT EXISTS resources (
    resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    resource_type TEXT,  -- 'cheatsheet', 'exploit', 'documentation', 'screenshot'
    resource_name TEXT,
    resource_content TEXT,  -- Contenido o ruta al archivo
    tags TEXT,  -- Tags para búsqueda (JSON)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- ============================================================================
-- ÍNDICES PARA MEJORAR RENDIMIENTO
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(last_active);
CREATE INDEX IF NOT EXISTS idx_lab_context_session ON lab_context(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_resources_session ON resources(session_id);
CREATE INDEX IF NOT EXISTS idx_user_progress_user ON user_progress(user_id);

-- ============================================================================
-- VISTAS ÚTILES
-- ============================================================================

-- Vista de sesiones recientes con resumen
CREATE VIEW IF NOT EXISTS recent_sessions AS
SELECT 
    s.session_id,
    s.user_id,
    s.session_name,
    s.lab_environment,
    s.lab_target,
    s.created_at,
    s.last_active,
    COUNT(DISTINCT m.message_id) as message_count,
    COUNT(DISTINCT te.execution_id) as tool_executions_count
FROM sessions s
LEFT JOIN messages m ON s.session_id = m.session_id
LEFT JOIN tool_executions te ON s.session_id = te.session_id
WHERE s.is_archived = 0
GROUP BY s.session_id
ORDER BY s.last_active DESC;

-- Vista de estadísticas de usuario
CREATE VIEW IF NOT EXISTS user_stats AS
SELECT 
    user_id,
    COUNT(DISTINCT session_id) as total_sessions,
    COUNT(DISTINCT CASE WHEN lab_environment = 'HTB' THEN session_id END) as htb_sessions,
    COUNT(DISTINCT CASE WHEN lab_environment = 'TryHackMe' THEN session_id END) as thm_sessions,
    COUNT(*) as total_activities,
    MAX(timestamp) as last_activity
FROM user_progress
GROUP BY user_id;
