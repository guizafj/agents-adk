# Directorio de Persistencia

Este directorio contiene las bases de datos SQLite que persisten entre reconstrucciones del contenedor Docker.

## 📁 Estructura

```
data/
└── persistence/
    ├── .gitkeep              # Mantiene el directorio en Git
    ├── sessions.db           # Base de datos principal (creada automáticamente)
    ├── sessions.db-journal   # Archivos temporales de SQLite
    ├── sessions.db-wal       # Write-Ahead Log de SQLite
    └── sessions.db-shm       # Shared Memory de SQLite
```

## 🐳 Configuración en Docker

El directorio está montado como volumen en `docker-compose.yml`:

```yaml
volumes:
  - ./data/persistence:/app/data/persistence
```

**Ventajas:**
- ✅ Los datos persisten cuando el contenedor se detiene
- ✅ Los datos persisten cuando se reconstruye la imagen
- ✅ Accesibles desde el host en `./data/persistence/`
- ✅ Backups fáciles (copiar el directorio)

## 💾 Backup y Restauración

### Hacer Backup
```bash
# Backup simple
cp data/persistence/sessions.db backups/sessions_$(date +%Y%m%d).db

# Backup completo comprimido
tar -czf backups/persistence_$(date +%Y%m%d).tar.gz data/persistence/
```

### Restaurar Backup
```bash
docker compose down
cp backups/sessions_20251004.db data/persistence/sessions.db
docker compose up adk -d
```

## 🔍 Verificación

```bash
# Ver tamaño de la base de datos
ls -lh data/persistence/sessions.db

# Contar sesiones (requiere Python)
docker compose exec adk python -c "
from chat_agent.database.persistence import SessionManager
mgr = SessionManager('/app/data/persistence/sessions.db')
sessions = mgr.list_sessions()
print(f'Total sesiones: {len(sessions)}')
"
```

## 🧹 Limpieza

Para empezar desde cero (eliminar todas las sesiones):

```bash
docker compose down
rm -f data/persistence/sessions.db*
docker compose up adk -d
```

---

⚠️ **Los archivos `.db-*` son temporales de SQLite y no deben editarse manualmente.**

⚠️ **No commitear archivos `.db` a Git** (ya están en `.gitignore`).
