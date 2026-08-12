# Plan de Contexto y Persistencia - Proyecto demo-ollam

## Diagnóstico Actual
Existen dos sistemas de persistencia coexistentes sin gestión de contexto activa en el CLI principal:
1. **Capa Propia (Cybersegurity_tutor/database/)**: Sesión rica pero mayormente ignorada por el motor de ejecución del CLI.
2. **Capa ADK**: Lógica funcional de redimensionamiento fallida porque no se usa la ruta correcta en Docker y carece de compactación de eventos, causando pérdida de contexto al superar los 8192 tokens.

## Plan de Acciones (Fases)

### Fase 0: Baseline y Verificación ✅ COMPLETADA
- **Medidas (CLI, gemma4:12b, num_ctx=8192):**
  - Prompt de sistema: `11669` chars ≈ **2917 tokens**.
  - Esquemas de 15 tools + instrucción → prompt total de **5802 tokens** en el **primer turno** (~71% de la ventana).
  - Output assistant: `1429` chars ≈ **357 tokens**.
  - Input user: `151` chars ≈ **37 tokens**.
  - Eventos ADK por invocación: 2 (1 user + 1 assistant) en 1 turno → crecimiento ~437 tokens/turno.
  - **Conclusión: solo caben ~5 turnos antes de alcanzar los 8192 tokens.** La compactación es obligatoria.
- `ADK_LOG_LEVEL=DEBUG` activado en `.env.example`, `Dockerfile`, `docker-compose.yml`, `README.md`.
- **Persistencia confirmada en runtime:** el CLI de ADK crea `Cybersegurity_tutor/.adk/session.db` (tablas `sessions`/`events`) con 2 sesiones y 4 eventos.
- **Hallazgo:** el `DatabaseSessionService` definido en `agent.py` (línea 89) **nunca se pasa al `Agent`** → el CLI lo ignora y usa su propio `local_storage.py`. La capa propia (`data/persistence/sessions.db`) sí guarda mensajes, pero solo si se usa `AgentPersistence` explícitamente.
- **Dependencia faltante:** `sqlalchemy` (extra `google-adk[db]`) no estaba declarada → añadida con `uv add sqlalchemy`.

### Fase 1: Unificar Persistencia en ADK ✅ COMPLETADA
- **`DatabaseSessionService` muerto eliminado** de `agent.py`: en ADK 2.x el servicio de sesión se inyecta en el `Runner`, no en el `Agent`. El CLI/web lo leen de `--session_service_uri`.
- **Vía oficial confirmada:** `--session_service_uri="sqlite:////<path>"` (4 slashes = ruta absoluta).
- **Corrección Docker:** el `CMD` del `Dockerfile` ahora usa `--session_service_uri=sqlite:///app/data/persistence/sessions.db` → la historia se guarda en el volumen nombrado `tutor_persistence` y sobrevive a rebuilds.
- `.adk/` añadido a `.gitignore` (el CLI sin `--session_service_uri` crea `.adk/session.db` por agente — evita commitearlo).
- **Verificado:** `adk run --session_service_uri=...` persiste 1 sesión + 2 eventos en la BD global. El `.adk/session.db` previo (residuo sin la flag) queda obsoleto.
- **Dependencia:** `sqlalchemy` ahora declarada en `pyproject.toml` (extra `google-adk[db]`).

### Fase 2: Contexto Estructurado via Estado + lab_context
- Decouplear "hechos del lab" del historial de chat usando un bloque compacto inyectado en cada turno.

### Fase 3: Compactación por Resumen (Núcleo del Fix)
- Implementar `EventsCompactionConfig` y `LlmEventSummarizer`.
- Asegurar que el resumen se persista correctamente.

### Fase 4: Memoria Recuperable (RAG Ligero)
- Implementar búsqueda sobre la capa propia para detalles antiguos a demanda.

### Fase 5: Afinamiento de Rendimiento y Contexto
- Ajuste fino de `num_ctx`, parseo de outputs y balances entre fidelidad y velocidad.

---
*Documento generado el [Fecha actual]*
