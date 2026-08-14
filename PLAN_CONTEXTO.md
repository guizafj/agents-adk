# Plan de Contexto y Persistencia - Proyecto demo-ollama

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

### Fase 2: Contexto Estructurado via Estado + lab_context ✅ COMPLETADA
- Nuevo módulo `Cybersegurity_tutor/lab_memory.py`:
  - **7 tools de registro de hechos** (`record_phase`, `record_port`, `record_finding`, `record_credential`, `record_flag`, `record_notes`, `record_target`) que escriben en el estado persistente de la sesión ADK (`session.state["lab_facts"]`).
  - **`inject_lab_facts`**: `before_model_callback` que inyecta el bloque compacto vía `llm_request.append_instructions()` en cada turno, sin ensuciar el historial de chat.
  - `build_lab_facts_block`: genera texto estructurado (objetivo, plataforma, fase, puertos, hallazgos, credenciales, flags, notas).
- Registradas las tools + callback en `agent.py` (22 tools totales).
- **Verificado end-to-end con gemma4:12b:** el modelo registró hechos (target, environment, phase, port), el estado persistió en SQLite entre 2 invocaciones, y el turno 2 respondió correctamente con los datos inyectados.
- Test unitario del callback: inyección en `system_instruction` funcionando y sin hechos no inyecta nada.

### Fase 3: Compactación por Resumen (Núcleo del Fix) ✅ COMPLETADA
- `agent.py` ahora exporta **`app`** (`google.adk.apps.App`) con `events_compaction_config` — el CLI/web lo detectan y lo prefieren sobre `root_agent`.
- Config: `token_threshold=7000`, `event_retention_size=4`. El `LlmEventSummarizer` se auto-crea por ADK con el modelo del agente.
- Basado en Fase 0 (primer turno ≈ 5800 tokens a num_ctx 8192): deja margen para ~3-4 turnos antes de la primera compactación.
- `summarizer=None` → ADK instancia `LlmEventSummarizer(llm=agent.canonical_model)`.
- **Verificado:** con 3 turnos largos se generaron 6 eventos de compactación con resúmenes fieles del contexto (target, /manager, credenciales por defecto, Struts).
- Env: `COMPACTION_TOKEN_THRESHOLD` / `COMPACTION_RETENTION_SIZE` (opcionales).
- `EventsCompactionConfig` importado de `google.adk.apps._configs` (no exportado públicamente).

### Fase 4: Memoria Recuperable (RAG Ligero) ✅ COMPLETADA
- Nuevo módulo `Cybersegurity_tutor/memory_search.py` con la tool **`search_lab_memory(query, limit)`**:
  - Busca en el historial de eventos ADK persistido (tabla `events` de `sessions.db`).
  - Divide la query en términos (≥2 chars) y exige que el fragmento contenga todos (coincidencia multi-término).
  - Devuelve fragmentos user/assistant por sesión con timestamp, sin cargar la sesión completa.
  - Localiza la BD vía `PERSISTENCE_DB_PATH`, con fallback a `.adk/session.db`.
- Registrada en `agent.py` (23 tools totales).
- **Verificado end-to-end con gemma4:12b:** en una sesión nueva sin el dato en el prompt, el agente llamó a la tool y recuperó `/manager` del historial de Fase 3.

### Fase 5: Afinamiento de Rendimiento y Contexto ✅ COMPLETADA
- Umbral de compactación **derivado de `num_ctx`**: `COMPACTION_TOKEN_THRESHOLD = num_ctx * COMPACTION_THRESHOLD_RATIO` (default 0.85 → 6963 tokens a 8192), anulable con variable absoluta.
- Knobs documentados en `Cybersegurity_tutor/.env.example`: `OLLAMA_NUM_CTX`, `COMPACTION_THRESHOLD_RATIO`, `COMPACTION_RETENTION_SIZE`, `LITELLM_*_TIMEOUT`.
- Sin cambios de parsing extra: `think=False` y `num_ctx` vía `extra_body` ya eran correctos desde el baseline.

### Fase 6: Alineación de Variables y Modelo por Defecto ✅ COMPLETADA

**Problema detectado:** el `.env` local de `Cybersegurity_tutor` definía `PERSISTENCE_DB="/app/data/persistence/sessions.db"`, pero todo el código (`agent.py`, `memory_search.py`, `Analist_cv/agent.py`) lee **`PERSISTENCE_DB_PATH`**. El nombre no llegaba al código → fuera de Docker la persistencia apuntaba a rutas inexistentes (`/app/...`). Además, el `.env` local declaraba `OLLAMA_MODEL="gemma4:latest"` (modelo inexistente en Ollama) y los contenedores usaban `ollama_chat/qwen3.6:35b`; el único modelo realmente descargado en el host era `gemma4:12b`.

**Decisión:** estandarizar todo el proyecto sobre **`PERSISTENCE_DB_PATH`** (único nombre que el código lee) y fijar **`gemma4:12b`** como modelo por defecto en todas las capas (código, Docker, compose, plantillas).

**Cambios:**
- `Cybersegurity_tutor/.env` (gitignored): renombrada `PERSISTENCE_DB`→`PERSISTENCE_DB_PATH` con ruta local absoluta (`.../demo-ollama/data/persistence/sessions.db`); nombres de timeouts corregidos a `LITELLM_REQUEST_TIMEOUT`/`LITELLM_CONNECT_TIMEOUT` (antes `REQUEST_TIMEOUT`, que el código no lee); `OLLAMA_MODEL="ollama_chat/gemma4:12b"`; añadidos `OLLAMA_NUM_CTX`, `COMPACTION_THRESHOLD_RATIO`, `COMPACTION_RETENTION_SIZE`.
- `Cybersegurity_tutor/agent.py:65` — default de `OLLAMA_MODEL` cambiado de `ollama_chat/qwen3.6:35b` a `ollama_chat/gemma4:12b`. Comentarios de `think=` neutralizados (ya no aluden a qwen). Docstring de cabecera actualizado (quitada la referencia al `DatabaseSessionService` eliminado en Fase 1).
- `Dockerfile` / `docker-compose.yml` — `OLLAMA_MODEL=ollama_chat/gemma4:12b` como default en imagen y servicio.
- `Cybersegurity_tutor/.env.example` — añadida `OLLAMA_MODEL` (con `ollama_chat/` y tag `12b`) y comentarios neutrales.
- `AGENTS.md` / `README.md` — actualizados pull de modelo y referencias de persistencia (`PERSISTENCE_DB_PATH`).

**Verificado:** `uv run adk run Cybersegurity_tutor` responde con `gemma4:12b`; `load_dotenv()` resuelve el `.env` local y `PERSISTENCE_DB` en `agent.py` ahora apunta a la BD local de desarrollo.

**Pendiente (documentado, no bloqueante):** `Analist_cv/agent.py`, `pokedex_agent/agent.py` y `Cybersegurity_tutor/database/examples.py` siguen hardcodeando modelos qwen (`ollama_chat/qwen3:8b`, `qwen3.5:latest`) no descargados en el host; alinearlos a gemma queda fuera del alcance de esta tarea.

### Fase 7: Depuración de Sesión No Generada + Suite de Tests ✅ COMPLETADA

**Estado inicial:** tras cerrar la Fase 6 (alineación de variables y modelo gemma4:12b), el contenedor Docker (`tutor:latest`) corría la web, pero **no se generaban sesiones**: `POST /apps/Cybersegurity_tutor/users/user/sessions` devolvía `500 Internal Server Error`. No había suite de tests configurada (AGENTS.md lo señalaba) y el proyecto no tenía `pytest`.

**Proceso de depuración (método):** se trabajó en modo autónomo con `ADK_LOG_LEVEL=DEBUG` (ya activo en `docker-compose.yml` y `Dockerfile`). Se inspeccionaron los logs del contenedor (`docker compose logs adk`), las BD SQLite del host y del volumen, y el código de ADK instalado para confirmar cada causa antes de tocarla.

**Problemas detectados (en orden de aparición en los logs):**

1. **`sqlite:///` relativo en el CMD del Dockerfile** — `--session_service_uri=sqlite:///app/data/persistence/sessions.db` (3 slashes). SQLAlchemy interpreta 3 slashes como **ruta relativa al CWD** (`/app` en el contenedor) → intenta abrir `/app/app/data/persistence/sessions.db`, que no existe → `sqlite3.OperationalError: unable to open database file`.
2. **Esquema híbrido roto en el volumen `tutor_persistence`** — tras arreglar el error anterior, la BD del volumen mezclaba tablas legacy de la antigua capa propia (`sessions` sin columna `app_name`, `messages`, `lab_context`, `user_progress`, ...) con tablas ADK (`app_states`, `user_states`, `events`) → ADK fallaba con `no such column: app_name`.
3. **App name mismatch (pre-existente)** — `root_agent.name="Cybersecurity_Tutor"` (con "e") ≠ nombre del directorio `Cybersegurity_tutor` (sin "e"). ADK emitía el warning `App name mismatch detected` y las sesiones quedaban guardadas bajo dos `app_name` distintos, fragmentando el historial.

**Decisiones tomadas y soluciones:**

1. **Ruta absoluta de la URI de sesión** → `Dockerfile:71`: `sqlite:////app/data/persistence/sessions.db` (4 slashes = absoluta). Se añadió un comentario en el Dockerfile explicando el porqué (evita regresión). Justificación: la doc de ADK (Fase 1) ya usaba 4 slashes en los comandos locales; el CMD del Dockerfile era el único sitio sin corregir.
2. **Regenerar el esquema de la BD** → `docker compose down -v` (borra el volumen `tutor_persistence`) + `docker compose up --build -d`. Decisión consultada y aprobada por el usuario: la BD rota era inservible y el historial legacy no era recuperable para ADK. Tras el reset, ADK crea su esquema limpio (`sessions.app_name`, `events`).
3. **Alinear el nombre del agente al directorio** → `agent.py:113`: `name="Cybersegurity_tutor"`. Justificación: ADK usa el nombre del directorio como `app_name` implícito al cargar el agente desde `agents_dir`; si `root_agent.name` difiere, la web (que lista por directorio) no encuentra las sesiones. Este es el fix de coherencia que el test de Fase 4 ya anticipaba.
4. **Crear suite de tests con pytest** → decisión confirmada por el usuario. Se añadió `pytest` como dev-dependency (`pyproject.toml` → `[dependency-groups].dev`), se configuró `[tool.pytest.ini_options]` (testpaths, pythonpath), y se construyeron 4 archivos de tests + 1 conftest.

**Verificación end-to-end:**
- `curl POST /apps/Cybersegurity_tutor/users/user/sessions` → `200` con `"appName":"Cybersegurity_tutor"`.
- La BD del volumen contiene **solo** tablas ADK (`app_states`, `user_states`, `sessions`, `events`).
- CLI local `uv run adk run Cybersegurity_tutor` responde con gemma4:12b sin warning de mismatch.
- `uv run pytest` → **39 tests, todos en verde**.

**Suite de tests (pytest, nueva):**
- `tests/conftest.py` — fixtures `ToolContext` reales (sobre `InMemorySessionService`), helpers de sesión síncronos, constantes de app_name.
- `tests/test_lab_memory.py` (14 tests) — tools de hechos del lab, `build_lab_facts_block`, `inject_lab_facts`.
- `tests/test_memory_search.py` (9 tests) — `_text_parts`, `_find_db`, `search_lab_memory` sobre BD temporal.
- `tests/test_agent_config.py` (11 tests) — defaults de env, compactación, coherencia de nombres; **el test de nombres detectó el bug de la Fase 7** (fallaba antes del fix).
- `tests/test_flow_session.py` (5 tests) — Runner real con **StubModel** (sin Ollama): creación de sesión, app_name, persistencia de estado entre turnos.
- Comando: `uv run pytest`. `pytest` como dev-dependency.

**Notas de diseño de los tests:**
- El `Runner` de ADK usa el modelo real del agente (LiteLlm → Ollama); para aislar los tests de flujo se sustituye el modelo por `StubModel` (subclase de `BaseLlm` que devuelve una respuesta fija) vía `monkeypatch`.
- Las API de `InMemorySessionService` (`create_session`, `get_session`) son asíncronas; los tests síncronos las envuelven con `asyncio.run`.

---

*Documento generado el 14 de agosto de 2026*
