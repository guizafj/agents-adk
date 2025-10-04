from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm

import os
from dotenv import load_dotenv

from .prompt import get_prompt
from .tools import get_pokemon_info

# Cargar variables del archivo .env
load_dotenv()

# Configurar URL de Ollama (priorizar OLLAMA_API_BASE del .env)
ollama_url = os.getenv("OLLAMA_API_BASE") or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

root_agent = Agent(
    name="pokedex_agent",
    description="A helpful assistant that can answer questions about Pokémon.",
    model=LiteLlm(
        model="ollama_chat/qwen3:8b",  # Corregido: era "wen3:8b"
        instruction=get_prompt(),
        tools=[get_pokemon_info],
        api_base=ollama_url  # Agregado: configuración de API base
    ),
)