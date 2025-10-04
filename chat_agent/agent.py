from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
import os
from dotenv import load_dotenv

from .prompt import get_prompt
from .tools import get_current_time, get_weather

# Cargar variables del archivo .env
load_dotenv()

# Configurar URL de Ollama (priorizar OLLAMA_API_BASE del .env)
ollama_url = os.getenv("OLLAMA_API_BASE") or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

root_agent = Agent(
    name="chat_agent",
    description="The chat agent",
    model=LiteLlm(
        model="ollama_chat/qwen3:8b",
        instruction=get_prompt(),
        tools=[get_weather, get_current_time],  # Sin paréntesis - referencias a funciones
        api_base=ollama_url
    ),
)