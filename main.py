"""Demo Ollama + Google ADK.

Punto de entrada principal usando Google ADK CLI.
"""


def main():
    """Función de entrada para ejecutar pruebas del codigo."""
    print("🚀 Para ejecutar el servidor web:")
    print("   adk web chat_agent/agent.py")
    print()
    print("📡 Para ejecutar CLI interactivo:")
    print("   adk run chat_agent/agent.py")
    print()
    print("🔧 Para servir API REST:")
    print("   adk api_server chat_agent/agent.py")


if __name__ == "__main__":
    main()
