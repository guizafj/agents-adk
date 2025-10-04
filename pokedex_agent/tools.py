import requests

def get_pokemon_info(pokemon_name: str) -> dict:
    """Retrieves information about a specific Pokémon.
    
    Args:
        pokemon_name (str): The name of the Pokémon in lowercase to retrieve information about.
    
    Returns:
        dict: status and result or error msg.
    """
    print(f"Getting information for {pokemon_name}")

    url = f"https://pokeapi.co/api/v2/pokemon/{pokemon_name.lower()}"
    response = requests.get(url)
    if response.status_code == 200:
        print(response.json())
        return {
            "status": "success",
            "result": response.json(),
        }
    else:
        return {
            "status": "error",
            "error_message": f"Failed to retrieve information for '{pokemon_name}'.",
        }