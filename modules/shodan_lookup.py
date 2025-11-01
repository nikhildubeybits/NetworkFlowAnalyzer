# modules/shodan_lookup.py
import shodan
import os

def get_shodan_info(ip_address):
    """
    Looks up an IP address using the Shodan API.
    
    :param ip_address: The IP address to look up.
    :return: A dictionary with Shodan information or an error message.
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"error": "Shodan API key not configured in .env file."}

    api = shodan.Shodan(api_key)

    try:
        host_info = api.host(ip_address)
        # We can return the whole dictionary or select specific fields
        return {
            "ip": host_info.get('ip_str'),
            "organization": host_info.get('org', 'N/A'),
            "os": host_info.get('os', 'N/A'),
            "ports": host_info.get('ports', []),
            "last_update": host_info.get('last_update', 'N/A')
        }
    except shodan.APIError as e:
        return {"error": f"Shodan API error: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}