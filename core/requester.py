import requests

HEADERS = {
    "User-Agent": "ViperScan/1.0"
}

def get_page(url):
    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=20
        )

        return {
            "url": url,
            "status_code": response.status_code,
            "content": response.text
        }

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return None