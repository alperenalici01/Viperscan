import os
import requests
from urllib.parse import urljoin

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}"
]


def load_payloads(path=None):
    path = path or os.path.join("payloads", "ssti.txt")
    try:
        with open(path, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        return SSTI_PAYLOADS


def build_form_data(inputs, payload):
    data = {}
    for input_field in inputs:
        name = input_field.get("name")
        if name:
            data[name] = payload
    return data


def test_ssti(url, forms):
    payloads = load_payloads()
    vulnerabilities = []

    for form in forms:
        action = form["action"]
        method = form["method"]
        target_url = urljoin(url, action)

        print(f"\n[+] Testing SSTI -> {target_url}")

        for payload in payloads:
            data = build_form_data(form["inputs"], payload)

            if not data:
                print("[WARN] Form has no named inputs; skipping SSTI payloads.")
                break

            print(f"[PAYLOAD] {payload}")

            try:
                if method == "post":
                    response = requests.post(target_url, data=data, timeout=10)
                else:
                    response = requests.get(target_url, params=data, timeout=10)

                if "49" in response.text:
                    print(f"[!!!] Possible SSTI Found!\n")
                    vulnerabilities.append({
                        "type": "SSTI",
                        "url": target_url,
                        "payload": payload
                    })

            except Exception as e:
                print(f"[ERROR] SSTI test failed: {e}")

    return vulnerabilities