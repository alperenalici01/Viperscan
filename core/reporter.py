import json
import os


def save_report(vulnerabilities, path="reports/report.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(vulnerabilities, file, indent=4, ensure_ascii=False)

    print(f"\n[+] Report saved to {path}")