from urllib.parse import urlparse

from core.crawler import crawl
from core.parser import extract_forms
from core.reporter import save_report
from modules.ssrf import test_ssrf
from modules.xxe import test_xxe
from modules.sqli import test_sqli
from modules.ssti import test_ssti
from utils.helpers import banner


def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and parsed.netloc


def format_vulnerability(vulnerability):
    details = [f"Type: {vulnerability.get('type')}", f"URL: {vulnerability.get('url')}" ]

    if vulnerability.get("payload"):
        details.append(f"Payload: {vulnerability.get('payload')}")
    if vulnerability.get("error"):
        details.append(f"Error: {vulnerability.get('error')}")
    if vulnerability.get("difference") is not None:
        details.append(f"Difference: {vulnerability.get('difference')}")

    return " | ".join(details)


def main():
    banner()

    url = input("Target URL: ").strip()
    if not url:
        print("[ERROR] Hedef URL boş olamaz.")
        return

    if not urlparse(url).scheme:
        url = f"http://{url}"

    if not is_valid_url(url):
        print("[ERROR] Geçersiz URL.")
        return

    print(f"\n[+] Crawling: {url}")
    response = crawl(url)

    if not response:
        return

    print(f"[+] Status Code: {response['status_code']}")

    forms = extract_forms(response["content"])
    print(f"[+] Forms Found: {len(forms)}\n")

    if not forms:
        print("[+] Sayfada test edilecek form bulunamadı.")
        return

    for index, form in enumerate(forms, start=1):
        print(f"--- FORM {index} ---")
        print(f"Action : {form['action'] or url}")
        print(f"Method : {form['method']}")
        print("Inputs:")

        if form["inputs"]:
            for input_field in form["inputs"]:
                print(f"  - Name: {input_field['name']} | Type: {input_field['type']}")
        else:
            print("  - (No named inputs detected)")

        print()

    print("[+] Starting SQL Injection Tests...\n")
    vulnerabilities = test_sqli(url, forms)

    print("\n[+] Starting SSTI Tests...\n")
    vulnerabilities.extend(test_ssti(url, forms))

    print("\n[+] Starting SSRF Tests...\n")
    vulnerabilities.extend(test_ssrf(url, forms))

    print("\n[+] Starting XXE Tests...\n")
    vulnerabilities.extend(test_xxe(url, forms))

    if vulnerabilities:
        print("\n[+] Vulnerabilities Found:")
        for vuln in vulnerabilities:
            print(f"  - {format_vulnerability(vuln)}")
    else:
        print("\n[+] Tarama sırasında hiçbir açık bulunamadı.")

    save_report(vulnerabilities)
    print("\n[+] Scan completed.")


if __name__ == "__main__":
    main()