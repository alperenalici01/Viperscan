from bs4 import BeautifulSoup


def extract_forms(html):
    soup = BeautifulSoup(html, "lxml")
    forms_data = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()

        inputs = []
        for input_tag in form.find_all(["input", "textarea", "select"]):
            name = input_tag.get("name")
            if not name:
                continue

            if input_tag.name == "select":
                input_type = "select"
            elif input_tag.name == "textarea":
                input_type = "textarea"
            else:
                input_type = input_tag.get("type", "text")

            inputs.append({
                "name": name,
                "type": input_type
            })

        forms_data.append({
            "action": action,
            "method": method,
            "inputs": inputs
        })

    return forms_data