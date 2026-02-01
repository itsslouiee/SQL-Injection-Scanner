from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from utils import session


def get_forms(url):
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[-] Error loading page: {e}")
        return []


def form_details(form):
    details = {
        "action": form.attrs.get("action"),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }
    for input_tag in form.find_all("input"):
        input_name = input_tag.attrs.get("name")
        if input_name:
            details["inputs"].append({
                "type": input_tag.attrs.get("type", "text"),
                "name": input_name,
                "value": input_tag.attrs.get("value", ""),
                "hidden": input_tag.attrs.get("type", "text").lower() == "hidden"
            })
    return details


def get_get_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {key: values[0] for key, values in params.items()}


def get_base_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def extract_targets(url):
    targets = []

    get_params = get_get_params(url)
    if get_params:
        targets.append({
            "source": "GET params",
            "url": get_base_url(url),
            "method": "get",
            "data": get_params,
            "fields": list(get_params.keys())
        })

    forms = get_forms(url)
    for i, form in enumerate(forms, 1):
        details = form_details(form)
        if not details["inputs"]:
            continue

        target_url = urljoin(url, details["action"]) if details["action"] else get_base_url(url)
        data = {}
        for inp in details["inputs"]:
            if inp["type"] != "submit":
                data[inp["name"]] = inp.get("value") or "test"

        if data:
            targets.append({
                "source": f"Form #{i}",
                "url": target_url,
                "method": details["method"],
                "data": data,
                "fields": [inp["name"] for inp in details["inputs"] if inp["type"] != "submit"],
                "hidden_fields": [inp["name"] for inp in details["inputs"] if inp.get("hidden")]
            })

    return targets