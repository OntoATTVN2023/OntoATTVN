import re
import requests
from bs4 import BeautifulSoup

def get_cve_info(cve_id):
    url = "https://nvd.nist.gov/vuln/detail/" + cve_id

    response = requests.get(url)

    if response.status_code != 200:
        return '', {}

    soup = BeautifulSoup(response.text, "html.parser")

    try:
        cve_description = soup.find(
            "p", {"data-testid": "vuln-description"}).text
    except Exception as e:
        print("Error while retrieving CVE Description:", str(e))
        return '', {}

    cwe_rows = soup.find_all(
        "tr", {"data-testid": lambda x: x and x.startswith("vuln-CWEs-row-")})

    cwe_dict = {}

    for cwe_row in cwe_rows:
        cwe_id = cwe_row.find(
            "td", {"data-testid": lambda x: x and x.startswith("vuln-CWEs-link-")}).text.strip()
        if re.search(r'\d', cwe_id):
            cwe_name = cwe_row.find_all(
                "td", {"data-testid": lambda x: x and x.startswith("vuln-CWEs-link-")})[1].text.strip()
            cwe_dict[cwe_id] = cwe_name

    return cve_description, cwe_dict