from collections import defaultdict
from bs4 import BeautifulSoup
from app import app
from flask import render_template, request
from rdflib import Graph
from rdflib.plugins.sparql.processor import prepareQuery
import re
import requests


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
            cwe_description = cwe_row.find_all(
                "td", {"data-testid": lambda x: x and x.startswith("vuln-CWEs-link-")})[1].text.strip()
            cwe_dict[cwe_id] = cwe_description

    return cve_description, cwe_dict


def get_capec_id(cwe_ids):
    cwe_numbers = [re.search(r'\d+', cwe).group(0) for cwe in cwe_ids]
    capec_ids = fetch_capec_ids(cwe_numbers)

    if not capec_ids:
        return set()

    return capec_ids


def fetch_capec_ids_for_cwe(url, cwe_number):
    try:
        capec_id_pattern = r"CAPEC-\d+"
        content = requests.get(url).text
        return set(re.findall(capec_id_pattern, content))
    except Exception as e:
        return {f"Error loading CAPEC data for CWE {cwe_number}: {e}"}


def fetch_capec_ids(cwe_numbers):
    capec_ids = set()
    for cwe_number in cwe_numbers:
        cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
        capec_ids.update(fetch_capec_ids_for_cwe(cwe_url, cwe_number))
    return capec_ids


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cve_id = request.form['cveId'].upper().strip()

        cve_description, cwe = get_cve_info(cve_id)
        if not cve_description and not cwe:
            return render_template('index.html', results=None)

        cwe_ids = list(cwe.keys())
        initial_capec_ids = get_capec_id(cwe_ids)

        list_to_filter = set([
            "CAPEC-1", "CAPEC-2", "CAPEC-11", "CAPEC-13", "CAPEC-17", "CAPEC-19",
            "CAPEC-21", "CAPEC-25", "CAPEC-30", "CAPEC-31", "CAPEC-35", "CAPEC-37",
            "CAPEC-38", "CAPEC-49", "CAPEC-55", "CAPEC-57", "CAPEC-60", "CAPEC-65",
            "CAPEC-68", "CAPEC-70", "CAPEC-94", "CAPEC-98", "CAPEC-112", "CAPEC-114",
            "CAPEC-115", "CAPEC-122", "CAPEC-125", "CAPEC-127", "CAPEC-130",
            "CAPEC-131", "CAPEC-132", "CAPEC-141", "CAPEC-142", "CAPEC-148",
            "CAPEC-150", "CAPEC-158", "CAPEC-159", "CAPEC-163", "CAPEC-165",
            "CAPEC-169", "CAPEC-177", "CAPEC-180", "CAPEC-186", "CAPEC-187",
            "CAPEC-191", "CAPEC-196", "CAPEC-203", "CAPEC-204", "CAPEC-206",
            "CAPEC-227", "CAPEC-233", "CAPEC-251", "CAPEC-267", "CAPEC-268",
            "CAPEC-270", "CAPEC-292", "CAPEC-295", "CAPEC-300", "CAPEC-309",
            "CAPEC-312", "CAPEC-313", "CAPEC-383", "CAPEC-407", "CAPEC-438",
            "CAPEC-439", "CAPEC-440", "CAPEC-442", "CAPEC-443", "CAPEC-445",
            "CAPEC-446", "CAPEC-448", "CAPEC-457", "CAPEC-464", "CAPEC-465",
            "CAPEC-469", "CAPEC-471", "CAPEC-473", "CAPEC-474", "CAPEC-478",
            "CAPEC-479", "CAPEC-480", "CAPEC-481", "CAPEC-482", "CAPEC-485",
            "CAPEC-488", "CAPEC-489", "CAPEC-490", "CAPEC-497", "CAPEC-504",
            "CAPEC-509", "CAPEC-511", "CAPEC-516", "CAPEC-520", "CAPEC-522",
            "CAPEC-523", "CAPEC-528", "CAPEC-531", "CAPEC-532", "CAPEC-537",
            "CAPEC-538", "CAPEC-539", "CAPEC-541", "CAPEC-542", "CAPEC-543",
            "CAPEC-545", "CAPEC-550", "CAPEC-551", "CAPEC-552", "CAPEC-555",
            "CAPEC-556", "CAPEC-558", "CAPEC-560", "CAPEC-561", "CAPEC-562",
            "CAPEC-564", "CAPEC-565", "CAPEC-568", "CAPEC-569", "CAPEC-571",
            "CAPEC-572", "CAPEC-573", "CAPEC-574", "CAPEC-575", "CAPEC-576",
            "CAPEC-577", "CAPEC-578", "CAPEC-579", "CAPEC-580", "CAPEC-581",
            "CAPEC-593", "CAPEC-600", "CAPEC-609", "CAPEC-616", "CAPEC-620",
            "CAPEC-633", "CAPEC-634", "CAPEC-635", "CAPEC-636", "CAPEC-637",
            "CAPEC-638", "CAPEC-639", "CAPEC-640", "CAPEC-641", "CAPEC-642",
            "CAPEC-643", "CAPEC-644", "CAPEC-645", "CAPEC-646", "CAPEC-647",
            "CAPEC-648", "CAPEC-649", "CAPEC-650", "CAPEC-651", "CAPEC-652",
            "CAPEC-654", "CAPEC-655", "CAPEC-657", "CAPEC-660", "CAPEC-662",
            "CAPEC-665", "CAPEC-666", "CAPEC-668", "CAPEC-669", "CAPEC-670",
            "CAPEC-671", "CAPEC-672", "CAPEC-673", "CAPEC-674", "CAPEC-675",
            "CAPEC-677", "CAPEC-678", "CAPEC-691", "CAPEC-694", "CAPEC-695",
            "CAPEC-697", "CAPEC-698", "CAPEC-700"
        ])

        filtered_capec_ids = initial_capec_ids & list_to_filter
        if not filtered_capec_ids:
            return render_template('index.html', results={}, cve_id=cve_id, cve_description=cve_description,
                               cwe=cwe, initial_capec_ids=initial_capec_ids, filtered_capec_ids=filtered_capec_ids)
        g = Graph()
        g.parse("C:/FU studying/s9/IAP491/Code/Ontology.owl", format="xml")

        capecs = "|".join(filtered_capec_ids)
        sparql_query = '''
            PREFIX my: <http://test.org/Ontology.owl#>
            SELECT DISTINCT ?Stage ?Tactic ?Tech ?SubTech ?Capec
            WHERE {
                {
                    FILTER REGEX(?Capec, "''' + capecs + '''") .
                    ?SubTechID rdf:type my:Sub_Techniques.
                    ?SubTechID my:mapTo ?Capec.
                    ?SubTechID my:hasName ?SubTech.
                    ?SubTechID my:isContained ?TechID.
                    ?TechID my:hasName ?Tech.
                    ?SubTechID my:isPartOf ?TacticID.
                    ?TacticID my:hasName ?Tactic.
                    ?TacticID my:isUsed ?StageID.
                    ?StageID my:hasName ?Stage.
                } UNION {
                    FILTER REGEX(?Capec, "''' + capecs + '''")
                    ?TechID rdf:type my:Techniques.
                    ?TechID my:mapTo ?Capec.
                    ?TechID my:hasName ?Tech.
                    ?TechID my:isPartOf ?TacticID.
                    ?TacticID my:hasName ?Tactic.
                    ?TacticID my:isUsed ?StageID.
                    ?StageID my:hasName ?Stage.
                }
            }
            ORDER BY ?Capec'''
        query = prepareQuery(sparql_query)

        result = g.query(query)
        result_data = defaultdict(list)

        for row in result:
            tactic = str(row["Tactic"])
            tech = str(row["Tech"])
            subtech = str(row["SubTech"])
            
            if subtech == 'None':
                value = tech
            else:
                value = f"{tech}:{subtech}"
            
            result_data[tactic].append(value)

        result_dict = dict(result_data)

        return render_template('index.html', results=result_dict, cve_id=cve_id, cve_description=cve_description,
                               cwe=cwe, initial_capec_ids=initial_capec_ids, filtered_capec_ids=filtered_capec_ids)

    else:
        return render_template('index.html', results=None)


if __name__ == '__main__':
    app.run()
