from collections import defaultdict
from app import app
from flask import render_template, request
from rdflib import Graph
from rdflib.plugins.sparql.processor import prepareQuery
from app.owl2vowl import convert
from app.getCVE import get_cve_info



@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
	if request.method == 'POST':
		cve_id = request.form['cveId'].strip()
		cve_description, cwe = get_cve_info(cve_id.upper())
		if not cve_description and not cwe:
			return render_template('index.html', results=None, msg=f'No results found for \"{cve_id}\"', dataGraph={})
		if not cwe:
			cwe = {'Undefined': ''}
			return render_template('index.html', results={'Undefined': ['Undefined']}, cve_id=cve_id.upper(), cve_description=cve_description,
                                   cwe=cwe, dataGraph={})
		initial_cwe_ids = set(cwe.keys())

		list_to_filter = set([
            'CWE-6', 'CWE-15', 'CWE-20', 'CWE-46', 'CWE-59', 'CWE-73', 'CWE-74', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-97', 'CWE-113',
            'CWE-114', 'CWE-117', 'CWE-162', 'CWE-172', 'CWE-173', 'CWE-180', 'CWE-181', 'CWE-200', 'CWE-204', 'CWE-205', 'CWE-208',
            'CWE-226', 'CWE-257', 'CWE-261', 'CWE-262', 'CWE-263', 'CWE-267', 'CWE-269', 'CWE-270', 'CWE-272', 'CWE-276', 'CWE-282',
            'CWE-284', 'CWE-285', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-300', 'CWE-302', 'CWE-307', 'CWE-308', 'CWE-309',
            'CWE-311', 'CWE-312', 'CWE-314', 'CWE-315', 'CWE-318', 'CWE-319', 'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-330',
            'CWE-345', 'CWE-346', 'CWE-348', 'CWE-349', 'CWE-350', 'CWE-353', 'CWE-359', 'CWE-384', 'CWE-400', 'CWE-404', 'CWE-412',
            'CWE-419', 'CWE-424', 'CWE-425', 'CWE-426', 'CWE-427', 'CWE-430', 'CWE-434', 'CWE-441', 'CWE-451', 'CWE-472', 'CWE-488',
            'CWE-494', 'CWE-497', 'CWE-506', 'CWE-507', 'CWE-521', 'CWE-522', 'CWE-524', 'CWE-525', 'CWE-539', 'CWE-552', 'CWE-553',
            'CWE-565', 'CWE-567', 'CWE-593', 'CWE-602', 'CWE-642', 'CWE-645', 'CWE-654', 'CWE-662', 'CWE-664', 'CWE-667', 'CWE-692',
            'CWE-693', 'CWE-697', 'CWE-706', 'CWE-732', 'CWE-757', 'CWE-770', 'CWE-772', 'CWE-798', 'CWE-829', 'CWE-833', 'CWE-836',
            'CWE-862', 'CWE-916', 'CWE-923', 'CWE-1021', 'CWE-1188', 'CWE-1190', 'CWE-1191', 'CWE-1193', 'CWE-1220', 'CWE-1239', 'CWE-1243',
            'CWE-1244', 'CWE-1258', 'CWE-1264', 'CWE-1266', 'CWE-1268', 'CWE-1269', 'CWE-1270', 'CWE-1272', 'CWE-1273', 'CWE-1278', 'CWE-1280',
            'CWE-1297', 'CWE-1299', 'CWE-1301', 'CWE-1311', 'CWE-1314', 'CWE-1315', 'CWE-1317', 'CWE-1318', 'CWE-1320', 'CWE-1321', 'CWE-1322',
            'CWE-1323', 'CWE-1325', 'CWE-1326', 'CWE-1327', 'CWE-1330'
        ])

		filtered_cwe_ids = initial_cwe_ids & list_to_filter
		if not filtered_cwe_ids:
			return render_template('index.html', results={'Undefined': ['Undefined']}, cve_id=cve_id.upper(), cve_description=cve_description,
                                   cwe=cwe, dataGraph={})

		if len(filtered_cwe_ids) > 1:
			cwe_id = "$|".join(filtered_cwe_ids)+"$"
		else:
			cwe_id = filtered_cwe_ids.pop()+"$"
		g = Graph()
		g.parse("ontology/Ontology.owl", format="xml")
		sparql_query = '''
		PREFIX my: <http://test.org/Ontology.owl#>
		SELECT DISTINCT ?TacticID ?TacticName ?TechID ?TechName
		WHERE {
		    filter REGEX(?CWEID,"''' + cwe_id + '''").
		    ?CWE rdf:type my:CWE.
		    ?CWE my:hasID ?CWEID.
		    ?CWE my:hasCAPEC ?Capec.
		    ?Capec my:mapToCAPEC ?Tech.
		    ?Tech my:hasID ?TechID.
		    ?Tech my:hasName ?TechName.
		    ?Tech my:accomplishedTactic ?Tactic.
		    ?Tactic my:hasID ?TacticID.
		    ?Tactic my:hasName ?TacticName.
		}'''
		query = prepareQuery(sparql_query)

		result = g.query(query)
		result_data = defaultdict(list)

		for row in result:
			tactic = str(row["TacticName"])
			tech = str(row["TechName"])
			tacticId = str(row["TacticID"])
			techId = str(row["TechID"])
			value = f"{techId}: {tech}"
			tactic = f"{tacticId}: {tactic}"
			result_data[tactic].append(value)
	
		result_dict = dict(result_data)
		tactics = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
                   'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact']

		dataGraph = dict()
		for key, value in result_dict.items():
			dataGraph[key.split(": ")[1]] = len(value)
		for tactic in tactics:
			if tactic not in dataGraph.keys():
				dataGraph[tactic] = 0
		return render_template('index.html', results=result_dict, cve_id=cve_id.upper(), cve_description=cve_description,
                               cwe=cwe,  dataGraph=dataGraph)

	else:
		return render_template('index.html', results=None, dataGraph={})

@app.route('/ontology-model')
def ontoModel():
	convert()
	return render_template('ontology-model.html')

@app.route('/defense', methods=['GET', 'POST'])
def defense():
	if request.method == 'POST':
		tech_id = request.form['techID'].upper()
		tech_id = '^'+str(tech_id)+'$'
		g = Graph()
		g.parse("ontoweb/OntoWeb.owl", format="xml")

		sparql_query = '''
		PREFIX attack: <http://test.org/Ontology.owl#>
		SELECT DISTINCT ?TechID ?TechName ?TechDescription ?DefenseID ?DefenseName ?DefenseDescription ?Type 
		WHERE {	
		
			filter REGEX(?TechID,"''' + tech_id + '''").
			?Tech rdf:type attack:Technique.
			?Tech attack:hasID ?TechID.
			?Tech attack:hasName ?TechName.
			?Tech attack:hasDescription ?TechDescription.
			?Tech attack:defenseBy ?Defense.
			?Defense attack:hasID ?DefenseID.
			?Defense attack:hasDescription ?DefenseDescription.
			?Defense attack:hasName ?DefenseName.
			?Defense attack:hasType ?Type.
		} order by ?Type
		'''
		query = prepareQuery(sparql_query)
		results = g.query(query)
		result_data = defaultdict(list)
		tech_detail = []
		for row in results:
			tech_id = str(row['TechID'])
			tech_name = str(row['TechName'])
			tech_desciption = str(row['TechDescription'])
			
			defense_id = str(row['DefenseID'])
			defense_name = str(row['DefenseName'])
			defense_description = str(row['DefenseDescription'])
			defense_type = str(row['Type'])
			value = f"{defense_id}: {defense_name}: {defense_description}"
			result_data[defense_type].append(value)
		tech_detail.append({
			'TechID': tech_id,
			'TechName': tech_name,
			'TechDescription': tech_desciption
			})
		result_dict = dict(result_data)
		defenses = ['Deceive', 'Detect', 'Evict', 'Model', 'Harden', 'Isolate', 'Restore']

		dataGraph = dict()
		for key, value in result_dict.items():
			dataGraph[key] = len(value)
		for defense in defenses:
			if defense not in dataGraph.keys():
				dataGraph[defense] = 0
		print(dataGraph)
		return render_template('defense.html',tech_detail=tech_detail, results=result_dict,dataGraph=dataGraph)

	return render_template('defense.html')
