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
		list_to_filter = set(['CWE-1330', 'CWE-1269', 'CWE-434', 'CWE-180', 'CWE-1222', 'CWE-1220', 'CWE-212', 
                            'CWE-349', 'CWE-1262', 'CWE-328', 'CWE-77', 'CWE-201', 'CWE-732', 'CWE-523', 'CWE-15', 
                            'CWE-1326', 'CWE-400', 'CWE-567', 'CWE-1325', 'CWE-262', 'CWE-916', 'CWE-697', 'CWE-279',
                            'CWE-645', 'CWE-114', 'CWE-836', 'CWE-1191', 'CWE-525', 'CWE-41', 'CWE-272', 'CWE-451', 
                            'CWE-6', 'CWE-488', 'CWE-221', 'CWE-354', 'CWE-707', 'CWE-204', 'CWE-1268', 'CWE-419', 
                            'CWE-1007', 'CWE-1322', 'CWE-1266', 'CWE-833', 'CWE-654', 'CWE-648', 'CWE-1296', 'CWE-1294',
                            'CWE-177', 'CWE-257', 'CWE-441', 'CWE-1274', 'CWE-1317', 'CWE-205', 'CWE-179', 'CWE-185', 
                            'CWE-497', 'CWE-1272', 'CWE-412', 'CWE-471', 'CWE-642', 'CWE-117', 'CWE-301', 'CWE-638', 'CWE-346',
                            'CWE-79', 'CWE-1321', 'CWE-350', 'CWE-1301', 'CWE-261', 'CWE-524', 'CWE-75', 'CWE-200', 'CWE-1283',
                            'CWE-1312', 'CWE-1323', 'CWE-284', 'CWE-348', 'CWE-250', 'CWE-176', 'CWE-1278', 'CWE-798', 'CWE-923',
                            'CWE-1315', 'CWE-424', 'CWE-614', 'CWE-183', 'CWE-287', 'CWE-288', 'CWE-667', 'CWE-494', 'CWE-1244', 
                            'CWE-1224', 'CWE-1264', 'CWE-772', 'CWE-302', 'CWE-692', 'CWE-1263', 'CWE-1252', 'CWE-506', 'CWE-353', 
                            'CWE-311', 'CWE-829', 'CWE-384', 'CWE-425', 'CWE-430', 'CWE-181', 'CWE-270', 'CWE-20', 'CWE-1239', 'CWE-1270', 
                            'CWE-427', 'CWE-1243', 'CWE-327', 'CWE-59', 'CWE-300', 'CWE-94', 'CWE-918', 'CWE-46', 'CWE-1316', 'CWE-290', 
                            'CWE-315', 'CWE-314', 'CWE-74', 'CWE-862', 'CWE-22', 'CWE-539', 'CWE-1259', 'CWE-1258', 'CWE-285', 'CWE-1233',
                            'CWE-208', 'CWE-770', 'CWE-73', 'CWE-319', 'CWE-610', 'CWE-1299', 'CWE-1204', 'CWE-318', 'CWE-307', 'CWE-757', 
                            'CWE-347', 'CWE-565', 'CWE-1280', 'CWE-97', 'CWE-1231', 'CWE-309', 'CWE-282', 'CWE-330', 'CWE-1257', 'CWE-664',
                            'CWE-345', 'CWE-113', 'CWE-96', 'CWE-522', 'CWE-172', 'CWE-662', 'CWE-1260', 'CWE-602', 'CWE-1318', 'CWE-1021',
                            'CWE-552', 'CWE-173', 'CWE-184', 'CWE-1275', 'CWE-291', 'CWE-276', 'CWE-352', 'CWE-359', 'CWE-404', 'CWE-1267', 
                            'CWE-706', 'CWE-93', 'CWE-507', 'CWE-693', 'CWE-1320', 'CWE-267', 'CWE-553', 'CWE-308', 'CWE-116', 'CWE-1273', 
                            'CWE-1297', 'CWE-325', 'CWE-269', 'CWE-95', 'CWE-593', 'CWE-1327', 'CWE-331', 'CWE-1190', 'CWE-521', 'CWE-295',
                            'CWE-1311', 'CWE-1193', 'CWE-326', 'CWE-472', 'CWE-226', 'CWE-1188', 'CWE-312', 'CWE-162', 'CWE-294', 'CWE-263',
                            'CWE-426', 'CWE-1314'])
		
		filtered_cwe_ids = initial_cwe_ids & list_to_filter
		if not filtered_cwe_ids:
			return render_template('index.html', results={'Undefined': ['Undefined']}, cve_id=cve_id.upper(), cve_description=cve_description,
                                   cwe=cwe, dataGraph={})

		if len(filtered_cwe_ids) > 1:
			cwe_id = "$|".join(filtered_cwe_ids)+"$"
		else:
			cwe_id = filtered_cwe_ids.pop()+"$"
			
		g = Graph()
		g.parse("ontology/ontology.owl", format="xml")
		sparql_query = '''
		PREFIX my: <http://test.org/Ontology.owl#>
		SELECT DISTINCT ?TacticID ?TacticName ?TechID ?TechName ?CapecID ?CapecName
		WHERE {
		    filter REGEX(?CWEID,"''' + cwe_id + '''").
		    ?CWE rdf:type my:CWE.
		    ?CWE my:hasID ?CWEID.
		    ?CWE my:hasCAPEC ?Capec.
            ?Capec my:hasID ?CapecID.
            ?Capec my:hasName ?CapecName.
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
		list_capec = set()
		for row in result:
			tactic = str(row["TacticName"])
			tech = str(row["TechName"])
			tacticId = str(row["TacticID"])
			techId = str(row["TechID"])
			capecId = str(row["CapecID"])
			capecName = str(row["CapecName"])
			value = f"{techId}: {tech}"
			tactic = f"{tacticId}: {tactic}"
			result_data[tactic].append(value)
			list_capec.add(f'{capecId}: {capecName}')

		result_dict = dict(result_data)

		tactics = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
                   'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact']

		dataGraph = dict()
		for key, value in result_dict.items():
			dataGraph[key.split(": ")[1]] = len(value)
		for tactic in tactics:
			if tactic not in dataGraph.keys():
				dataGraph[tactic] = 0
		return render_template('index.html', capecs=list_capec, results=result_dict, cve_id=cve_id.upper(), cve_description=cve_description,
                               cwe=cwe,  dataGraph=dataGraph)

	else:
		return render_template('index.html', results=None, dataGraph={})

@app.route('/ontology-model')
def ontoModel():
	convert()
	return render_template('ontology-model.html')

@app.route('/defense', methods=['GET'])
def defense():
	if request.args.get('techID') is None:
		return render_template('defense.html', tech_detail=[], results={},dataGraph={})
	
	techId = str(request.args.get('techID'))
	print(techId)
	tech_id = techId.strip().upper()
	tech_id = '^'+str(tech_id)+'$'
	
	g = Graph()
	g.parse("ontology/ontoDefense.owl", format="xml")
	sparql_query = '''
	PREFIX attack: <http://test.org/Ontology.owl#>
	SELECT DISTINCT ?TechID ?TechName ?TechDescription ?DefenseID ?DefenseName ?DefenseDescription ?Type 
	WHERE {		
		filter REGEX(?TechID,"''' + tech_id + '''").
		?Tech rdf:type attack:Technique.
		?Tech attack:hasID ?TechID.
		?Tech attack:hasName ?TechName.
		?Tech attack:hasDescription ?TechDescription.
		optional{
		?Tech attack:defenseBy ?Defense.
		?Defense attack:hasID ?DefenseID.
		?Defense attack:hasDescription ?DefenseDescription.
		?Defense attack:hasName ?DefenseName.
		?Defense attack:hasType ?Type.}
	} order by ?Type
	'''
	query = prepareQuery(sparql_query)
	results = g.query(query)
	if len(results) == 0:
		return render_template('defense.html', tech_detail=[], results={},dataGraph={}, msg=f'No results found for \"{techId}\"')
		
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

	if result_dict.get(0) is None and len(result_dict) == 1:
		return render_template('defense.html', tech_detail=tech_detail, results={},dataGraph={})

	defenses = ['Deceive', 'Detect', 'Evict', 'Model', 'Harden', 'Isolate', 'Restore']

	dataGraph = dict()
	for key, value in result_dict.items():
		dataGraph[key] = len(value)
	for defense in defenses:
		if defense not in dataGraph.keys():
			dataGraph[defense] = 0
	return render_template('defense.html',tech_detail=tech_detail, results=result_dict,dataGraph=dataGraph)
