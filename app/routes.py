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
		cwe_ids = set(cwe.keys())
		
		if len(cwe_ids) > 1:
			cwe_id = "$|".join(cwe_ids)+"$"
		else:
			cwe_id = cwe_ids.pop()+"$"
			
		g = Graph()
		g.parse("ontology/ontology.owl", format="xml")
		sparql_query = '''
		PREFIX attack: <http://test.org/Ontology.owl#>
		SELECT DISTINCT ?TacticID ?TacticName ?TechID ?TechName ?CapecID ?CapecName
		WHERE {
		    filter REGEX(?CWEID,"''' + cwe_id + '''").
		    ?CWE rdf:type attack:CWE.
		    ?CWE attack:hasID ?CWEID.
		    ?CWE attack:hasCAPEC ?Capec.
            ?Capec attack:hasID ?CapecID.
            ?Capec attack:hasName ?CapecName.
		    ?Capec attack:mapToTechnique ?Tech.
		    ?Tech attack:hasID ?TechID.
		    ?Tech attack:hasName ?TechName.
		    ?Tech attack:accomplishedTactic ?Tactic.
		    ?Tactic attack:hasID ?TacticID.
		    ?Tactic attack:hasName ?TacticName.
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
			if value not in result_data[tactic]:
				result_data[tactic].append(value)
			list_capec.add(f'{capecId}: {capecName}')

		if not list_capec:
			return render_template('index.html', results={'Undefined': ['Undefined']}, cve_id=cve_id.upper(), cve_description=cve_description,
                                   cwe=cwe, dataGraph={})
		
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
