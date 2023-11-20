import subprocess 
import os 
import shutil

def convert():

    # Run owl2vowl.jar converter : convert ontology file TTL to JSON format supported by WebVOWL
    proc = subprocess.Popen("java -jar app/static/owl2vowl.jar -file app/static/data/cveattck.ttl", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Move generated JSON file to data dir 
    source = 'cveattck.json'
    destination = 'app/static/data/cveattck.json'

    if os.path.exists(source):
        shutil.move(source, destination)