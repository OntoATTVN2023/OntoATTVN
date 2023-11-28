import subprocess 
import os 
import shutil

def convert():

    proc = subprocess.Popen("java -jar app/static/owl2vowl.jar -file app/static/data/cveattck.ttl", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    source = 'cveattck.json'
    destination = 'app/static/data/cveattck.json'

    if os.path.exists(source):
        shutil.move(source, destination)