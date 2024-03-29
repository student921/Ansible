import yaml
import subprocess

class ACE:
    def __init__(self, grant, protocol_options, source, destination, enable_fragments=''):
        self.grant=grant
        self.protocol_options=protocol_options
        self.source=source
        self.destination=destination
        self.enable_fragments=enable_fragments

target_ip = "192.168.2.1"
general_spoofing_command = " -S 192.168.180.160"

def generate_nmap_command(ace):
    #Zunächst wird ein grundleger Nmap-Befehl generiert, der im Laufe der Funktion um die Eigenschaften der ACEs erweitert wird.
    nmap_command = 'nmap -sS -Pn'

    #Zunächst wird überprüft, ob ein Spoofing-Test notwendig ist. Dies wäre der Fall, wenn ACEs auf einzelne Hosts beschränkt werden.
    if "host" in ace.source.keys():
        nmap_command += general_spoofing_command
    #Extrahiere den Dienst oder die Portnummer für einen spezifischen Portscan.
    if "port_protocol" in ace_entry.destination.keys():
        nmap_command +=  " -p" + ace.destination["port_protocol"]["eq"]
    #Ist die Fragmentierungsoption gesetzt, soll Nmap fragmentierte Pakete an das Ziel übermitteln.
    if ace.enable_fragments:
        nmap_command += " -f"
    #Betriffen die Regeln ICMP, sollen explizite ICMP-Anforderungen an das Ziel gesendet werden.
    if "icmp" in ace.protocol_options.keys():
            nmap_command = nmap_command.replace("-Pn", "-PE")

    nmap_command += " "+target_ip
    return nmap_command

#Hiermit soll eine Liste erstellt und mit den einzelnen ACEs der configure_acl.yml befüllt werden
list_of_aces = []

#Öffne das Konfigurationsplaybook und lade die Daten als Python Dictionary Objekt
with open("/home/student921/ansible-security/workspace/acl_security/Ansible/router/ACL/configure_acl.yml", 'r') as stream:
    try:
        d=yaml.load(stream, Loader=yaml.BaseLoader)
        
        #Im Dictionary Objekt werden nun die einzelnen Attribute aus den ACE Konfigurationen geparsed und als Objekt initialisiert.
        for acl in d[0]["tasks"]:
            for ace in acl["cisco.ios.ios_acls"]["config"][0]["acls"][0]["aces"]:
                ace_entry=ACE(grant=ace["grant"],
                              protocol_options=ace["protocol_options"],
                              source=ace["source"],
                              destination=ace["destination"])
                try:
                    if ace["enable_fragments"]:
                        ace_entry.enable_fragments=ace["enable_fragments"]
                except:
                    pass

                list_of_aces.append(ace_entry)
                    
    except yaml.YAMLError as error_message:
        print(error_message)

#Iteriere durch die Liste oder ACE Objekte, eneriere für jede ACE den entsprechenden Nmap-Prüfscan und führe ihn durch.
for ace_entry in list_of_aces:
    print("Scan command: " + generate_nmap_command(ace_entry))
    scan_result = subprocess.run(generate_nmap_command(ace_entry) ,shell=True, capture_output=True, text=True)
    print(scan_result.stdout)
    
    #Wenn ein Spoofing-Test erfolgt ist, soll der gleiche Befehl nochmal ohne die gespoofte Adresse erfolgen, um die Funktionalität zu verifizieren.
    if general_spoofing_command in generate_nmap_command(ace_entry):
        command = generate_nmap_command(ace_entry).replace(general_spoofing_command, "")
        print("Scan command: " + command)
        scan_result = subprocess.run(command ,shell=True, capture_output=True, text=True)
        print(scan_result.stdout)
    
