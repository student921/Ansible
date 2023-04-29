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

    #Zunächst wird überprüft, ob ein Spoofing-Test notwendig ist.
    if "host" in ace.source.keys():
        nmap_command += general_spoofing_command

    if "port_protocol" in ace_entry.destination.keys():
        nmap_command +=  " -p" + ace.destination["port_protocol"]["eq"]

    if ace.enable_fragments:
        nmap_command += " -F"

    if "icmp" in ace.protocol_options.keys():
            nmap_command = nmap_command.replace("-Pn", "-PE")

    nmap_command += " "+target_ip
    return nmap_command

list_of_aces = []

#Create ACE
with open("/home/student921/ansible-security/workspace/acl_security/Ansible/router/ACL/configure_acl.yml", 'r') as stream:
    try:
    # Convert yaml document to python object
        d=yaml.load(stream, Loader=yaml.BaseLoader)

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


for ace_entry in list_of_aces:
    print(generate_nmap_command(ace_entry))

#execute
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
    
