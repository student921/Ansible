import yaml
import subprocess

class ACE:
    def __init__(self, grant, protocol_options, source, destination, enable_fragments=''):
        self.grant=grant
        self.protocol_options=protocol_options
        self.source=source
        self.destination=destination
        self.enable_fragments=enable_fragments
  

class nmap_command:
    def __init__(self, target):
        self.standard_arguments = "-sS -Pn "
        self.target=target
        self.protocol=""
        self.optional=""


list_of_aces = []
list_of_nmap_objects = []
list_of_nmap_commands = []
spoofing_ip = "192.168.180.160"
target_ip="192.168.2.1 "

#Create ACE
with open("/home/student921/ansible-security/workspace/CiscoSec/Ansible/router/ACL/configure_acl.yml", 'r') as stream:
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


#Create nmap_commands
for ace in list_of_aces:
    try:
        protocol = ace.protocol_options.keys()
        if "tcp" in protocol or "ip" in protocol:
            nmap_command_entry = nmap_command(target=target_ip)
            
            if ace.enable_fragments == "true":
                nmap_command_entry.optional="-f"

            try:
                if ace.destination["port_protocol"]["eq"]:
                    nmap_command_entry.protocol="-p"+ace.destination["port_protocol"]["eq"]
            except:
                pass

            try:
                if ace.source["host"]:
                    nmap_command_entry.optional = " -S "+spoofing_ip
            except:
                pass
        
            list_of_nmap_objects.append(nmap_command_entry)
    
    except:
        pass


for object in list_of_nmap_objects:
    if object.protocol or object.optional:
        nmap_c = "nmap "+ object.standard_arguments + object.target + object.protocol + object.optional
        if "-f" in nmap_c:
            nmap_c=nmap_c+" -p22"
        list_of_nmap_commands.append(nmap_c)
        if "-S" in nmap_c:
            nmap_c = nmap_c.replace("-S "+spoofing_ip, "")
            list_of_nmap_commands.append(nmap_c)

#execute
for command in list_of_nmap_commands:
    print("Scan command: " + command)
    scan_result = subprocess.run(command ,shell=True, capture_output=True, text=True)
    print(scan_result.stdout)

 
