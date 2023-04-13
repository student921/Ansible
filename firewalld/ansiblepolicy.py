# Ein Programm zur statischen Code Analyse einer firewalld-Konfiguration mittels Ansible.
import yaml
import csv
from csv import DictReader

# Die Sicherheitspolicen befinden sich in der Datei "policies.csv".
# Zunächst wird eine Klasse policy erstellt, um die jeweiligen Regel als Objekte initialisieren zu können.
class policy:
    def __init__(self, name='', zone='', service='', source='', permanent='', state='', security_message=''):
        self.name = name
        self.zone = zone
        self.service = service
        self.source = source
        self.permanent = permanent
        self.state = state
        self.security_message = security_message
        self.ruleset = {}

    # Diese Funktion nimmt nach der Initialisierung eines Policy-Objekts die relevanten Attribute entgegen.
    # Die Werte werden daraufhin als Schlüssel:Werte-Paare in einem Dictionary gespeichert, das später zum Vergleich genommen wird.
    def set_policy_ruleset(self):

        for rule_key, rule_value in self.__dict__.items():

            match rule_key:
                case 'name':
                    continue
                case 'ruleset':
                    continue
                case 'security_message':
                    continue

            if rule_value == '' or rule_value == None:
                continue

            self.ruleset[rule_key] = rule_value

# Wie auch für die Sicherheitspolicen, wird eine Klasse für die Regeln des Konfigurationsplaybooks configure-firewalld.yml erstellt.
class configuration:
    def __init__(self, name=None):
        self.name = name
        self.ruleset = {}
        
    # Diese Funktion nimmt nach der Initialisierung eines Configuration-Objekts die Konfiguration aus dem Playbook entgegen.
    # Die Werte werden daraufhin als Schlüssel:Werte-Paare in einem Dictionary gespeichert, das später zum Vergleich genommen wird.
    def set_configuration_ruleset(self, task_dictionary):

        for rule_key, rule_value in task_dictionary.items():

            self.ruleset[rule_key] = rule_value

# Als nächstes werden für beide Klassen Listen erstellt, in das die einzelnen Objekte geladen werden.
list_of_policies = []
list_of_configurations = []

# Dieser Schritt liest die policies.csv Datei ein, initialisiert für jede Regel ein entsprechendes Objekt und fügt sie der entsprechenden Liste hinzu.
with open('/home/student921/ansible-security/workspace/firewalld/Ansible/firewalld/policies.csv', newline='') as csvfile:
    csv_reader = DictReader(csvfile)
    for row in csv_reader:
        new_policy = policy(
                        name=row["name"],
                        zone=row["zone"],
                        source=row["source"],
                        permanent=row["permanent"],
                        state=row["state"],
                        service=row["service"],
                        security_message=row["security_message"])
        new_policy.set_policy_ruleset()
        list_of_policies.append(new_policy)
        
# Dieser Schritt liest die configure-firewalld.yml Datei ein, initialisiert für jeden Task ein entsprechendes Objekt und fügt sie der entsprechenden Liste hinzu.
with open('/home/student921/ansible-security/workspace/firewalld/Ansible/firewalld/configure-firewalld.yml', 'r') as stream:
    try:
    # Konvertiere das geöffnete Dokument zu einem Python Objekt.
        d=yaml.load(stream, Loader=yaml.BaseLoader)
        
        # Jeder task ist ein Dictionary-Objekt, der die Konfiguration beinhaltet, innerhalb einer Liste. Die Liste ist der Wert des Schlüssels d[0]["tasks"].
        for task in d[0]["tasks"]:
            
            # Suche nach dem Ansible Modul firewalld
            if "ansible.posix.firewalld" in task:
                
                # Extrahiere nur die Werte des jeweiligen Dictionary-Objekts und konvertiere sie in eine Liste.
                # Die Konfiguration ist hierbei ein Dictionary-Objekt, das den Wert des Schlüssel "ansible.posix.firewalld:" einnimmt.
                config = list(task.values())
                
                # Ein Beispielhaftes Ergebnis der konvertierten Liste: 
                # ['Firewalld - Enable https for Zone public.', {'zone': 'public', 'service': 'ssh', 'permanent': 'true', 'status': 'enabled'}]
                # Die Listen-Objekte können nun eingesetzt werden, um das configuration-Objekt zu initialisieren.
                new_configuration = configuration(name=config[0])
                new_configuration.set_configuration_ruleset(config[1])
                list_of_configurations.append(new_configuration)

    except yaml.YAMLError as error_message:
        print(error_message)


print(r"""
                           _       _
     _____               _| |     | |
    /     |             (_) | ___ | | ___
   /  /|  |_  __   _____ _| |/ _ \| |/ _ \
  /  /_|  | \/  \ /  __/| |   (_) | |  _
 /  ___   |   _  |_\ \  |_|_|\___/|_|\__|
/__/   |__|__| |_|___/  ___ ___  _   _  ___ _   _
                       | _ \ _ \| | | |/ __\ \_/ /
                       | __/(_) | |_| | |__ \   /
                       |_| \___/|___|_|\___/ |_|

Developer: Dejan Bijelic
Codename:  Master-THM
Version:   1.0



      """)

print('Checking for possible security issues with firewall configuration...')

# Für die Überprüfung wird zunächst eine Liste erstellt. In diese werden alle nicht durchgesetzten Sicherheitspolicen geladen.
list_of_security_issues = []

# Nun wird sowohl jedes Policy-Objekt und jedes Configuration-Objekt aus den enstprechenen Listen für ein Vergleich herangezogen.
for policy in list_of_policies:

    for configuration in list_of_configurations:
        # Wenn beide Rulesets miteinander identisch sind, kann aus der inneren Schleife ausgebrochen und das nächste Policy-Objekt herangezogen werden.
        if policy.ruleset.items() == configuration.ruleset.items():

            break
            
    # Wenn die obige if-Klausel nicht erfüllt wurde, dann bedeutet das, dass die Sicherheitspolice im Konfigurationsplaybook nicht umgesetzt wurde. 
    else:
        # Im ersten Schritt wird die Liste der Sicherheitsprobleme um den individuellen Sicherheitshinweis des unerfüllten Policy-Objekts erweitert. 
        list_of_security_issues.append({"security_message" : policy.security_message, "policy_rules" : policy.ruleset.items()})

        #for policy_key in policy.ruleset:

            #for config_key in configuration.ruleset:

               # if policy_key == config_key and policy.ruleset[policy_key] != configuration.ruleset[config_key]:

                    #list_of_security_issues[-1]["policy_rules"] = policy.ruleset.items()

                #else:
                    #continue


if list_of_security_issues:
    print("Ansible Policy found the following possible security isses:\n")

    for security_issue in list_of_security_issues:

            print("[!] " + security_issue["security_message"])
            print("[*] Please check the following policy parameters in configuration file:")
            
            for key, value in security_issue["policy_rules"]:
                print("[-] " + key + " : " + value)

else:
    print("No possible security issues found in firewall configuration.")
