import yaml
from functions_complex_checks import *

#Mittels dieser Klasse wird jeder Task innerhalb des Playbooks configure-router.yml in ein einzelnes Objekt initialisiert.
class ios_task:
    def __init__(self, name, commands):
        self.name=name
        self.commands=commands

#Mittels dieser Klasse wird jede empfohlene Sicherheitskonfiguraiton innerhalb cis_controls_v7v8_ig1.yml in ein einzelnes Objekt initialisiert.
class cis_recommendation:
    def __init__(self, name, rationale, impact, remediation, configure_commands, check_commands=''):
        self.name=name
        self.rationale=rationale
        self.impact=impact
        self.remediation=remediation
        self.configure_commands=configure_commands
        self.check_commands=check_commands

#Diese Liste übernimmt alle Objekte der Klasse cis_recommendation, bei denen ein einfacher String Abgleich durchgeführt werden kann.
list_of_cis_recommendations = []
#Diese Liste übernimmt alle Objekte der Klasse cis_recommendation, bei denen zusätzlich variable Benutzereingaben überprüft werden müssen. 
list_of_complex_cis_recommendations = []
#Diese Liste übernimmt alle Objekte der Klasse ios_task.
list_of_ios_tasks = []
#Diese Liste übernimmt alle Objekte der Klasse cis_recommendation, die innerhalb des Playbooks configure_router.yml identifiziert werden.
list_of_enforced_security_practices = []

#Zunächst werden alle Objekte der Klasse cis_recommendation als Objekte initialisiert, die einen keine Komplexität für den String Abgleich aufweisen.
with open('/home/student921/ansible-security/workspace/CiscoSec/Ansible/router/configuration/cis_controls_v7v8_ig1.yml', 'r') as stream:
    try:
    #Konvertiere das YAML-Dokument als Python-Objekt
        d=yaml.load(stream, Loader=yaml.BaseLoader)

        for recommendation in d[0]["recommendations"]:
	    #Wenn keine Komplexität vorhanden ist, soll ein Objekt der Klasse cis_recommendation erstellt werden.
            if recommendation["complex"] == "False":
                new_security_recommendation = cis_recommendation(name=recommendation["name"], 
                                                                    rationale=recommendation["rationale"], 
                                                                    impact=recommendation["impact"],
                                                                    remediation=recommendation["remediation"],
                                                                    configure_commands=recommendation["configure_commands"], 
                                                                    check_commands=recommendation["check_commands"])
                #Füge das Objekt der entsprechenden Liste hinzu.
                list_of_cis_recommendations.append(new_security_recommendation)

    except yaml.YAMLError as error_message:
        print(error_message)

#Dann werden alle Objekte der Klasse cis_recommendation als Objekte initialisiert, die einen komplexen String Abgleich erfordern.
with open('/home/student921/ansible-security/workspace/CiscoSec/Ansible/router/configuration/cis_controls_v7v8_ig1.yml', 'r') as stream:
    try:
        d=yaml.load(stream, Loader=yaml.BaseLoader)

        for recommendation in d[0]["recommendations"]:
	    #Wenn Komplexität vorhanden ist, soll ein Objekt der Klasse cis_recommendation erstellt werden.
            if recommendation["complex"] == "True":
                new_security_recommendation = cis_recommendation(name=recommendation["name"], 
                                                                    rationale=recommendation["rationale"], 
                                                                    impact=recommendation["impact"], 
                                                                    remediation=recommendation["remediation"],
                                                                    configure_commands=recommendation["configure_commands"])
                #Füge das Objekt der entsprechenden Liste hinzu.
                list_of_complex_cis_recommendations.append(new_security_recommendation)

    except yaml.YAMLError as error_message:
        print(error_message)

#Nun werden die einzelnen Tasks des Playbooks configure_router.yml als Objekte initialisiert.
with open('/home/student921/ansible-security/workspace/CiscoSec/Ansible/router/configuration/configure-router.yml', 'r') as stream:
    try:
        d=yaml.load(stream, Loader=yaml.BaseLoader)

        for task in d[0]["tasks"]:
            
            new_ios_task = ios_task(name=task["name"], commands=task["ios_command"]["commands"])
            list_of_ios_tasks.append(new_ios_task)

    except yaml.YAMLError as error_message:
        print(error_message)

#Der erste Schritt des Sicherheitstests: Überprüfe, ob die Sicherheitskonfiguration, die keine Komplexität aufweisen, im Playbook enthalten sind.
#Iteriere durch die Liste der Sicherheitsempfehlungen.
for recommendation in list_of_cis_recommendations:
    #Iteriere durch die Liste der Playbook Tasks
    for task in list_of_ios_tasks:
	#Zunächst übernimmt die Variable "task_command" die Kommandos (Strings) des Objekts "task"
	#Danach übernimmt die Variable "recommendation_command" die Kommandos des Objekts "recommendation"
	#Für den Test wird überprüft, ob sich die Kommandos des Objekts "recommendation" innerhalb (also auch als ein Substring) der Kommandos des Objekts "task" befinden
        if any(any(recommendation_command in task_command for recommendation_command in recommendation.check_commands) for task_command in task.commands):
	    #Wenn es eine Übereinstimmung gibt, bedeutet dies, dass die Sicherheitskonfiguration in das Playbook implementiert wurde. 
            list_of_enforced_security_practices.append(recommendation)
            break

#Als nächstes wird eine Liste erstellt, die alle Objekte der Klasse cis_recommendation übernimmt, welche nicht in das Playbook implementiert wurden.
#Dies wird erreicht, indem die Liste der implementierten Objekte der Klasse cis_recommendation von der Liste aller Objekte abgezogen wird.
list_of_unenforced_security_practices = list(set(list_of_cis_recommendations) - set(list_of_enforced_security_practices))

#Als nächster Test wird durch die Liste der Objekte mit komplexen Sicherheitskonfigurationen iteriert 
for complex_cis_recommendation in list_of_complex_cis_recommendations:
#Wenn der Name der Sicherheitskonfiguration einen match erreicht, wird eine entsprechende Funktion aufgerufen, die die Überprüfung durchführt.
	match complex_cis_recommendation.name:
		case "Set 'exec-timeout' to less than or equal to 10 minutes for 'line aux 0'":
	#Wenn Sicherheitsüberprüft ein Problem identifizert, wird die Sicherheitskonfiguration als Objekt zurückgegeben und in check_result initialisiert.
			check_result = check_exec_timeout_line_aux0_10_minutes(complex_cis_recommendation, list_of_ios_tasks)
			if check_result:
	#Wenn die Variable check_result initialisiert wurde, wird die Liste der nicht-durchgesetzten Sicherheitskonfigurationen erweitert.
				list_of_unenforced_security_practices.append(check_result)
		case "Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0'":
			check_result = check_exec_timeout_line_console0_10_minutes(complex_cis_recommendation, list_of_ios_tasks)
			if check_result:
                		list_of_unenforced_security_practices.append(check_result)
		case "Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'":
			check_result = check_exec_timeout_line_vty015_10_minutes(complex_cis_recommendation, list_of_ios_tasks)
			if check_result:
				list_of_unenforced_security_practices.append(check_result)
		case "Set 'exec-timeout' less than or equal to 10 minutes 'line tty'":
			check_result = check_exec_timeout_line_tty_10_minutes(complex_cis_recommendation, list_of_ios_tasks)
			if check_result:
				list_of_unenforced_security_practices.append(check_result)
		case "Set 'transport input ssh' for 'line vty' connections":
			check_result = check_transport_input_ssh_vty015(complex_cis_recommendation, list_of_ios_tasks)
			if check_result:
				list_of_unenforced_security_practices.append(check_result)

print(r"""

                           _       _
     _____               _| |     | |
    /     |             (_) | ___ | | ___
   /  /|  |_  __   _____ _| |/ _ \| |/ _ \
  /  /_|  | \/  \ /  __/| |   (_) | |  _
 /  ___   |   _  |_\ \  |_|_|\___/|_|\__|
/__/   |__|__| |_|___/____                  _____
		     /  __\(_) _______  ___/  __/ ___  __
		    /  /   | |/  __/ _\/ _ \__  \/ _ \/ _\
		    \  \__ | |_\ \ ||_  (_) _/  /  _  ||_
 		     \____/|_|___/ \__/\___/___/ \__| \__/

		    Static Code Analysis Tool for configuring Cisco Routers
                        with Ansible cisco.ios.ios_command module


Developer: Dejan Bijelic
Codename:  Master-THM
Version:   1.0



Scanning for possible security issues...
      """)

#Wurde die Liste der nicht-durchgesetzten Sicherheitskonfigurationen initialisiert, werden die identifizierten Sicherheitsprobleme ausgegeben.
if list_of_unenforced_security_practices:
    print("The following security configurations are recommended (" + str(len(list_of_unenforced_security_practices)) + "): \n")
    for unenforced_practice in list_of_unenforced_security_practices:
        print("[Recommendation]\n" + unenforced_practice.name)
        print("[Rationale]\n" + unenforced_practice.rationale)
        print("[Impact]\n" + unenforced_practice.impact)
        print("[Remediation]\n" + unenforced_practice.remediation)
        print("[Configuration]")
        for command in unenforced_practice.configure_commands:
            print(command)
        print("\n")


else:
    print("No security issues found!")
