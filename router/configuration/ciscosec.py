import yaml
from functions_complex_checks import *

class ios_task:
    def __init__(self, name, commands):
        self.name=name
        self.commands=commands

class cis_recommendation:
    def __init__(self, name, rationale, impact, remediation, configure_commands, check_commands=''):
        self.name=name
        self.rationale=rationale
        self.impact=impact
        self.remediation=remediation
        self.configure_commands=configure_commands
        self.check_commands=check_commands


list_of_cis_recommendations = []
list_of_complex_cis_recommendations = []
list_of_ios_tasks = []
list_of_enforced_security_practices = []

#Initialize cis recommendations that don't fullfill complexity
with open('cis_controls_v7v8_ig1.yml', 'r') as stream:
    try:
    # Convert yaml document to python object
        d=yaml.load(stream, Loader=yaml.BaseLoader)

        for recommendation in d[0]["recommendations"]:
            if recommendation["complex"] == "False":
                new_security_recommendation = cis_recommendation(name=recommendation["name"], 
                                                                    rationale=recommendation["rationale"], 
                                                                    impact=recommendation["impact"],
                                                                    remediation=recommendation["remediation"],
                                                                    configure_commands=recommendation["configure_commands"], 
                                                                    check_commands=recommendation["check_commands"])
                
                list_of_cis_recommendations.append(new_security_recommendation)

    except yaml.YAMLError as error_message:
        print(error_message)

#Initialize cis recommendations that fullfill complexity
with open('cis_controls_v7v8_ig1.yml', 'r') as stream:
    try:
    # Convert yaml document to python object
        d=yaml.load(stream, Loader=yaml.BaseLoader)

        for recommendation in d[0]["recommendations"]:
            if recommendation["complex"] == "True":
                new_security_recommendation = cis_recommendation(name=recommendation["name"], 
                                                                    rationale=recommendation["rationale"], 
                                                                    impact=recommendation["impact"], 
                                                                    remediation=recommendation["remediation"],
                                                                    configure_commands=recommendation["configure_commands"])
                
                list_of_complex_cis_recommendations.append(new_security_recommendation)

    except yaml.YAMLError as error_message:
        print(error_message)

with open('configure_router.yml', 'r') as stream:
    try:
    # Convert yaml document to python object
        d=yaml.load(stream, Loader=yaml.BaseLoader)

        for task in d[0]["tasks"]:
            
            new_ios_task = ios_task(name=task["name"], commands=task["ios_command"]["commands"])
            list_of_ios_tasks.append(new_ios_task)

    except yaml.YAMLError as error_message:
        print(error_message)

#Do the check of cis recommendations that fulfill no complexity
for recommendation in list_of_cis_recommendations:
    for task in list_of_ios_tasks:
        if any(any(recommendation_command in task_command for recommendation_command in recommendation.check_commands) for task_command in task.commands):
            list_of_enforced_security_practices.append(recommendation)
            break


list_of_unenforced_security_practices = list(set(list_of_cis_recommendations) - set(list_of_enforced_security_practices))

#Do the check of cis recommendations that fullfill complexity
for complex_cis_recommendation in list_of_complex_cis_recommendations:
    match complex_cis_recommendation.name:
        case "Set 'exec-timeout' to less than or equal to 10 minutes for 'line aux 0'":
            #Return the object, if the check fails
            check_result = check_exec_timeout_line_aux0_10_minutes(complex_cis_recommendation, list_of_ios_tasks)
            if check_result:
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
