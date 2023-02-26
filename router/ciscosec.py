import yaml

class ios_task:
    def __init__(self, name, commands):
        self.name=name
        self.commands=commands

class security_practice:
    def __init__(self, name, commands, security_message):
        self.name=name
        self.commands=commands
        self.security_message=security_message

list_of_ios_tasks = []
list_of_security_practices = []
list_of_enforced_security_practices = []

with open('security_practices.yml', 'r') as stream:
    try:
    # Convert yaml document to python object
        d=yaml.load(stream, Loader=yaml.BaseLoader)

        for sec_practice in d[0]["security_practice"]:

            new_security_practice = security_practice(name=sec_practice["name"],commands=sec_practice["ios_commands"],security_message=sec_practice["security_message"])
            list_of_security_practices.append(new_security_practice)

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


for practice in list_of_security_practices:
    for task in list_of_ios_tasks:
        if set(practice.commands).issubset(set(task.commands)):
            list_of_enforced_security_practices.append(practice)
            break

list_of_unenforced_security_practices = list(set(list_of_security_practices) - set(list_of_enforced_security_practices))


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
    print("Following security issues have been found: ")
    for unenforced_practice in list_of_unenforced_security_practices:
        print("[+] " + unenforced_practice.name + " not enforced! " + unenforced_practice.security_message )

else:
    print("No security issues found!")

