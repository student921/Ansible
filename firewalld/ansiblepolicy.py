# Program to convert yaml file to dictionary in order to check missconfigurations in Ansible Code
import yaml
import csv
from csv import DictReader

#The security policies for firewalld are maintained in a csv file. The first step is to create a class that has the attributes of possible ansible firewalld configurations.
class policy:
    def __init__(self, name='', zone='', source='', permanent='', state='', service='', port='', security_message=''):
        self.name = name
        self.zone = zone
        self.source = source
        self.permanent = permanent
        self.state = state
        self.service = service
        self.port = port
        self.security_message = security_message
        self.ruleset = {}

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


class configuration:
    def __init__(self, name=None):
        self.name = name
        self.ruleset = {}

    def set_configuration_ruleset(self, task_dictionary):

        for rule_key, rule_value in task_dictionary.items():

            self.ruleset[rule_key] = rule_value

#The second step is to create a list (list_of_policies), where the policies will be loaded into as objects.
list_of_policies = []
list_of_configurations = []

#The third step reads the csv file and initializes policy objects which include the best practice configurations that will be appended in the list_of_policies
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
                        port=row["port"],
                        security_message=row["security_message"])
        new_policy.set_policy_ruleset()
        list_of_policies.append(new_policy)

with open('/home/student921/ansible-security/workspace/firewalld/Ansible/firewalld/configure-firewalld.yml', 'r') as stream:
    try:
    # Convert yaml document to python object
        d=yaml.load(stream, Loader=yaml.BaseLoader)

        for task in d[0]["tasks"]:

            if "ansible.posix.firewalld" in task:

                #Take the values of the dictionary objects and convert them to a list, the task parameters are dictionaries themselves and are listed at the 2nd position in the list
                #f.e. ['Install Firewalld.', {'name': 'firewalld', 'state': 'latest'}]
                config = list(task.values())
                new_configuration = configuration(name=config[0])
                new_configuration.set_configuration_ruleset(config[1])
                list_of_configurations.append(new_configuration)

    except yaml.YAMLError as error_message:
        print(error_message)

#print("\n\n\n")

#for i in list_of_configurations:
    #print(i.__dict__)

#for i in list_of_policies:
    #print(i.__dict__)

#print("RULESETS OF POLICIES")
#for i in list_of_policies:
    #print(i.name)
    #print(i.ruleset)
    #print(i.security_message)

#print("\n\n\n")

#print("RULESETS OF CONFIGURATIONS")
#for i in list_of_configurations:
    #print(i.name)
    #print(i.ruleset)


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

print('Checking for possible security issues with firewall rules...')

list_of_security_issues = []

for policy in list_of_policies:

    for configuration in list_of_configurations:

        if policy.ruleset.items() <= configuration.ruleset.items():
            break

    else:
        list_of_security_issues.append(policy.security_message)

if list_of_security_issues:
    print("Ansible Policy found the following possible security isses:\n")

    for security_issue in list_of_security_issues:
        print("[-] " + security_issue)

else:
    print("No possible security issues found in firewall configuration .")

#print("\n\n")


#print(list_of_policies[2].ruleset)
#print(list_of_configurations[1].ruleset)
#print(list_of_security_issues)

