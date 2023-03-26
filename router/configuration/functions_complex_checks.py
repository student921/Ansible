import yaml

def check_exec_timeout_line_aux0_10_minutes(recommendation_object, list_of_ios_tasks):
    #Set 'exec-timeout' to less than or equal to 10 minutes for 'line aux 0'
    for task in list_of_ios_tasks:
        if "line aux 0" in task.commands:
            for command in task.commands:
                #if any("exec-timeout" in substring for substring in command):
                if "exec-timeout" in command:
                    #extract <minute> from exec-timeout <minute>, if it fails, the command is not set properly
                    try:
                        timeout = int(command.split()[-2])
                    except:
                        return recommendation_object
                    if timeout <= 10:
                        break
                    else:
                        return recommendation_object
            else:
                continue
            break
    #if "line aux 0" not found, return object
    else:
        return recommendation_object

def check_exec_timeout_line_console0_10_minutes(recommendation_object, list_of_ios_tasks):
    #Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0'
    for task in list_of_ios_tasks:
        if "line console 0" in task.commands:
            for command in task.commands:
                if "exec-timeout" in command:
                    try:
                        timeout = int(command.split()[-2])
                    except:
                        return recommendation_object
                    if timeout <= 10:
                        break
                    else:
                        return recommendation_object
            else:
                continue
            break
    else:
        return recommendation_object
    
def check_exec_timeout_line_vty015_10_minutes(recommendation_object, list_of_ios_tasks):
    #Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'
    for task in list_of_ios_tasks:
        if "line vty 0 15" in task.commands:
            for command in task.commands:
                if "exec-timeout" in command:
                    try:
                        timeout = int(command.split()[-2])
                    except:
                        return recommendation_object
                    if timeout <= 10:
                        break
                    else:
                        return recommendation_object
            else:
                continue
            break

        elif "line vty 0 4" and "line vty 5 15" in task.commands:
            #We create a list of timeouts since more timeouts were set
            list_of_timeouts = []
            for command in task.commands:
                if "exec-timeout" in command:
                    try:
                        list_of_timeouts.append(int(command.split()[-2]))
                    except:
                        return recommendation_object
            #There have to be at least 2 timeouts set for both line declarations
            if len(list_of_timeouts) >= 2:
                for timeout in list_of_timeouts:
                    if timeout <= 10:
                        continue
                    else:
                        return recommendation_object
                    
def check_exec_timeout_line_tty_10_minutes(recommendation_object, list_of_ios_tasks):
    #Set 'exec-timeout' to less than or equal to 10 minutes 'line tty'
    for task in list_of_ios_tasks:
        if "line tty 1" in task.commands:
            for command in task.commands:
                if "exec-timeout" in command:
                    try:
                        timeout = int(command.split()[-2])
                    except:
                        return recommendation_object
                    if timeout <= 10:
                        break
                    else:
                        return recommendation_object
            else:
                continue
            break
    else:
        return recommendation_object
    
def check_transport_input_ssh_vty015(recommendation_object, list_of_ios_tasks):
    #Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'
    for task in list_of_ios_tasks:
        if "line vty 0 15" in task.commands and "transport input ssh" in task.commands:
            break

        elif "line vty 0 4" and "line vty 5 15" in task.commands:
            #We create a list of timeouts since more timeouts were set
            number_of_transport_input_ssh = 0
            for command in task.commands:
                if "transport input ssh" == command:
                    number_of_transport_input_ssh = number_of_transport_input_ssh+1
            #There have to be at least 2 "transport input ssh set"
            if number_of_transport_input_ssh >= 2:
                break
    else:
        return recommendation_object
    
def check_input_shh(recommendation_object, list_of_ios_tasks):
    #Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'
    for task in list_of_ios_tasks:
        if "line vty 0 15" in task.commands and "transport input ssh" in task.commands:
            break

        elif "line vty 0 4" and "line vty 5 15" in task.commands:
            #We create a list of timeouts since more timeouts were set
            number_of_transport_input_ssh = 0
            for command in task.commands:
                if "transport input ssh" == command:
                    number_of_transport_input_ssh = number_of_transport_input_ssh+1
            #There have to be at least 2 "transport input ssh set"
            if number_of_transport_input_ssh >= 2:
                break
    else:
        return recommendation_object
