import yaml

def check_exec_timeout_line_aux0_10_minutes(recommendation_object, list_of_ios_tasks):
    #Set 'exec-timeout' to less than or equal to 10 minutes for 'line aux 0'
    for task in list_of_ios_tasks:
        if "line aux 0" in task.commands:
            for command in task.commands:
                #Suche nach dem Kommando "exec-timeout"
                if "exec-timeout" in command:
                    #Extrahiere die Minuten aus "exec-timeout <minute>". Wenn dies fehlschlägt, wurde das Kommando nicht richtig umgesetzt.
                    try:
                        timeout = int(command.split()[-2])
                    except:
                        return recommendation_object
                    #Überprüfe, ob es bis zu 10 Minuten dauert, bis die Session deaktiviert wird.
                    if timeout <= 10:
                        break
                    #Ist dies nicht der Fall, kann die Sicherheitskonfiguration zurückgegeben werden.
                    else:
                        return recommendation_object
            else:
                continue
            break
    #Wenn kein "line aux 0" identifiziert wurde, bedeutet das, dass keine Konfigurationen und damit keine Sicherheitskonfigurationen vorgenommen wurden.
    else:
        return recommendation_object

def check_exec_timeout_line_console0_10_minutes(recommendation_object, list_of_ios_tasks):
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
        
        #In diesem Beispiel wird die Legacy-Konfiguration berücksichtigt, in der nicht alle VTY-Lines gleichzeitig (0 15) konfiguriert werden.
        elif "line vty 0 4" and "line vty 5 15" in task.commands:
            list_of_timeouts = []
            for command in task.commands:
                if "exec-timeout" in command:
                    try:
                        list_of_timeouts.append(int(command.split()[-2]))
                    except:
                        return recommendation_object
            #Es müssen mind. 2 Timeouts existieren, da zwei "exec-timout" Befehle vorhanden sind.
            if len(list_of_timeouts) >= 2:
                #Iteriere durch die Timouts und überprüfe, ob es jeweils bis zu 10 Minuten dauert, bis die Session deaktiviert wird. 
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
    for task in list_of_ios_tasks:
        if "line vty 0 15" in task.commands and "transport input ssh" in task.commands:
            break

        elif "line vty 0 4" and "line vty 5 15" in task.commands:
            number_of_transport_input_ssh = 0
            for command in task.commands:
                if "transport input ssh" == command:
                    number_of_transport_input_ssh = number_of_transport_input_ssh+1
            if number_of_transport_input_ssh >= 2:
                break
    else:
        return recommendation_object
