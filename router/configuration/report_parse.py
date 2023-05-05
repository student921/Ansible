file = open("/media/sf_shared-folder/report.html", "r")

print("Nipper performed a security audit on Router R1. Following security issues have been found (details in report.html):\n")
list_of_security_issues = []
for line in file:
    if line.startswith('Nipper determined') or line.startswith('Nipper identified'):
        list_of_security_issues.append(line.replace("<br>", ""))

for security_issue in list_of_security_issues:
    print("[+] " + security_issue)


