import nmap
import requests
import socket
import subprocess
import sys
import webbrowser

# Etape 1: Detection des appareils sur le reseau
def scan_devices(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
    devices_list = []
    for host in nm.all_hosts():
        devices_list.append({"ip": host, "mac": nm[host]['addresses']['mac']})
    return devices_list

# Etape 2: Scan des ports
def scan_ports(ip):
    open_ports = []
    try:
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
    except KeyboardInterrupt:
        print("Exiting scan...")
        sys.exit()
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("Couldn't connect to server.")
        sys.exit()
    return open_ports

# Etape 3: Analyse des services
def analyze_services(devices_list):
    for device in devices_list:
        try:
            response = requests.get(f"http://{device['ip']}")
            if response.status_code == 200:
                print(f"Device {device['ip']} is running a web server")
        except requests.ConnectionError:
            pass

# Etape 4: Scan des vulnérabilités web
def scan_web_vulnerabilities(url):
    # Scan de vulnérabilités SQL Injection
    payload = "'"
    response = requests.get(url + "/search?id=" + payload)
    if "error in your SQL syntax" in response.text:
        print("Vulnerability found: SQL Injection")
        webbrowser.open("https://example.com/sql-injection-article")

    # Scan de vulnérabilités Command Injection
    command = "ls"
    response = requests.get(url + "/search?command=" + command)
    if "ls: command not found" in response.text:
        print("Vulnerability found: Command Injection")
        webbrowser.open("https://example.com/command-injection-article")

    # Analyse des en-têtes HTTP
    response = requests.get(url)
    headers = response.headers
    if "X-Frame-Options" not in headers:
        print("Missing security header: X-Frame-Options")
        webbrowser.open("https://example.com/x-frame-options-article")

# Etape 5: Gestion des vulnérabilités
def manage_vulnerabilities(vulnerabilities):
    for vulnerability in vulnerabilities:
        if vulnerability == "SQL Injection":
            print("Suggested remediation: Use prepared statements in your SQL queries.")
        elif vulnerability == "Command Injection":
            print("Suggested remediation: Sanitize and validate all user inputs.")
        elif vulnerability == "Missing X-Frame-Options":
            print("Suggested remediation: Add X-Frame-Options header to your HTTP responses.")
        else:
            print(f"Suggested remediation for {vulnerability}: Update to the latest version or apply specific patch.")

# Etape 7: Automatisation des correctifs (à compléter)
def apply_remediations(vulnerabilities):
    for vulnerability in vulnerabilities:
        if vulnerability == "SQL Injection":
            # Exemple d'utilisation d'Ansible pour appliquer un correctif
            subprocess.run(["ansible-playbook", "sql_injection_fix.yml"])
        elif vulnerability == "Command Injection":
            # Exemple d'utilisation d'Ansible pour appliquer un correctif
            subprocess.run(["ansible-playbook", "command_injection_fix.yml"])
        # Ajouter d'autres conditions pour d'autres vulnérabilités

# Exemple d'utilisation
if __name__ == "__main__":
    ip_range = "192.168.1.1/24"
    devices_list = scan_devices(ip_range)
    analyze_services(devices_list)
    # Ajoutez une URL valide pour tester les vulnérabilités web
    url = "http://bourama.com"
    scan_web_vulnerabilities(url)
