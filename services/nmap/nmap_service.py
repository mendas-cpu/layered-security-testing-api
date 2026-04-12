import nmap
import re

#get vulnerability status based on what nmap detected
#as open ports and then outputing it to the ui as (NORMAL,MEDIUM,HIGH,CRITICAL)
#fontend dev should use this dict to display it
VULN_PATTERNS = [
    {"service": "ftp", "version": r"vsftpd 2\.3\.4", "risk": "CRITICAL", "cve": "CVE-2011-2523"},
    {"service": "ssh", "version": r"OpenSSH 5\.", "risk": "HIGH", "cve": "Multiple CVEs"},
    {"service": "http", "version": r"Apache/2\.2", "risk": "HIGH", "cve": "Outdated Apache"},
    {"service": "http", "version": r"nginx/1\.0", "risk": "MEDIUM", "cve": "Old Nginx"},
    {"service": "mysql", "version": r"5\.5", "risk": "HIGH", "cve": "Old MySQL"},
]
def detect_vulnerability(service, version, port):
    for pattern in VULN_PATTERNS:
        if service and pattern["service"] in service.lower():
            if version and re.search(pattern["version"], version):
                return {
                    "risk": pattern["risk"],
                    "cve": pattern["cve"]
                }
    # fall back to port-based severity
    return {
        "risk": get_status(port),
        "cve": None
    }


def get_status(port):
    status = {
        #receiving requests
        80:"NORMAL",
        443:"NORMAL",
        #protected is often appreciated
        22: "MEDIUM",
        8080: "MEDIUM",
        8443: "MEDIUM",
        #not supposed to be open
        21:"HIGH",
        25:"HIGH",
        53:"HIGH",
        #services or databases ports
        137:"CRITICAL",
        138:"CRITICAL",
        3306: "CRITICAL",
        5432: "CRITICAL",
        27017: "CRITICAL",
        6379: "CRITICAL",
        23: "CRITICAL",
        445: "CRITICAL"
    }
    #in case the port is not listed above it's automatically considered as MEDIUM severity
    if port not in status:
        return "MEDIUM"
    return status[port]

#launches the nmap scan, note that the scan can take a domain of ports so it's not limited to one port that's what
#gives the advantage of scanning the whole business related to the ip address
def launch_scan(target_address,target_ports=""):
    try:
        nm = nmap.PortScanner()
        if target_ports != "":
            nm.scan(target_address,target_ports,arguments="-sV")
        else:
            nm.scan(target_address,arguments="-sV")
        detected_open_ports = []
        for host in nm.all_hosts():
            for proto, ports in nm[host].items():
                if proto == 'status':
                    continue

                if not isinstance(ports, dict):
                    continue

                for port, data in ports.items():

                    if not isinstance(data, dict):
                        continue

                    service = data.get('name', '')
                    product = data.get('product', '')
                    version = data.get('version', '')

                    full_version = f"{product} {version}".strip()
                    vuln = detect_vulnerability(service, full_version, port)

                    detected_open_ports.append({
                        "host": host,
                        "port": port,
                        "state": data['state'],
                        "service": service,
                        "version": full_version,
                        "risk": vuln["risk"],
                        "cve": vuln["cve"]
                    })
        return detected_open_ports

    except nmap.PortScannerError:
        return None
