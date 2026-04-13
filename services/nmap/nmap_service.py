import nmap
import re
from urllib.parse import urlparse


class PortDetectingLayer:
    vulnerabilities = [
        {"service": "ftp", "version": r"vsftpd 2\.3\.4", "risk": "CRITICAL", "cve": "CVE-2011-2523"},
        {"service": "ssh", "version": r"OpenSSH 5\.", "risk": "HIGH", "cve": "Multiple CVEs"},
        {"service": "http", "version": r"Apache/2\.2", "risk": "HIGH", "cve": "Outdated Apache"},
        {"service": "http", "version": r"nginx/1\.0", "risk": "MEDIUM", "cve": "Old Nginx"},
        {"service": "mysql", "version": r"5\.5", "risk": "HIGH", "cve": "Old MySQL"}
    ]
    def __init__(self, target, port=None):
        self.target = target
        self.port = port
    def detect_vulnerability(self,service,version):
        # get vulnerability status based on what nmap detected
        # as open ports and then outputing it to the ui as (NORMAL,MEDIUM,HIGH,CRITICAL)
        # fontend dev should use this dict to display it
        for pattern in PortDetectingLayer.vulnerabilities:
            if service and pattern["service"] in service.lower():
                if version and re.search(pattern["version"], version):
                    return {
                        "risk": pattern["risk"],
                        "cve": pattern["cve"]
                    }
        #sometimes it doesn't detect the exact vuln so it automatically fall to a default severity which is "NORMAL"
        return {
            "risk": "NORMAL",
            "cve": None
        }

    # launches the nmap scan, the port can be in a form of a domain

    def launch_scan(self):
        try:
            nm = nmap.PortScanner()
            if self.port:
                nm.scan(self.extract_host(), self.port, arguments="-sV --exclude-ports 8080")
            else:
                nm.scan(self.extract_host(), arguments="-sV --exclude-ports 8080")
            detected_open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto]
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
                        vuln = self.detect_vulnerability(service, full_version)

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
        except nmap.PortScannerError as e:
            print(e)
            return []
        except Exception as e:
            print(e)
            return []

    def extract_host(self):
        parsed = urlparse(self.target)
        return parsed.hostname if parsed.hostname else self.target






