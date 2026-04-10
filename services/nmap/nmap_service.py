import nmap

#get vulnerability status based on what nmap detected
#as open ports and then outputing it to the ui as (NORMAL,MEDIUM,HIGH,CRITICAL)
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


def launch_scan(target_address,target_port=""):
    try:
        nm = nmap.PortScanner()
        nm.scan(target_address,target_port,arguments="-sV")
        return nm
    except nmap.PortScannerError:
        return None

print(launch_scan("192.168.1.1","80"))
