import nmap

#get vulnerability status based on what nmap detected
#as open ports and then outputing it to the ui as (NORMAL,MEDIUM,HIGH,CRITICAL)
#fontend dev should use this dict to display it
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
            return nm.csv()
        else:
            nm.scan(target_address,arguments="-sV")
            return nm.csv()
    except nmap.PortScannerError:
        return None
