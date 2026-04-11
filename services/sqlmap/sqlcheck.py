import subprocess
import re

#step1 building the command for sqlmap
def build_cmd(target, cookie=None):
    command = [
        "sqlmap", "-u", target,
        "--batch", "--level=2", "--risk=1", "-o",
        "--output-dir=sqlmap"
    ]
    if cookie:
        command.append(f"--cookie={cookie}")
    return command
#step 2 running cmd
def run_cmd(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        process.kill()
        return {
            "error": "scan timed out",
            "success": False
        }
    return stdout.decode("utf-8"), stderr.decode("utf-8"), process.returncode
#step 3 getting the byte code and then parsing it into csv
def sqlmap(target,cookie=None):
    try:
        command = build_cmd(target, cookie)
        result = run_cmd(command)
    except ValueError as e:
        return {
            "error": "invalid arguments",
            "success": False
        }

    except FileNotFoundError:
        return {
            "error": "sqlmap is not installed",
            "success": False
        }

    except OSError as e:
        return {"error": f"OS error: {str(e)}", "success": False}

    #checks for error dictionary
    if isinstance(result, dict):
        return result
    stdout, stderr, return_code = result
    if return_code != 0 and not stdout:
        return {"error": stderr, "success": False}
    return parse_sqlmap_output(stdout, target)


def parse_sqlmap_output(output, target):
    scan_result = {
        "target": target,
        "tool": "sqlmap",
        "vulnerable": False,
        "waf_detected": False,
        "unreachable": False,
        "dbms": None,
        "vulnerabilities": []
    }
    #checking every possible security restrictions
    if "connection timed out" in output or "unable to connect" in output:
        scan_result["unreachable"] = True
        return scan_result

    if "WAF" in output or "protected by" in output:
        scan_result["waf_detected"] = True
    #checking if it's vulnerable
    if "is vulnerable" in output or "injection point" in output:
        scan_result["vulnerable"] = True

    dbms_match = re.search(r"back-end DBMS:\s(.+)", output)
    if dbms_match:
        scan_result["dbms"] = dbms_match.group(1).strip()

    #extraction of information
    types = re.findall(r"Type:\s(.+)", output)
    titles = re.findall(r"Title:\s(.+)", output)
    payloads = re.findall(r"Payload:\s(.+)", output)

    for type_, title, payload in zip(types, titles, payloads):
        scan_result["vulnerabilities"].append({
            "severity": "HIGH",
            "type": type_,
            "title": title,
            "payload": payload,
        })

    return scan_result