import subprocess
import re

class SqlInjectionLayer:
    def __init__(self, target, cookie=None):
        self.target = target
        self.cookie = cookie
    #building the main command just so it adapts to whether the target is cookies based or not
    def build_cmd(self):
        command = [
            "sqlmap", "-u", self.target,
            "--batch", "--level=2", "--risk=1", "-o",
            "--output-dir=sqlmapoutput"
        ]
        if self.cookie:
            command.append(f"--cookie={self.cookie}")
        return command
    def run_cmd(self):
        try:
            process = subprocess.Popen(self.build_cmd(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            process.kill()
            return {
                "error": "scan timed out",
                "success": False
            }
        return stdout.decode("utf-8"), stderr.decode("utf-8"), process.returncode
    def parse_output(self,output):
        scan_result = {
            "target": self.target,
            "tool": "sqlmap",
            "vulnerable": False,
            "waf_detected": False,
            "unreachable": False,
            "dbms": None,
            "vulnerabilities": []
        }
        if "connection timed out" in output or "unable to connect" in output:
            scan_result["unreachable"] = True
            return scan_result

        if "WAF" in output or "protected by" in output:
            scan_result["waf_detected"] = True
        # checking if it's vulnerable
        if "is vulnerable" in output or "injection point" in output:
            scan_result["vulnerable"] = True

        dbms_match = re.search(r"back-end DBMS:\s(.+)", output)
        if dbms_match:
            scan_result["dbms"] = dbms_match.group(1).strip()

        # extraction of information
        types = re.findall(r"Type:\s*(.+)", output)
        titles = re.findall(r"Title:\s*(.+)", output)
        payloads = re.findall(r"Payload:\s*(.+)", output)

        for type_, title, payload in zip(types, titles, payloads):
            scan_result["vulnerabilities"].append({
                "severity": "HIGH",
                "type": type_,
                "title": title,
                "payload": payload,
            })

        return scan_result

    def sqlmap(self):
        try:
            result = self.run_cmd()
            # check the instance if it's a dict, if true return the result otherwise continue
            if isinstance(result, dict):
                return result
            stdout, stderr, return_code = result
            if return_code != 0 and not stdout:
                return {"error": stderr, "success": False}
            return self.parse_output(stdout)
        except ValueError :
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


