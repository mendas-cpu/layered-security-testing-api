

Security testing is a critical step before deploying any web application to production. Vulnerabilities like SQL injection, exposed services, and misconfigurations can lead to data breaches and system compromise.  

This project provides an automated way to scan web applications and detect common security issues using a unified API.
---

## Important
Only use it on web apps that u have authority on or has the right to do so
This project aims to provide precise testing results, however use it at ur own responsibility

---

##  Tech Stack
- **FastAPI** – Backend API framework
- **Nmap** – Network and port scanning
- **SQLMap** – SQL injection detection
- **OWASP ZAP** – Web vulnerability scanning
- **Python Asyncio** – Concurrent execution

---
## Prerequisites
- **OWASP ZAP** Installed
- **SQLMap** Installed
- **Nmap** Installed
---

## Project Structure
```markdown
│   .env
│   .gitignore
│   main.py
│   README.md
│   requirements.txt
│   
│           
├───services
   │   
   ├───nmap
   │   │   nmap_service.py
   │   
   │           
   ├───sqlmap
   │   │   sqlcheck.py
   │           
   ├───zed
       │   zaproxy.py
```
## Installation

```bash
git clone https://github.com/mendas-cpu/layered-security-testing-api.git
cd layered-security-testing-api
pip install -r requirements.txt
```

# Running the Project
```bash
uvicorn main:app --reload
java -jar "C:\Program Files\ZAP\Zed Attack Proxy\zap-2.17.0.jar" -daemon -port 8090 -config api.key=rsv5fmq01ufr3v7parvhgjgi7j
```


