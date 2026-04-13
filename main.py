from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional
import asyncio
from services.sqlmap.sqlcheck import SqlInjectionLayer
from services.nmap.nmap_service import PortDetectingLayer
from services.zed.zaproxy import ZapLayer
import dotenv
import os
dotenv.load_dotenv()
ZAP_KEY = os.getenv("ZAP_KEY")


app = FastAPI()
class SqlmapRequest(BaseModel):
    target: str
    cookie: Optional[str] = None

class NmapRequest(BaseModel):
    target: str
    ports: Optional[str] = None

class ZapRequest(BaseModel):
    target: str

class ScanAllRequest(BaseModel):
    target: str
    cookie: Optional[str] = None
    ports: Optional[str] = None

#cors config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
#server check
@app.get("/")
def root():
    return {"status": "running", "version": "1.0"}

# sqlmap route
@app.post("/scan/sqlmap")
def scan_sqlmap(request: SqlmapRequest):
    result = SqlInjectionLayer(request.target, request.cookie).sqlmap()
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result

# nmap route
@app.post("/scan/nmap")
def scan_nmap(request: NmapRequest):
    scanner = PortDetectingLayer(request.target,request.ports)
    result = scanner.launch_scan()
    if result is None:
        raise HTTPException(status_code=500, detail="Nmap scan failed")
    return {"target": request.target, "tool": "nmap", "results": result}

# zap route
@app.post("/scan/zap")
def scan_zap(request: ZapRequest):
    scanner = ZapLayer(request.target, ZAP_KEY)
    result = scanner.results()
    return {"target": request.target, "tool": "zap", "alerts": result}

# run all 3 tools concurrently
@app.post("/scan/all")
async def scan_all(request: ScanAllRequest):
    loop = asyncio.get_running_loop()

    # run all 3 in parallel using thread pool from the asyncio module
    sqlmap_task = loop.run_in_executor(None,SqlInjectionLayer(request.target,request.cookie).sqlmap)
    nmap_task = loop.run_in_executor(None,PortDetectingLayer(request.target,request.ports).launch_scan)
    zap_task = loop.run_in_executor(None,ZapLayer(request.target, ZAP_KEY).results)

    # wait for all 3 to finish
    sqlmap_result, nmap_result, zap_result = await asyncio.gather(
        sqlmap_task,
        nmap_task,
        zap_task
    )

    return {
        "sqlmap": sqlmap_result,
        "nmap": {"results": nmap_result},
        "zap": {"alerts": zap_result}
    }