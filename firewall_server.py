from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict
import time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-Memory Storage
blocked_urls = []
connected_pcs: Dict[str, dict] = {}
pc_history: Dict[str, list] = {}

class HeartbeatData(BaseModel):
    pc_name: str
    username: str
    ip_address: str
    history: List[str] = []

class RuleData(BaseModel):
    url: str

@app.get("/api/rules")
def get_rules():
    return {"urls": blocked_urls}

@app.post("/api/rules")
def add_rule(data: RuleData):
    if data.url not in blocked_urls:
        blocked_urls.append(data.url)
    return {"status": "success", "urls": blocked_urls}

@app.delete("/api/rules/{url}")
def delete_rule(url: str):
    if url in blocked_urls:
        blocked_urls.remove(url)
    return {"status": "success", "urls": blocked_urls}

# PC Sync & Heartbeat Endpoint
@app.post("/api/heartbeat")
def receive_heartbeat(data: HeartbeatData):
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    
    connected_pcs[data.pc_name] = {
        "pc_name": data.pc_name,
        "username": data.username,
        "ip_address": data.ip_address,
        "last_sync": current_time
    }
    
    if data.pc_name not in pc_history:
        pc_history[data.pc_name] = []
        
    for domain in data.history:
        entry = {"domain": domain, "time": current_time}
        if entry not in pc_history[data.pc_name]:
            pc_history[data.pc_name].insert(0, entry)
            
    # Keep last 50 history logs
    pc_history[data.pc_name] = pc_history[data.pc_name][:50]
    
    return {"status": "success", "urls": blocked_urls}

# Dashboard Data Endpoints
@app.get("/api/pcs")
def get_pcs():
    return list(connected_pcs.values())

@app.get("/api/history/{pc_name}")
def get_history(pc_name: str):
    return pc_history.get(pc_name, [])
