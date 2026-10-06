from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta

app = FastAPI()

connected_pcs = {}
blocked_rules = ["facebook.com", "instagram.com"]
history_logs = []

# 90 Days Retention Limit
RETENTION_DAYS = 90

class HeartbeatData(BaseModel):
    pc_name: str
    username: str
    ip_address: str

class HistoryEntry(BaseModel):
    pc_name: str
    url: str
    title: str
    visit_time: str

def cleanup_old_history():
    global history_logs
    cutoff_date = datetime.now() - timedelta(days=RETENTION_DAYS)
    
    filtered_logs = []
    for log in history_logs:
        try:
            log_time = datetime.strptime(log["visit_time"], "%Y-%m-%d %H:%M:%S")
            if log_time >= cutoff_date:
                filtered_logs.append(log)
        except Exception:
            pass
            
    history_logs = filtered_logs

@app.get("/api/pcs")
def get_pcs():
    return list(connected_pcs.values())

@app.get("/api/rules")
def get_rules():
    return blocked_rules

@app.post("/api/heartbeat")
def receive_heartbeat(data: HeartbeatData):
    connected_pcs[data.pc_name] = {
        "pc_name": data.pc_name,
        "username": data.username,
        "ip_address": data.ip_address,
        "last_sync": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return {"status": "success"}

@app.post("/api/history")
def receive_history(entries: List[HistoryEntry]):
    for entry in entries:
        history_logs.append(entry.dict())
    
    cleanup_old_history()
    return {"status": "success", "count": len(entries)}

@app.get("/api/history")
def get_history(pc_name: Optional[str] = Query(default=None)):
    cleanup_old_history()
    
    if pc_name:
        filtered = [
            log for log in history_logs 
            if log["pc_name"].lower() == pc_name.lower()
        ]
        return filtered
    
    return history_logs
