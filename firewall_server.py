import sqlite3
from datetime import datetime, timedelta
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_db():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE)''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pc_name TEXT,
            username TEXT,
            domain TEXT,
            visited_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

connected_pcs = {}

def cleanup_old_logs():
    try:
        conn = sqlite3.connect("firewall.db")
        cursor = conn.cursor()
        ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("DELETE FROM url_history WHERE visited_at < ?", (ninety_days_ago,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Cleanup Error: {e}")

@app.post("/api/firewall/sync")
async def sync_rules(request: Request):
    data = await request.json()
    pc_name = data.get("pc_name")
    username = data.get("username")
    client_ip = request.client.host
    
    connected_pcs[pc_name] = {
        "pc_name": pc_name,
        "username": username,
        "ip_address": client_ip,
        "last_sync": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("SELECT url FROM blocked_urls")
    urls = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT ip FROM blocked_ips")
    ips = [row[0] for row in cursor.fetchall()]
    conn.close()

    return {"blocked_urls": urls, "blocked_ips": ips}

@app.post("/api/firewall/logs")
async def save_client_logs(request: Request):
    data = await request.json()
    pc_name = data.get("pc_name")
    username = data.get("username")
    domains = data.get("domains", [])

    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    for domain in domains:
        cursor.execute(
            "INSERT INTO url_history (pc_name, username, domain) VALUES (?, ?, ?)",
            (pc_name, username, domain)
        )
    conn.commit()
    conn.close()
    
    cleanup_old_logs()
    return {"status": "success"}

@app.get("/api/history/{pc_name}")
def get_pc_history(pc_name: str):
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT domain, visited_at FROM url_history WHERE pc_name = ? ORDER BY visited_at DESC LIMIT 300",
        (pc_name,)
    )
    rows = cursor.fetchall()
    conn.close()
    return {"pc_name": pc_name, "history": [{"domain": r[0], "time": r[1]} for r in rows]}

@app.get("/api/clients")
def get_clients():
    return {"clients": list(connected_pcs.values())}

@app.get("/api/rules")
def get_rules():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, url FROM blocked_urls")
    urls = [{"id": r[0], "url": r[1]} for r in cursor.fetchall()]
    cursor.execute("SELECT id, ip FROM blocked_ips")
    ips = [{"id": r[0], "ip": r[1]} for r in cursor.fetchall()]
    conn.close()
    return {"urls": urls, "ips": ips}

@app.post("/api/rules/url")
async def add_url(request: Request):
    data = await request.json()
    url = data.get("url")
    if url:
        conn = sqlite3.connect("firewall.db")
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO blocked_urls (url) VALUES (?)", (url,))
            conn.commit()
        except:
            pass
        conn.close()
    return {"status": "ok"}

@app.delete("/api/rules/url/{url_id}")
def delete_url(url_id: int):
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_urls WHERE id = ?", (url_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.post("/api/rules/ip")
async def add_ip(request: Request):
    data = await request.json()
    ip = data.get("ip")
    if ip:
        conn = sqlite3.connect("firewall.db")
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO blocked_ips (ip) VALUES (?)", (ip,))
            conn.commit()
        except:
            pass
        conn.close()
    return {"status": "ok"}

@app.delete("/api/rules/ip/{ip_id}")
def delete_ip(ip_id: int):
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE id = ?", (ip_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Master Custom Firewall Portal</title>
        <style>
            body { font-family: Arial, sans-serif; background: #0f172a; color: white; padding: 20px; }
            .container { display: flex; gap: 20px; flex-wrap: wrap; }
            .card { background: #1e293b; padding: 20px; border-radius: 8px; flex: 1; min-width: 300px; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { border: 1px solid #334155; padding: 8px; text-align: left; }
            th { background: #334155; }
            tr.clickable { cursor: pointer; }
            tr.clickable:hover { background: #334155; }
            input { padding: 8px; width: 60%; background: #0f172a; color: white; border: 1px solid #334155; border-radius: 4px; }
            button { padding: 8px 12px; background: #ef4444; color: white; border: none; cursor: pointer; border-radius: 4px; }
            .del-btn { padding: 4px 8px; background: #dc2626; font-size: 12px; }
            .modal { display:none; position:fixed; top:10%; left:20%; width:60%; background:#1e293b; padding:20px; border-radius:8px; border:2px solid #38bdf8; max-height:70vh; overflow-y:auto; z-index: 100; }
        </style>
    </head>
    <body>
        <h2>🛡️ Master Custom Firewall Portal</h2>
        <div class="container">
            <div class="card">
                <h3>📡 Connected Network PCs (Click PC for History)</h3>
                <table>
                    <thead><tr><th>PC Name</th><th>Active User</th><th>IP Address</th><th>Last Sync</th></tr></thead>
                    <tbody id="pcTable"></tbody>
                </table>
            </div>
            <div class="card">
                <h3>🌐 Domain Filtering (Blocked URLs)</h3>
                <input id="urlInput" placeholder="e.g. facebook.com">
                <button onclick="addUrl()">Block</button>
                <table>
                    <thead><tr><th>Blocked Domain</th><th>Action</th></tr></thead>
                    <tbody id="urlTable"></tbody>
                </table>
            </div>
            <div class="card">
                <h3>🚫 Network Filtering (Blocked IPs)</h3>
                <input id="ipInput" placeholder="e.g. 192.168.1.50">
                <button onclick="addIp()">Block</button>
                <table>
                    <thead><tr><th>Blocked IP</th><th>Action</th></tr></thead>
                    <tbody id="ipTable"></tbody>
                </table>
            </div>
        </div>

        <div id="historyModal" class="modal">
            <button onclick="closeModal()" style="float:right; background:#64748b;">Close</button>
            <h3 id="modalTitle">PC History</h3>
            <table>
                <thead><tr><th>Visited Domain / URL</th><th>Timestamp</th></tr></thead>
                <tbody id="historyTable"></tbody>
            </table>
        </div>

        <script>
            async function loadClients() {
                let res = await fetch('/api/clients');
                let data = await res.json();
                let tbody = document.getElementById('pcTable');
                tbody.innerHTML = '';
                data.clients.forEach(pc => {
                    tbody.innerHTML += `<tr class="clickable" onclick="showHistory('${pc.pc_name}')">
                        <td><b>${pc.pc_name}</b> 🔍</td>
                        <td>${pc.username}</td>
                        <td>${pc.ip_address}</td>
                        <td>${pc.last_sync}</td>
                    </tr>`;
                });
            }

            async function loadRules() {
                let res = await fetch('/api/rules');
                let data = await res.json();
                
                let urlTbody = document.getElementById('urlTable');
                urlTbody.innerHTML = '';
                data.urls.forEach(item => {
                    urlTbody.innerHTML += `<tr>
                        <td><b>${item.url}</b></td>
                        <td><button class="del-btn" onclick="deleteUrl(${item.id})">Unblock</button></td>
                    </tr>`;
                });

                let ipTbody = document.getElementById('ipTable');
                ipTbody.innerHTML = '';
                data.ips.forEach(item => {
                    ipTbody.innerHTML += `<tr>
                        <td><b>${item.ip}</b></td>
                        <td><button class="del-btn" onclick="deleteIp(${item.id})">Unblock</button></td>
                    </tr>`;
                });
            }

            async function showHistory(pcName) {
                document.getElementById('modalTitle').innerText = "Browsing History (Last 3 Months) - " + pcName;
                let res = await fetch('/api/history/' + pcName);
                let data = await res.json();
                let tbody = document.getElementById('historyTable');
                tbody.innerHTML = '';
                data.history.forEach(h => {
                    tbody.innerHTML += `<tr><td>${h.domain}</td><td>${h.time}</td></tr>`;
                });
                document.getElementById('historyModal').style.display = 'block';
            }

            function closeModal() { document.getElementById('historyModal').style.display = 'none'; }

            async function addUrl() {
                let url = document.getElementById('urlInput').value;
                if (!url) return;
                await fetch('/api/rules/url', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url}) });
                document.getElementById('urlInput').value = '';
                loadRules();
            }

            async function deleteUrl(id) {
                await fetch('/api/rules/url/' + id, { method: 'DELETE' });
                loadRules();
            }

            async function addIp() {
                let ip = document.getElementById('ipInput').value;
                if (!ip) return;
                await fetch('/api/rules/ip', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip}) });
                document.getElementById('ipInput').value = '';
                loadRules();
            }

            async function deleteIp(id) {
                await fetch('/api/rules/ip/' + id, { method: 'DELETE' });
                loadRules();
            }

            setInterval(loadClients, 5000);
            loadClients();
            loadRules();
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)