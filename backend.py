from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import socket
import threading
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Try to use python-dotenv if available, otherwise fall back to a simple .env parser
import importlib

try:
    dotenv_mod = importlib.import_module("dotenv")
    load_dotenv = getattr(dotenv_mod, "load_dotenv")
    _have_dotenv = True
except Exception:
    _have_dotenv = False

import os

if _have_dotenv:
    load_dotenv()
else:
    # Simple .env loader: read KEY=VALUE lines and export to os.environ
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k not in os.environ:
                        os.environ[k] = v

VT_API_KEY = os.getenv("VT_API_KEY")   # ← ←  API KEY  

VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"


# =========================================================
# 🔹 SECTION 1 — IP LOOKUP
@app.route("/ipinfo", methods=["POST"])
def ipinfo():
    data = request.json
    ip = data.get("ip")

    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url).json()
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)})


# =========================================================
# 🔹 SECTION 2 — URL STATUS CHECK (عادي)
@app.route("/scanurl", methods=["POST"])
def scanurl():
    data = request.json
    url = data.get("url")
    try:
        r = requests.get(url, timeout=5)
        return jsonify({"status_code": r.status_code, "ok": r.ok})
    except Exception as e:
        return jsonify({"error": str(e)})


# =========================================================
# 🔹 SECTION 3 — PORT SCANNER
ports_to_scan = [21,22,23,25,53,80,110,139,143,443,445,3306,3389]

def scan_port(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ip, port))
        return True
    except:
        return False

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target")
    result = {}

    for port in ports_to_scan:
        result[port] = "OPEN" if scan_port(target, port) else "CLOSED"

    return jsonify(result)


# =========================================================
# 🔹 SECTION 4 — HONEYPOT ATTACK MONITOR
logs = []

def honeypot_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 2222))
    server.listen(5)
    print("[HONEYPOT] Listening on port 2222...")

    while True:
        client_socket, addr = server.accept()
        try:
            data = client_socket.recv(1024).decode(errors="ignore")
        except:
            data = ""

        logs.append({
            "ip": addr[0],
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "port": 2222,
            "event": f"Connection attempt | Data: {data}"
        })

        client_socket.close()

@app.route("/get_logs", methods=["GET"])
def get_logs():
    return jsonify(logs)

@app.route("/clear_logs", methods=["GET"])
def clear_logs():
    logs.clear()
    return jsonify({"msg": "Logs cleared"})


# =========================================================
# 🔹 SECTION 5 — VirusTotal URL Scan (حقيقي مع اضافة API KEY)
@app.route("/vt_url", methods=["POST"])
def vt_url():
    data = request.json
    url_to_scan = data.get("url")

    headers = {
        "x-apikey": VT_API_KEY
    }

    payload = {"url": url_to_scan}

    try:
        vt_response = requests.post(VT_URL_SCAN_URL, headers=headers, data=payload)
        return jsonify(vt_response.json())
    except Exception as e:
        return jsonify({"error": str(e)})


# =========================================================
# 🔹 SECTION 6 — VirusTotal File Scan (حقيقي)
@app.route("/vt_file", methods=["POST"])
def vt_file():
    try:
        uploaded_file = request.files["file"]

        headers = {
            "x-apikey": VT_API_KEY
        }

        files = {
            "file": (uploaded_file.filename, uploaded_file.read())
        }

        vt_response = requests.post(VT_FILE_SCAN_URL, headers=headers, files=files)
        return jsonify(vt_response.json())

    except Exception as e:
        return jsonify({"error": str(e)})


# =========================================================
# 🔹 START BACKEND SERVER + HONEYPOT THREAD
if __name__ == "__main__":
    listener = threading.Thread(target=honeypot_listener)
    listener.daemon = True
    listener.start()

    app.run(port=5000)