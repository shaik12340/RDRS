from app.api.routes import router
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
import json


from app.detectors.ransomware import RansomwareDetector
from app.detectors.risk_engine import RiskEngine
from app.reports.alert_manager import AlertManager


# ==========================================
# FASTAPI APPLICATION
# ==========================================

app = FastAPI(
    title="RDRS",
    description="Ransomware Detection and Response System",
    version="1.0.0"
)


# ==========================================
# RDRS COMPONENTS
# ==========================================

detector = RansomwareDetector(
    "/home/kali/rdrs/test_data"
)

risk_engine = RiskEngine()
alert_manager = AlertManager()


# ==========================================
# ROOT
# ==========================================

@app.get("/")
def root():

    return RedirectResponse(
        url="/login",
        status_code=302
    )



# ==========================================
# LOGIN PAGE
# ==========================================

@app.get("/login", response_class=HTMLResponse)
def login_page():

    return """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>RDRS Login</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: Arial, sans-serif;
    background:
        radial-gradient(
            circle at top,
            #172554,
            #020617 65%
        );
    color: white;
}

.login-container {
    width: 400px;
    max-width: 92%;
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 18px;
    padding: 35px;
    box-shadow:
        0 25px 60px rgba(0,0,0,0.5);
}

.logo {
    text-align: center;
    font-size: 42px;
    margin-bottom: 10px;
}

h1 {
    text-align: center;
    margin: 0;
    font-size: 28px;
}

.subtitle {
    text-align: center;
    color: #94a3b8;
    margin: 8px 0 30px;
}

label {
    display: block;
    margin-bottom: 8px;
    color: #cbd5e1;
    font-size: 14px;
    font-weight: bold;
}

input {
    width: 100%;
    padding: 13px;
    margin-bottom: 18px;
    border-radius: 9px;
    border: 1px solid #334155;
    background: #020617;
    color: white;
    outline: none;
}

input:focus {
    border-color: #2563eb;
}

button {
    width: 100%;
    padding: 13px;
    border: none;
    border-radius: 9px;
    background: #2563eb;
    color: white;
    font-weight: bold;
    font-size: 15px;
    cursor: pointer;
}

button:hover {
    background: #1d4ed8;
}

.error {
    display: none;
    background: #450a0a;
    color: #fca5a5;
    border: 1px solid #7f1d1d;
    padding: 10px;
    border-radius: 8px;
    margin-bottom: 18px;
    text-align: center;
}

.demo {
    margin-top: 25px;
    padding: 12px;
    background: #111827;
    border-radius: 8px;
    color: #94a3b8;
    font-size: 12px;
    text-align: center;
}

.status {
    text-align: center;
    margin-top: 20px;
    color: #22c55e;
    font-size: 13px;
}

</style>

</head>

<body>

<div class="login-container">

    <div class="logo">🛡️</div>

    <h1>RDRS</h1>

    <div class="subtitle">
        Ransomware Detection & Response System
    </div>

    <div id="error" class="error">
        Invalid username or password
    </div>

    <form onsubmit="login(event)">

        <label>Username</label>

        <input
            id="username"
            type="text"
            placeholder="Enter username"
            required
        >

        <label>Password</label>

        <input
            id="password"
            type="password"
            placeholder="Enter password"
            required
        >

        <button type="submit">
            🔐 LOGIN TO RDRS
        </button>

    </form>

    <div class="demo">
        Demo credentials<br>
        <strong>admin</strong> /
        <strong>rdrs123</strong>
    </div>

    <div class="status">
        ● RDRS SYSTEM ONLINE
    </div>

</div>

<script>

async function login(event) {

    event.preventDefault();

    const username =
        document.getElementById("username").value;

    const password =
        document.getElementById("password").value;

    const error =
        document.getElementById("error");

    try {

        const response = await fetch(
            "/api/login",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    username,
                    password
                })
            }
        );

        const result =
            await response.json();

        if (result.success) {

            window.location.href =
                "/dashboard";

        } else {

            error.style.display =
                "block";

        }

    } catch (e) {

        error.textContent =
            "Unable to connect to RDRS server";

        error.style.display =
            "block";
    }
}

</script>

</body>

</html>
"""


# ==========================================
# LOGIN API
# ==========================================

@app.post("/api/login")
async def login(credentials: dict):

    username = credentials.get("username", "")
    password = credentials.get("password", "")

    if username == "admin" and password == "rdrs123":

        return {
            "success": True,
            "message": "Login successful"
        }

    return {
        "success": False,
        "message": "Invalid username or password"
    }

# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": "RDRS"
    }


# ==========================================
# FILE SCAN
# ==========================================

@app.get("/scan")
def scan():

    return detector.scan()


# ==========================================
# CREATE BASELINE
# ==========================================

@app.post("/baseline")
def create_baseline():

    return detector.create_baseline()


# ==========================================
# GET ALL INCIDENTS
# ==========================================

@app.get("/api/incidents")
def get_incidents():

    incidents_file = Path("data/incidents.json")

    if not incidents_file.exists():
        return []

    try:
        with open(incidents_file, "r") as f:
            incidents = json.load(f)

        if not isinstance(incidents, list):
            return []

        # Return only unique incidents from the database.
        # Do not create or modify incident records here.
        normalized = []
        seen_ids = set()

        for incident in incidents:

            if not isinstance(incident, dict):
                continue

            incident_id = incident.get("incident_id")

            if not incident_id:
                continue

            if incident_id in seen_ids:
                continue

            seen_ids.add(incident_id)

            normalized.append(incident)

        return normalized

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):

    incident_file = (
        Path("incidents") /
        f"{incident_id}.json"
    )


    if not incident_file.exists():

        return {

            "status": "error",

            "message":
                "Incident not found",

            "incident_id":
                incident_id

        }


    try:

        with open(
            incident_file,
            "r"
        ) as f:

            incident = json.load(f)


        return incident


    except Exception as e:

        return {

            "status": "error",

            "message": str(e)

        }


# ==========================================
# SYSTEM STATUS
# ==========================================

@app.get("/api/status")
def api_status():

    incidents = []

    try:
        incidents_file = Path("data/incidents.json")

        if incidents_file.exists():
            with open(incidents_file, "r") as f:
                data = json.load(f)

            if isinstance(data, list):
                incidents = data

    except Exception:
        incidents = []

    total_incidents = len(incidents)
    open_incidents = 0
    investigating = 0
    contained = 0
    closed = 0
    critical_incidents = 0
    quarantined = 0

    for incident in incidents:

        if not isinstance(incident, dict):
            continue

        status = incident.get("status", "OPEN")

        if status == "OPEN":
            open_incidents += 1
        elif status == "INVESTIGATING":
            investigating += 1
        elif status == "CONTAINED":
            contained += 1
        elif status == "CLOSED":
            closed += 1

        if incident.get("risk_level") == "CRITICAL":
            critical_incidents += 1

        response = incident.get("response", {})

        if isinstance(response, dict):
            if response.get("status") == "quarantined":
                quarantined += 1

    return {
        "system": "RDRS",
        "status": "online",
        "version": "1.0.0",
        "monitoring_directory": "/home/kali/rdrs/test_data",
        "statistics": {
            "total_incidents": total_incidents,
            "open": open_incidents,
            "investigating": investigating,
            "contained": contained,
            "closed": closed,
            "critical": critical_incidents,
            "quarantined": quarantined
        }
    }


# ==========================================
# UPDATE INCIDENT STATUS
# ==========================================

@app.put(
    "/api/incidents/{incident_id}/status"
)
def update_incident_status(
    incident_id: str,
    status: str
):

    allowed_statuses = [

        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "CLOSED"

    ]


    status = status.upper()


    if status not in allowed_statuses:

        return {

            "status": "error",

            "message":
                "Invalid incident status",

            "allowed_statuses":
                allowed_statuses

        }


    incident_file = (
        Path("incidents") /
        f"{incident_id}.json"
    )


    if not incident_file.exists():

        return {

            "status": "error",

            "message":
                "Incident not found",

            "incident_id":
                incident_id

        }


    try:

        with open(
            incident_file,
            "r"
        ) as f:

            incident = json.load(f)


        old_status = incident.get(
            "status",
            "OPEN"
        )


        incident["status"] = status


        if "status_history" not in incident:

            incident["status_history"] = []


        incident["status_history"].append({

            "from": old_status,

            "to": status

        })


        with open(
            incident_file,
            "w"
        ) as f:

            json.dump(
                incident,
                f,
                indent=4
            )


        return {

            "status": "success",

            "incident_id":
                incident_id,

            "old_status":
                old_status,

            "new_status":
                status

        }


    except Exception as e:

        return {

            "status": "error",

            "message": str(e)

        }


# ==========================================
# DASHBOARD
# ==========================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
def dashboard():

    html_file = Path(
        "app/dashboard/templates/index.html"
    )


    if not html_file.exists():

        return """

        <h1>RDRS Dashboard Error</h1>

        <p>
        Dashboard HTML file not found.
        </p>

        """


    return html_file.read_text(
        encoding="utf-8"
    )


# ==========================================
# FAVICON
# ==========================================

@app.get("/favicon.ico")
def favicon():

    favicon_file = Path(
        "app/dashboard/static/favicon.ico"
    )


    if favicon_file.exists():

        return FileResponse(
            favicon_file
        )


    return {
        "status": "no favicon"
    }


# ==========================================
# API INFORMATION
# ==========================================

@app.get("/api")
def api_info():

    return {

        "name": "RDRS API",

        "version": "1.0.0",

        "endpoints": {

            "health":
                "GET /health",

            "scan":
                "GET /scan",

            "baseline":
                "POST /baseline",

            "incidents":
                "GET /api/incidents",

            "single_incident":
                "GET /api/incidents/{incident_id}",

            "system_status":
                "GET /api/status",

            "update_status":
                "PUT /api/incidents/{incident_id}/status",

            "dashboard":
                "GET /dashboard"

        }

    }


app.include_router(router)
