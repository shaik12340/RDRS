from app.api.routes import router
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
import json
import re
from passlib.context import CryptContext
from app.database.database import (
    load_users,
    get_user_by_email,
    add_user,
    update_user_password
)


from app.detectors.ransomware import RansomwareDetector
from app.detectors.risk_engine import RiskEngine
from app.reports.alert_manager import AlertManager


# ==========================================
# FASTAPI APPLICATION
# ==========================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


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
<meta name="viewport" content="width=device-width, initial-scale=1.0">

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
        radial-gradient(circle at top, #172554, #020617 65%);
    color: white;
}

.auth-container {
    width: 410px;
    max-width: 92%;
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 18px;
    padding: 32px;
    box-shadow: 0 25px 60px rgba(0,0,0,0.5);
}

.logo {
    text-align: center;
    font-size: 42px;
}

h1 {
    text-align: center;
    margin: 5px 0;
}

.subtitle {
    text-align: center;
    color: #94a3b8;
    margin-bottom: 25px;
    font-size: 14px;
}

label {
    display: block;
    margin: 12px 0 7px;
    color: #cbd5e1;
    font-size: 14px;
    font-weight: bold;
}

input {
    width: 100%;
    padding: 13px;
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
    margin-top: 20px;
    border: none;
    border-radius: 9px;
    background: #2563eb;
    color: white;
    font-weight: bold;
    cursor: pointer;
}

button:hover {
    background: #1d4ed8;
}

.secondary {
    background: #334155;
}

.secondary:hover {
    background: #475569;
}

.message {
    display: none;
    padding: 10px;
    border-radius: 8px;
    margin-bottom: 15px;
    text-align: center;
    font-size: 14px;
}

.error {
    background: #450a0a;
    color: #fca5a5;
}

.success {
    background: #052e16;
    color: #86efac;
}

.links {
    text-align: center;
    margin-top: 18px;
}

.links a {
    color: #60a5fa;
    cursor: pointer;
    text-decoration: none;
    margin: 0 8px;
}

.links a:hover {
    text-decoration: underline;
}

.panel {
    display: none;
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

<div class="auth-container">

<div id="loginPanel">

    <div class="logo">🛡️</div>

    <h1>RDRS</h1>

    <div class="subtitle">
        Ransomware Detection & Response System
    </div>

    <div id="loginMessage" class="message"></div>

    <form onsubmit="login(event)">

        <label>Email Address</label>

        <input
            id="loginEmail"
            type="email"
            placeholder="Enter your email"
            required
        >

        <label>Password</label>

        <input
            id="loginPassword"
            type="password"
            placeholder="Enter your password"
            required
        >

        <button type="submit">
            🔐 LOGIN TO RDRS
        </button>

    </form>

    <div class="links">
        <a onclick="showPanel('registerPanel')">Create Account</a>
        <a onclick="showPanel('forgotPanel')">Forgot Password?</a>
    </div>

</div>


<div id="registerPanel" class="panel">

    <div class="logo">📝</div>

    <h1>Create Account</h1>

    <div class="subtitle">
        Register for RDRS Security Dashboard
    </div>

    <div id="registerMessage" class="message"></div>

    <form onsubmit="registerUser(event)">

        <label>Email Address</label>

        <input
            id="registerEmail"
            type="email"
            placeholder="Enter your email"
            required
        >

        <label>Password</label>

        <input
            id="registerPassword"
            type="password"
            placeholder="Minimum 8 characters"
            minlength="8"
            required
        >

        <button type="submit">
            📝 CREATE ACCOUNT
        </button>

    </form>

    <button
        class="secondary"
        onclick="showPanel('loginPanel')">
        ← Back to Login
    </button>

</div>


<div id="forgotPanel" class="panel">

    <div class="logo">🔑</div>

    <h1>Forgot Password</h1>

    <div class="subtitle">
        Enter your registered email
    </div>

    <div id="forgotMessage" class="message"></div>

    <form onsubmit="forgotPassword(event)">

        <label>Email Address</label>

        <input
            id="forgotEmail"
            type="email"
            placeholder="Enter your email"
            required
        >

        <button type="submit">
            📧 RESET PASSWORD
        </button>

    </form>

    <button
        class="secondary"
        onclick="showPanel('loginPanel')">
        ← Back to Login
    </button>

</div>


<div class="status">
    ● RDRS SYSTEM ONLINE
</div>

</div>


<script>

function showPanel(panelId) {

    document
        .querySelectorAll(".panel")
        .forEach(panel => {
            panel.style.display = "none";
        });

    document.getElementById(panelId).style.display = "block";
}


function showMessage(id, message, success=false) {

    const box = document.getElementById(id);

    box.innerText = message;

    box.className =
        "message " +
        (success ? "success" : "error");

    box.style.display = "block";
}


async function login(event) {

    event.preventDefault();

    const email =
        document.getElementById("loginEmail").value;

    const password =
        document.getElementById("loginPassword").value;

    try {

        const response = await fetch(
            "/api/login",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    email,
                    password
                })
            }
        );

        const result =
            await response.json();

        if (result.success) {

            window.location.href = "/dashboard";

        } else {

            showMessage(
                "loginMessage",
                result.message
            );

        }

    } catch (error) {

        showMessage(
            "loginMessage",
            "Unable to connect to RDRS server"
        );

    }
}


async function registerUser(event) {

    event.preventDefault();

    const email =
        document.getElementById("registerEmail").value;

    const password =
        document.getElementById("registerPassword").value;

    try {

        const response = await fetch(
            "/api/register",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    email,
                    password
                })
            }
        );

        const result =
            await response.json();

        if (result.success) {

            showMessage(
                "registerMessage",
                "Account created successfully. You can now login.",
                true
            );

            document.getElementById(
                "registerEmail"
            ).value = "";

            document.getElementById(
                "registerPassword"
            ).value = "";

        } else {

            showMessage(
                "registerMessage",
                result.message
            );

        }

    } catch (error) {

        showMessage(
            "registerMessage",
            "Unable to connect to RDRS server"
        );

    }
}


async function forgotPassword(event) {

    event.preventDefault();

    const email =
        document.getElementById("forgotEmail").value;

    try {

        const response = await fetch(
            "/api/forgot-password",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    email
                })
            }
        );

        const result =
            await response.json();

        showMessage(
            "forgotMessage",
            result.message,
            result.success
        );

    } catch (error) {

        showMessage(
            "forgotMessage",
            "Unable to connect to RDRS server"
        );

    }
}

</script>

</body>

</html>
"""


@app.post("/api/register")
async def register(credentials: dict):

    email = credentials.get("email", "").strip().lower()
    password = credentials.get("password", "")

    # Email validation
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    if not re.match(email_pattern, email):
        return {
            "success": False,
            "message": "Please enter a valid email address"
        }

    # Password validation
    if len(password) < 8:
        return {
            "success": False,
            "message": "Password must contain at least 8 characters"
        }

    if len(password.encode("utf-8")) > 72:
        return {
            "success": False,
            "message": "Password must be 72 bytes or less"
        }

    # Check existing account
    if get_user_by_email(email):
        return {
            "success": False,
            "message": "An account with this email already exists"
        }

    password_hash = pwd_context.hash(password)

    add_user(
        email,
        password_hash
    )

    return {
        "success": True,
        "message": "Account created successfully"
    }


# ==========================================
# AUTH API - LOGIN
# ==========================================

@app.post("/api/login")
async def login(credentials: dict):

    email = credentials.get("email", "").strip().lower()
    password = credentials.get("password", "")

    if not email or not password:
        return {
            "success": False,
            "message": "Email and password are required"
        }

    user = get_user_by_email(email)

    if not user:
        return {
            "success": False,
            "message": "Invalid email or password"
        }

    try:

        password_valid = pwd_context.verify(
            password,
            user.get("password_hash", "")
        )

    except Exception:

        password_valid = False

    if not password_valid:
        return {
            "success": False,
            "message": "Invalid email or password"
        }

    return {
        "success": True,
        "message": "Login successful",
        "email": email
    }


# ==========================================
# AUTH API - FORGOT PASSWORD
# ==========================================

@app.post("/api/forgot-password")
async def forgot_password(credentials: dict):

    email = credentials.get("email", "").strip().lower()

    if not email:
        return {
            "success": False,
            "message": "Email is required"
        }

    user = get_user_by_email(email)

    # Do not reveal whether account exists.
    if not user:
        return {
            "success": True,
            "message": "If the email is registered, password reset instructions will be provided."
        }

    return {
        "success": True,
        "message": "Password reset request accepted."
    }


# ==========================================
# AUTH API - RESET PASSWORD
# ==========================================

@app.post("/api/reset-password")
async def reset_password(credentials: dict):

    email = credentials.get("email", "").strip().lower()
    new_password = credentials.get("new_password", "")

    if not email or not new_password:
        return {
            "success": False,
            "message": "Email and new password are required"
        }

    if len(new_password) < 8:
        return {
            "success": False,
            "message": "Password must contain at least 8 characters"
        }

    if len(new_password.encode("utf-8")) > 72:
        return {
            "success": False,
            "message": "Password must be 72 bytes or less"
        }

    user = get_user_by_email(email)

    if not user:
        return {
            "success": False,
            "message": "Account not found"
        }

    password_hash = pwd_context.hash(
        new_password
    )

    updated = update_user_password(
        email,
        password_hash
    )

    if not updated:
        return {
            "success": False,
            "message": "Unable to update password"
        }

    return {
        "success": True,
        "message": "Password updated successfully"
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
