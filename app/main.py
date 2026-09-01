from app.api.routes import router
from fastapi import FastAPI, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
import json
import re
import secrets
import tempfile
import shutil
from datetime import datetime, timedelta, timezone

from passlib.context import CryptContext

from app.services.email_service import send_otp_email
from app.database.database import (
    load_users,
    get_user_by_email,
    add_user,
    update_user_password,
    save_password_reset_otp,
    get_password_reset_otp,
    mark_otp_verified,
    clear_password_reset_otp
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
app.mount("/dashboard/static", StaticFiles(directory="app/dashboard/static"), name="dashboard-static")



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
        url="/dashboard",
        status_code=302
    )



# ==========================================
# AUTH API - REGISTER
# ====

# ==========================================
# AUTH API - LOGIN
# ==========================================

@app.post("/api/register")
async def register(credentials: dict):

    email = credentials.get("email", "").strip().lower()
    password = credentials.get("password", "")

    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    if not re.match(email_pattern, email):
        return {
            "success": False,
            "message": "Please enter a valid email address"
        }

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

    # Do not reveal whether an account exists.
    if not user:
        return {
            "success": True,
            "message": "If the email is registered, an OTP has been sent."
        }

    # Generate secure 6-digit OTP
    otp = f"{secrets.randbelow(1000000):06d}"

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    save_password_reset_otp(
        email,
        otp,
        expires_at.isoformat()
    )

    try:
        sent = send_otp_email(
            email,
            otp
        )

        if not sent:
            return {
                "success": False,
                "message": "Unable to send OTP email"
            }

    except Exception as e:
        print("❌ OTP email error:", e)

        return {
            "success": False,
            "message": "Unable to send OTP email"
        }

    print(f"✅ Password reset OTP sent to {email}")

    return {
        "success": True,
        "message": "OTP sent to your registered email.",
        "otp_sent": True
    }


@app.post("/api/verify-otp")
async def verify_otp(credentials: dict):

    email = credentials.get("email", "").strip().lower()
    otp = credentials.get("otp", "").strip()

    if not email or not otp:
        return {
            "success": False,
            "message": "Email and OTP are required"
        }

    if not otp.isdigit() or len(otp) != 6:
        return {
            "success": False,
            "message": "OTP must be 6 digits"
        }

    record = get_password_reset_otp(email)

    if not record:
        return {
            "success": False,
            "message": "OTP not found or expired"
        }

    expires_at = record.get("expires_at")

    try:
        expiry = datetime.fromisoformat(
            expires_at.replace("Z", "+00:00")
        )
    except Exception:
        return {
            "success": False,
            "message": "Invalid OTP record"
        }

    if datetime.now(timezone.utc) > expiry:
        clear_password_reset_otp(email)

        return {
            "success": False,
            "message": "OTP expired. Please request a new OTP."
        }

    if record.get("otp") != otp:
        return {
            "success": False,
            "message": "Invalid OTP"
        }

    mark_otp_verified(email)

    return {
        "success": True,
        "message": "OTP verified successfully"
    }


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
# FILE UPLOAD / STATIC FILE ANALYSIS
# ==========================================

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

    from app.database.database import get_incident as db_get_incident

    incident = db_get_incident(incident_id)

    if incident is None:

        return {
            "status": "error",
            "message": "Incident not found",
            "incident_id": incident_id
        }

    return incident


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
    high_incidents = 0
    medium_incidents = 0
    low_incidents = 0
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

        risk_level = str(
            incident.get("risk_level", "LOW")
        ).upper()

        if risk_level == "CRITICAL":
            critical_incidents += 1
        elif risk_level == "HIGH":
            high_incidents += 1
        elif risk_level == "MEDIUM":
            medium_incidents += 1
        else:
            low_incidents += 1

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
            "high": high_incidents,
            "medium": medium_incidents,
            "low": low_incidents,
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

    from app.database.database import (
        update_incident_status as db_update_incident_status
    )

    allowed_statuses = [
        "DETECTED",
        "INVESTIGATING",
        "CONTAINED",
        "CLOSED"
    ]

    status = status.upper()

    if status not in allowed_statuses:

        return {
            "status": "error",
            "message": "Invalid incident status",
            "allowed_statuses": allowed_statuses
        }

    try:

        incident = db_update_incident_status(
            incident_id,
            status
        )

    except ValueError as e:

        return {
            "status": "error",
            "message": str(e),
            "incident_id": incident_id
        }

    if incident is None:

        return {
            "status": "error",
            "message": "Incident not found",
            "incident_id": incident_id
        }

    return {
        "status": "success",
        "message": "Incident status updated successfully",
        "incident": incident
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
