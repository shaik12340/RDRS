from app.api.routes import router
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
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

@app.get("/", response_class=HTMLResponse)
def root():

    html_file = Path(
        "app/dashboard/templates/index.html"
    )

    if not html_file.exists():

        return """
        <h1>RDRS Dashboard Error</h1>
        <p>Dashboard HTML file not found.</p>
        """

    return html_file.read_text(
        encoding="utf-8"
    )


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

        normalized = []
        seen_ids = set()

        for incident in incidents:

            if not isinstance(incident, dict):
                continue

            incident_id = incident.get("incident_id")

            if not incident_id:
                continue

            # Remove duplicate incident IDs
            if incident_id in seen_ids:
                continue

            seen_ids.add(incident_id)

            risk_score = incident.get("risk_score", 0)
            risk_level = incident.get("risk_level", "LOW")
            status = incident.get("status", "OPEN")
            event_type = incident.get("event_type", "MODIFIED")

            file_info = incident.get("file", {})

            if not isinstance(file_info, dict):
                file_info = {}

            file_name = file_info.get("name")
            file_path = file_info.get("path")

            # Support old incident format
            changed_files = incident.get("changed_files", [])

            if not file_name and changed_files:
                first_file = changed_files[0]

                if isinstance(first_file, dict):
                    file_name = first_file.get("name")
                    file_path = first_file.get("path")

            if not file_name and file_path:
                file_name = Path(file_path).name

            if not file_name:
                file_name = "Unknown"

            analysis = incident.get("analysis", {})

            if not isinstance(analysis, dict):
                analysis = {}

            entropy = analysis.get("entropy")
            suspicious = analysis.get("suspicious", False)

            reasons = incident.get("risk_reasons")

            if not reasons:
                message = incident.get("message")

                if message:
                    reasons = [message]
                else:
                    reasons = ["No suspicious indicators"]

            response = incident.get("response", {})

            if not isinstance(response, dict):
                response = {}

            normalized.append({
                "incident_id": incident_id,
                "timestamp": incident.get("timestamp", ""),
                "status": status,
                "severity": incident.get(
                    "severity",
                    risk_level
                ),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "event_type": event_type,
                "file": {
                    "name": file_name,
                    "path": file_path,
                    "size": file_info.get("size"),
                    "sha256": file_info.get("sha256")
                },
                "analysis": {
                    "entropy": entropy,
                    "suspicious": suspicious
                },
                "risk_reasons": reasons,
                "response": {
                    "status": response.get(
                        "status",
                        "no_action"
                    )
                }
            })

        normalized.sort(
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )

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

    incident_file = Path("data/incidents.json")
    incident_dir = Path("incidents")

    total_incidents = 0
    open_incidents = 0
    investigating = 0
    contained = 0
    closed = 0
    critical_incidents = 0
    quarantined = 0


    if incident_dir.exists():

        for file in incident_dir.glob("*.json"):

            try:

                with open(file, "r") as f:

                    incident = json.load(f)


                total_incidents += 1


                status = incident.get(
                    "status",
                    "OPEN"
                )


                if status == "OPEN":

                    open_incidents += 1

                elif status == "INVESTIGATING":

                    investigating += 1

                elif status == "CONTAINED":

                    contained += 1

                elif status == "CLOSED":

                    closed += 1


                if incident.get(
                    "risk_level"
                ) == "CRITICAL":

                    critical_incidents += 1


                response = incident.get(
                    "response",
                    {}
                )


                if response.get(
                    "status"
                ) == "quarantined":

                    quarantined += 1


            except Exception:

                continue


    return {

        "system": "RDRS",

        "status": "online",

        "version": "1.0.0",

        "monitoring_directory":
            "/home/kali/rdrs/test_data",

        "statistics": {

            "total_incidents":
                total_incidents,

            "open":
                open_incidents,

            "investigating":
                investigating,

            "contained":
                contained,

            "closed":
                closed,

            "critical":
                critical_incidents,

            "quarantined":
                quarantined

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
