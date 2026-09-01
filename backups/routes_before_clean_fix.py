from fastapi import APIRouter, UploadFile, File, HTTPException
from pathlib import Path
import hashlib
import shutil
import uuid
from datetime import datetime

from app.detectors.ransomware import RansomwareDetector
from app.detectors.response_engine import ResponseEngine
from app.database.database import add_incident, load_incidents

router = APIRouter(prefix="/api", tags=["RDRS API"])

UPLOAD_DIR = Path("/home/kali/rdrs/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

TEST_DIR = Path("/home/kali/rdrs/test_data")

detector = RansomwareDetector(str(TEST_DIR))
response_engine = ResponseEngine()


def calculate_sha256(file_path: Path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()



@router.delete("/incidents/clean")
def clean_incidents():
    incidents_file = Path("/home/kali/rdrs/data/incidents.json")

    try:
        incidents_file.write_text("[]")

        return {
            "status": "success",
            "message": "Incident history cleaned successfully"
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected"
        )

    safe_name = Path(file.filename).name

    unique_name = f"{uuid.uuid4().hex}_{safe_name}"

    destination = UPLOAD_DIR / unique_name

    try:

        # ==========================================
        # SAVE UPLOADED FILE
        # ==========================================

        with open(destination, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # ==========================================
        # RANSOMWARE ANALYSIS
        # ==========================================

        analysis = detector.analyze_file(
            str(destination)
        )

        if analysis["status"] != "success":

            destination.unlink(missing_ok=True)

            raise HTTPException(
                status_code=500,
                detail=analysis["message"]
            )

        scan = analysis["analysis"]
        file_info = analysis["file"]

        risk_score = scan["risk_score"]
        risk_level = scan["risk_level"]
        reasons = scan["reasons"]

        # ==========================================
        # CREATE INCIDENT ID
        # ==========================================

        incident_id = (
            f"RDRS-"
            f"{datetime.now().strftime('%Y%m%d%H%M%S')}-"
            f"{uuid.uuid4().hex[:6]}"
        )

        # ==========================================
        # DEFAULT RESPONSE
        # ==========================================

        response_result = {
            "status": "no_action",
            "message": f"No containment required for {risk_level} risk"
        }

        incident_status = "OPEN"

        # ==========================================
        # AUTOMATIC RESPONSE
        # ==========================================

        if risk_level in ["HIGH", "CRITICAL"]:

            response_result = response_engine.respond(
                risk_level,
                str(destination)
            )

            if response_result.get("status") == "quarantined":

                incident_status = "CONTAINED"

        # ==========================================
        # INCIDENT
        # ==========================================

        incident = {

            "incident_id": incident_id,

            "timestamp":
                datetime.now().isoformat(),

            "status":
                incident_status,

            "severity":
                risk_level,

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "event_type":
                "UPLOADED",

            "file":
                file_info,

            "risk_reasons":
                reasons,

            "analysis": {

                "entropy":
                    scan["entropy"],

                "suspicious":
                    scan["suspicious"]
            },

            "response":
                response_result
        }

        # ==========================================
        # SAVE INCIDENT TO DATABASE
        # ==========================================

        add_incident(incident)

        # ==========================================
        # FINAL RESPONSE
        # ==========================================

        return {

            "status":
                "success",

            "message":
                "File uploaded and analyzed successfully",

            "scan_result": {

                "filename":
                    safe_name,

                "size":
                    file_info["size"],

                "sha256":
                    file_info["sha256"],

                "entropy":
                    scan["entropy"],

                "risk_score":
                    risk_score,

                "risk_level":
                    risk_level,

                "suspicious":
                    scan["suspicious"],

                "risk_reasons":
                    reasons
            },

            "incident":
                incident
        }

    except HTTPException:
        raise

    except Exception as error:

        destination.unlink(
            missing_ok=True
        )

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


@router.get("/upload/test")
def upload_test():

    return {

        "status":
            "online",

        "message":
            "RDRS upload API is working"
    }


@router.post("/scan-multiple")
async def scan_multiple(files: list[UploadFile] = File(...)):

    if not files:
        raise HTTPException(
            status_code=400,
            detail="No files selected"
        )

    results = []

    for file in files:

        if not file.filename:
            continue

        safe_name = Path(file.filename).name

        unique_name = (
            f"{uuid.uuid4().hex}_{safe_name}"
        )

        destination = UPLOAD_DIR / unique_name

        try:

            with open(destination, "wb") as buffer:
                shutil.copyfileobj(
                    file.file,
                    buffer
                )

            analysis = detector.analyze_file(
                str(destination)
            )

            if analysis["status"] != "success":

                destination.unlink(
                    missing_ok=True
                )

                results.append({
                    "filename": safe_name,
                    "status": "error",
                    "message": analysis["message"]
                })

                continue

            scan = analysis["analysis"]
            file_info = analysis["file"]

            risk_level = scan["risk_level"]

            response_result = {
                "status": "no_action"
            }

            if risk_level in ["HIGH", "CRITICAL"]:

                response_result = response_engine.respond(
                    risk_level,
                    str(destination)
                )

            results.append({

                "filename": safe_name,

                "size":
                    file_info["size"],

                "sha256":
                    file_info["sha256"],

                "entropy":
                    scan["entropy"],

                "risk_score":
                    scan["risk_score"],

                "risk_level":
                    risk_level,

                "suspicious":
                    scan["suspicious"],

                "risk_reasons":
                    scan["reasons"],

                "response":
                    response_result

            })

        except Exception as error:

            destination.unlink(
                missing_ok=True
            )

            results.append({

                "filename":
                    safe_name,

                "status":
                    "error",

                "message":
                    str(error)

            })

    return {

        "status":
            "success",

        "files_scanned":
            len(results),

        "results":
            results

    }

