from fastapi import APIRouter, UploadFile, File, HTTPException
from pathlib import Path
import hashlib
import shutil
import uuid
from datetime import datetime

from app.detectors.ransomware import RansomwareDetector
from app.detectors.response_engine import ResponseEngine
from agent.recovery import RecoveryEngine
from app.database.database import add_incident, load_incidents

router = APIRouter(prefix="/api", tags=["RDRS API"])

UPLOAD_DIR = Path("/tmp/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

TEST_DIR = Path("/tmp/test_data")

detector = RansomwareDetector(str(TEST_DIR))
response_engine = ResponseEngine()
recovery_engine = RecoveryEngine()


def calculate_sha256(file_path: Path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()



@router.delete("/incidents/clean")
def clean_incidents():
    incidents_file = Path("data/incidents.json")
    quarantine_dir = Path("/tmp/quarantine")

    deleted_uploads = 0

    try:
        # Clear incident history
        incidents_file.write_text("[]")

        # Remove files created in the RDRS upload workspace.
        # Original files on the user's computer are NOT affected.
        if UPLOAD_DIR.exists():
            for item in UPLOAD_DIR.iterdir():
                if item.is_file():
                    try:
                        item.unlink()
                        deleted_uploads += 1
                    except Exception:
                        pass

        return {
            "status": "success",
            "message": "Incident history and uploaded scan copies cleaned successfully",
            "deleted_uploads": deleted_uploads
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# QUARANTINE MANAGEMENT
# ============================================================

QUARANTINE_DIR = Path("/tmp/quarantine")


def _safe_quarantine_file(filename: str) -> Path:
    """
    Resolve a quarantine filename safely.
    Prevents path traversal outside the quarantine directory.
    """
    safe_name = Path(filename).name
    file_path = QUARANTINE_DIR / safe_name

    if safe_name != filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid quarantine filename"
        )

    return file_path


def _sha256_file(file_path: Path) -> str:
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


def _find_incident_by_quarantine_path(quarantine_path: str):
    incidents = load_incidents()

    for incident in incidents:

        response = incident.get("response", {})

        stored_path = response.get("quarantine_path")

        if stored_path == quarantine_path:
            return incident

        # Also support relative paths from older incidents.
        if stored_path:
            try:
                if Path(stored_path).resolve() == Path(
                    quarantine_path
                ).resolve():
                    return incident
            except OSError:
                pass

    return None


@router.get("/quarantine")
def list_quarantined_files():

    QUARANTINE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    files = []

    for item in sorted(
        QUARANTINE_DIR.iterdir(),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    ):

        if not item.is_file():
            continue

        try:

            stat = item.stat()

            quarantine_path = str(
                item.resolve()
            )

            incident = _find_incident_by_quarantine_path(
                quarantine_path
            )

            # Older database records may contain a relative path.
            if incident is None:
                incident = _find_incident_by_quarantine_path(
                    str(item)
                )

            response = (
                incident.get("response", {})
                if incident
                else {}
            )

            original_path = response.get(
                "original_path"
            )

            files.append({
                "filename": item.name,
                "status": "QUARANTINED",
                "quarantine_timestamp": datetime.fromtimestamp(
                    stat.st_mtime
                ).isoformat(),
                "size": stat.st_size,
                "sha256": _sha256_file(item),
                "original_path": original_path,
                "current_quarantine_path": quarantine_path,
                "incident_id": (
                    incident.get("incident_id")
                    if incident
                    else None
                ),
                "risk_level": (
                    incident.get("risk_level")
                    if incident
                    else None
                ),
                "risk_score": (
                    incident.get("risk_score")
                    if incident
                    else None
                )
            })

        except (OSError, ValueError):
            continue

    return {
        "status": "success",
        "count": len(files),
        "quarantined_files": files
    }


@router.get("/quarantine/{filename}")
def quarantine_file_details(filename: str):

    file_path = _safe_quarantine_file(filename)

    if not file_path.exists() or not file_path.is_file():

        raise HTTPException(
            status_code=404,
            detail="Quarantined file not found"
        )

    try:

        stat = file_path.stat()

        quarantine_path = str(
            file_path.resolve()
        )

        incident = _find_incident_by_quarantine_path(
            quarantine_path
        )

        if incident is None:

            incident = _find_incident_by_quarantine_path(
                str(file_path)
            )

        response = (
            incident.get("response", {})
            if incident
            else {}
        )

        return {
            "status": "success",

            "file": {
                "filename": file_path.name,

                "status": "QUARANTINED",

                "quarantine_timestamp":
                    datetime.fromtimestamp(
                        stat.st_mtime
                    ).isoformat(),

                "size":
                    stat.st_size,

                "sha256":
                    _sha256_file(file_path),

                "original_path":
                    response.get("original_path"),

                "current_quarantine_path":
                    quarantine_path
            },

            "incident": incident
        }

    except OSError as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


@router.post("/quarantine/{filename}/restore")
def restore_quarantined_file(filename: str):

    file_path = _safe_quarantine_file(filename)

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Quarantined file not found"
        )

    try:
        # ==================================================
        # PHASE 10 — RECOVERY ENGINE LOOKUP
        # ==================================================

        records = recovery_engine.list_quarantined()

        record = None

        for item in records:
            if item.get("incident_id") and (
                Path(item.get("quarantine_path", "")).resolve()
                == file_path.resolve()
            ):
                record = item
                break

        if record is None:
            raise HTTPException(
                status_code=404,
                detail="Recovery record not found"
            )

        incident_id = record["incident_id"]

        # ==================================================
        # PHASE 10 — SHA-256 VERIFICATION
        # ==================================================

        verification = recovery_engine.verify_integrity(
            incident_id
        )

        if not verification["integrity"]:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": (
                        "SHA-256 verification failed. "
                        "Restore blocked."
                    ),
                    "incident_id": incident_id,
                    "original_sha256":
                        verification["original_sha256"],
                    "current_sha256":
                        verification["current_sha256"],
                    "integrity": False
                }
            )

        # ==================================================
        # INTEGRITY PASSED → RESTORE
        # ==================================================

        result = recovery_engine.restore(
            incident_id
        )

        return {
            "status": "success",
            "message": (
                "SHA-256 verified. "
                "Integrity check passed. "
                "File restored successfully."
            ),
            "incident_id": incident_id,
            "verification": {
                "original_sha256":
                    verification["original_sha256"],
                "current_sha256":
                    verification["current_sha256"],
                "integrity":
                    verification["integrity"],
                "status":
                    verification["status"]
            },
            "restored_path":
                result["original_path"],
            "sha256":
                result["sha256"],
            "timestamp":
                result["timestamp"]
        }

    except HTTPException:
        raise

    except FileExistsError as error:
        raise HTTPException(
            status_code=409,
            detail=str(error)
        )

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error)
        )

    except ValueError as error:
        raise HTTPException(
            status_code=409,
            detail=str(error)
        )

    except OSError as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


@router.delete("/quarantine/{filename}")
def permanently_delete_quarantined_file(
    filename: str
):

    file_path = _safe_quarantine_file(filename)

    if not file_path.exists() or not file_path.is_file():

        raise HTTPException(
            status_code=404,
            detail="Quarantined file not found"
        )

    quarantine_path = str(
        file_path.resolve()
    )

    incident = _find_incident_by_quarantine_path(
        quarantine_path
    )

    if incident is None:

        incident = _find_incident_by_quarantine_path(
            str(file_path)
        )

    try:

        sha256 = _sha256_file(file_path)

        file_path.unlink()

        if incident:

            response = incident.setdefault(
                "response",
                {}
            )

            response["status"] = "deleted"

            response["deleted_timestamp"] = (
                datetime.now().isoformat()
            )

            response["deleted_sha256"] = sha256

            incident["status"] = "CLOSED"

            incidents = load_incidents()

            for index, existing in enumerate(
                incidents
            ):

                if existing.get(
                    "incident_id"
                ) == incident.get(
                    "incident_id"
                ):

                    incidents[index] = incident
                    break

            from app.database.database import save_incidents

            save_incidents(incidents)

        return {
            "status": "success",
            "message": (
                "Quarantined file permanently deleted"
            ),
            "filename": filename,
            "sha256": sha256,
            "incident_id": (
                incident.get("incident_id")
                if incident
                else None
            )
        }

    except OSError as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
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

                # Update current file location after quarantine.
                if response_result.get("quarantine_path"):

                    file_info["path"] = response_result[
                        "quarantine_path"
                    ]

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

