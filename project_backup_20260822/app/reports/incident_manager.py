import uuid
from pathlib import Path
from datetime import datetime

from app.database.database import add_incident


class IncidentManager:

    def __init__(self):
        pass

    def create_incident(
        self,
        risk,
        event_type,
        file_path,
        file_hash,
        response_status,
        response_details=None
    ):

        timestamp = datetime.now()

        incident_id = (
            "RDRS-"
            + timestamp.strftime("%Y%m%d%H%M%S%f")
            + "-"
            + uuid.uuid4().hex[:6]
        )

        incident_status = (
            "CONTAINED"
            if response_status == "quarantined"
            else "OPEN"
        )

        path = Path(file_path)

        response = {
            "status": response_status
        }

        # Preserve containment information when available.
        if isinstance(response_details, dict):

            if response_details.get("quarantine_path"):
                response["quarantine_path"] = str(
                    response_details["quarantine_path"]
                )

            if response_details.get("original_path"):
                response["original_path"] = str(
                    response_details["original_path"]
                )

        incident = {
            "incident_id": incident_id,
            "timestamp": timestamp.isoformat(),
            "status": incident_status,
            "severity": risk["risk_level"],
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "entropy": risk.get("entropy"),
            "suspicious": risk.get("suspicious", False),
            "event_type": event_type,

            "file": {
                "name": path.name,
                "path": str(path),
                "sha256": file_hash
            },

            "risk_reasons": risk.get(
                "reasons",
                []
            ),

            "response": response
        }

        # Save to the same database used by /api/incidents.
        # add_incident() returns the existing incident when
        # the same SHA-256 hash was already recorded.
        saved_incident = add_incident(incident)

        return saved_incident
