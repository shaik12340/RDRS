import json
from datetime import datetime
from pathlib import Path


INCIDENT_FILE = Path("data/incidents.json")


class AlertManager:

    def __init__(self):
        INCIDENT_FILE.parent.mkdir(parents=True, exist_ok=True)

    def load_incidents(self):
        if not INCIDENT_FILE.exists():
            return []

        try:
            with open(INCIDENT_FILE, "r") as file:
                return json.load(file)
        except (json.JSONDecodeError, OSError):
            return []

    def save_incidents(self, incidents):
        with open(INCIDENT_FILE, "w") as file:
            json.dump(incidents, file, indent=4)

    def create_alert(self, scan_result, risk_result):

        risk_level = risk_result["risk_level"]
        risk_score = risk_result["risk_score"]

        if risk_level == "CRITICAL":
            severity = "CRITICAL"
            message = "Possible ransomware activity detected"

        elif risk_level == "HIGH":
            severity = "HIGH"
            message = "Suspicious file activity detected"

        elif risk_level == "MEDIUM":
            severity = "MEDIUM"
            message = "Unusual file activity detected"

        else:
            severity = "LOW"
            message = "Normal file activity"

        incident = {
            "incident_id": f"RDRS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "message": message,
            "changed_files": scan_result["changed_files"],
            "new_files": scan_result["new_files"],
            "deleted_files": scan_result["deleted_files"]
        }

        incidents = self.load_incidents()
        incidents.append(incident)
        self.save_incidents(incidents)

        return incident
