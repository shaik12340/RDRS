from datetime import datetime


class RDRSIncidentManager:

    def __init__(self):
        self.incidents = []
        self.sequence = 0

    def generate_incident_id(self):
        self.sequence += 1

        date_part = datetime.now().strftime("%Y%m%d")

        return f"RDRS-{date_part}-{self.sequence:03d}"

    def create_incident(
        self,
        severity,
        risk_score,
        event,
        files_affected=1
    ):
        incident = {
            "incident_id": self.generate_incident_id(),
            "severity": severity,
            "risk_score": risk_score,
            "event": event,
            "files_affected": files_affected,
            "status": "DETECTED",
            "created_at": datetime.now().isoformat(timespec="seconds")
        }

        self.incidents.append(incident)

        return incident

    def update_status(self, incident_id, new_status):

        valid_statuses = {
            "DETECTED",
            "INVESTIGATING",
            "CONTAINED",
            "CLOSED"
        }

        if new_status not in valid_statuses:
            raise ValueError(
                f"Invalid incident status: {new_status}"
            )

        for incident in self.incidents:

            if incident["incident_id"] == incident_id:

                incident["status"] = new_status

                return incident

        raise ValueError(
            f"Incident not found: {incident_id}"
        )

    def get_incident(self, incident_id):

        for incident in self.incidents:

            if incident["incident_id"] == incident_id:
                return incident

        return None

    def get_all_incidents(self):
        return list(self.incidents)
