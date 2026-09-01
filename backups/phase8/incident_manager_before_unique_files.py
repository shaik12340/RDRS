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
        """
        Create a new incident.

        This method intentionally creates a new incident.
        Use get_or_update_active_incident() when processing
        continuous activity from the same attack.
        """

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

    def get_or_update_active_incident(
        self,
        severity,
        risk_score,
        event,
        files_affected=1
    ):
        """
        Return the existing active incident when one exists.

        Otherwise create a new incident.

        Active lifecycle:
            DETECTED
            INVESTIGATING
            CONTAINED

        CLOSED incidents are not reused.
        """

        active_statuses = {
            "DETECTED",
            "INVESTIGATING",
            "CONTAINED"
        }

        # Find the latest active incident.
        for incident in reversed(self.incidents):

            if incident["status"] in active_statuses:

                # Add newly affected files.
                incident["files_affected"] += files_affected

                # Keep the highest observed risk score.
                if risk_score > incident["risk_score"]:
                    incident["risk_score"] = risk_score

                # Keep the highest severity.
                severity_rank = {
                    "LOW": 1,
                    "MEDIUM": 2,
                    "HIGH": 3,
                    "CRITICAL": 4
                }

                current_rank = severity_rank.get(
                    incident["severity"],
                    0
                )

                new_rank = severity_rank.get(
                    severity,
                    0
                )

                if new_rank > current_rank:
                    incident["severity"] = severity

                # Update event description if a new event is more severe.
                if event:
                    incident["event"] = event

                return incident

        # No active incident exists.
        return self.create_incident(
            severity=severity,
            risk_score=risk_score,
            event=event,
            files_affected=files_affected
        )

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
