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
            "affected_files": [],
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

    def get_or_update_active_incident(
        self,
        severity,
        risk_score,
        event,
        file_path=None,
        files_affected=1
    ):
        """
        Reuse the current active incident and track
        unique affected files.
        """

        active_statuses = {
            "DETECTED",
            "INVESTIGATING",
            "CONTAINED"
        }

        active_incident = None

        for incident in self.incidents:
            if incident["status"] in active_statuses:
                active_incident = incident
                break

        if active_incident is None:
            active_incident = self.create_incident(
                severity=severity,
                risk_score=risk_score,
                event=event,
                files_affected=0
            )

        # Make sure older incidents also have this field.
        if "affected_files" not in active_incident:
            active_incident["affected_files"] = []

        # Track only unique file paths.
        if file_path and file_path not in active_incident["affected_files"]:
            active_incident["affected_files"].append(file_path)

        # Keep count synchronized with unique files.
        if active_incident["affected_files"]:
            active_incident["files_affected"] = len(
                active_incident["affected_files"]
            )
        elif files_affected:
            active_incident["files_affected"] = files_affected

        # Preserve the highest severity/risk observed.
        severity_rank = {
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 2,
            "CRITICAL": 3
        }

        current_rank = severity_rank.get(
            active_incident["severity"], 0
        )

        new_rank = severity_rank.get(
            severity, 0
        )

        if new_rank > current_rank:
            active_incident["severity"] = severity

        if risk_score > active_incident["risk_score"]:
            active_incident["risk_score"] = risk_score

        return active_incident


    def update_status(self, incident_id, new_status):

        lifecycle = {
            "DETECTED": "INVESTIGATING",
            "INVESTIGATING": "CONTAINED",
            "CONTAINED": "CLOSED"
        }

        for incident in self.incidents:

            if incident["incident_id"] == incident_id:

                current_status = incident["status"]

                # Already closed incidents cannot change state.
                if current_status == "CLOSED":
                    raise ValueError(
                        "Closed incidents cannot be updated."
                    )

                expected_status = lifecycle.get(current_status)

                if new_status != expected_status:
                    raise ValueError(
                        f"Invalid lifecycle transition: "
                        f"{current_status} -> {new_status}. "
                        f"Expected: {expected_status}"
                    )

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
