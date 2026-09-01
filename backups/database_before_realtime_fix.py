import json
from pathlib import Path


BASELINE_FILE = Path("data/baseline.json")
INCIDENTS_FILE = Path("data/incidents.json")


# ==========================================
# BASELINE
# ==========================================

def load_baseline():

    if not BASELINE_FILE.exists():
        return {}

    try:

        with open(BASELINE_FILE, "r") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return {}


def save_baseline(data):

    BASELINE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(BASELINE_FILE, "w") as file:

        json.dump(
            data,
            file,
            indent=4
        )


# ==========================================
# INCIDENTS
# ==========================================

def load_incidents():

    if not INCIDENTS_FILE.exists():
        return []

    try:

        with open(INCIDENTS_FILE, "r") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except (json.JSONDecodeError, OSError):

        return []


def save_incidents(incidents):

    INCIDENTS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(INCIDENTS_FILE, "w") as file:

        json.dump(
            incidents,
            file,
            indent=4
        )


def add_incident(incident):

    incidents = load_incidents()

    incidents.insert(
        0,
        incident
    )

    save_incidents(incidents)

    return incident


def get_incident(incident_id):

    incidents = load_incidents()

    for incident in incidents:

        if incident.get("incident_id") == incident_id:
            return incident

    return None


def update_incident_status(
    incident_id,
    new_status
):

    incidents = load_incidents()

    for incident in incidents:

        if incident.get("incident_id") == incident_id:

            old_status = incident.get(
                "status",
                "OPEN"
            )

            if old_status != new_status:

                history = incident.setdefault(
                    "status_history",
                    []
                )

                history.append({
                    "from": old_status,
                    "to": new_status
                })

                incident["status"] = new_status

            save_incidents(incidents)

            return incident

    return None
