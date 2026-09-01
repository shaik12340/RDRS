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

    new_hash = (
        incident.get("file", {})
        .get("sha256")
    )

    # Prevent duplicate incidents for the same file hash.
    # SHA-256 identifies the file content, so the same file
    # should not create a new incident every time it is uploaded.
    if new_hash:

        for existing in incidents:

            existing_hash = (
                existing.get("file", {})
                .get("sha256")
            )

            if existing_hash == new_hash:

                return existing

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


# ==========================================
# USER AUTHENTICATION
# ==========================================

USERS_FILE = Path("data/users.json")


def load_users():

    if not USERS_FILE.exists():
        return []

    try:
        with open(USERS_FILE, "r") as file:
            data = json.load(file)

        return data if isinstance(data, list) else []

    except (json.JSONDecodeError, OSError):
        return []


def save_users(users):

    USERS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(USERS_FILE, "w") as file:
        json.dump(
            users,
            file,
            indent=4
        )


def get_user_by_email(email):

    email = email.strip().lower()

    for user in load_users():

        if user.get("email", "").lower() == email:
            return user

    return None


def add_user(email, password_hash):

    users = load_users()

    user = {
        "email": email.strip().lower(),
        "password_hash": password_hash
    }

    users.append(user)

    save_users(users)

    return user


def update_user_password(email, password_hash):

    users = load_users()

    email = email.strip().lower()

    for user in users:

        if user.get("email", "").lower() == email:

            user["password_hash"] = password_hash

            save_users(users)

            return True

    return False


# ==========================================
# PASSWORD RESET OTP
# ==========================================

def save_password_reset_otp(
    email,
    otp_hash,
    expires_at
):

    users = load_users()

    email = email.strip().lower()

    for user in users:

        if user.get("email", "").lower() == email:

            user["reset_otp_hash"] = otp_hash
            user["reset_otp_expires_at"] = expires_at
            user["reset_otp_verified"] = False

            save_users(users)

            return True

    return False


def get_password_reset_otp(email):

    email = email.strip().lower()

    user = get_user_by_email(email)

    if not user:
        return None

    return {
        "otp_hash": user.get("reset_otp_hash"),
        "expires_at": user.get("reset_otp_expires_at"),
        "verified": user.get(
            "reset_otp_verified",
            False
        )
    }


def mark_otp_verified(email):

    users = load_users()

    email = email.strip().lower()

    for user in users:

        if user.get("email", "").lower() == email:

            user["reset_otp_verified"] = True

            save_users(users)

            return True

    return False


def clear_password_reset_otp(email):

    users = load_users()

    email = email.strip().lower()

    for user in users:

        if user.get("email", "").lower() == email:

            user.pop("reset_otp_hash", None)
            user.pop("reset_otp_expires_at", None)
            user.pop("reset_otp_verified", None)

            save_users(users)

            return True

    return False
