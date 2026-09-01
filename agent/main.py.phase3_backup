from pathlib import Path

from agent.config import (
    DEFAULT_FOLDERS,
    SERVER_URL,
    SUSPICIOUS_EXTENSIONS,
)
from agent.scanner import scan_file
from agent.watcher import start_watching
from agent.api_client import RDRSAPIClient


api_client = RDRSAPIClient(SERVER_URL)


def calculate_local_risk(event, file_info):

    if event == "DELETED":
        return {
            "score": 20,
            "level": "LOW"
        }

    if not file_info:
        return {
            "score": 0,
            "level": "UNKNOWN"
        }

    score = 0

    extension = file_info.get("extension", "")
    entropy = file_info.get("entropy", 0)

    # Suspicious ransomware-like extension
    if extension in SUSPICIOUS_EXTENSIONS:
        score += 50

    # High entropy indicator
    if entropy >= 7.5:
        score += 30
    elif entropy >= 7.0:
        score += 20

    if score >= 70:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level
    }


def process_event(event, path):

    print()
    print("=" * 60)
    print(f"🚨 EVENT     : {event}")
    print(f"📁 FILE      : {path}")

    file_info = None

    if event != "DELETED":
        file_info = scan_file(path)

        if file_info:
            print(f"🔐 SHA-256   : {file_info['sha256']}")
            print(f"📊 ENTROPY   : {file_info['entropy']}")
            print(f"📦 SIZE      : {file_info['size']} bytes")
            print(f"📄 EXTENSION : {file_info['extension']}")

    risk = calculate_local_risk(event, file_info)

    print(f"⚠️ RISK SCORE : {risk['score']}/100")
    print(f"🛡️ RISK LEVEL : {risk['level']}")

    event_data = {
        "agent": "RDRS Endpoint Agent",
        "event": event,
        "file": file_info,
        "risk": risk,
    }

    # Server communication will be enabled once
    # the corresponding backend endpoint is added.
    # We intentionally do not modify the existing
    # RDRS backend in this phase.

    print("=" * 60)


def main():

    print()
    print("=" * 60)
    print("🛡️ RDRS ENDPOINT AGENT")
    print("Version: 1.0.0")
    print("=" * 60)

    for folder in DEFAULT_FOLDERS:

        folder_path = Path(folder).expanduser()

        if folder_path.exists():
            print(f"📂 Configured folder: {folder_path}")
        else:
            print(f"⚠️ Folder not found: {folder_path}")

    print()
    print("ℹ️ Phase 3 agent test mode")
    print("ℹ️ Existing RDRS server is not modified.")
    print()

    # Monitor the first available default folder.
    watch_folder = None

    for folder in DEFAULT_FOLDERS:
        folder_path = Path(folder).expanduser()

        if folder_path.exists() and folder_path.is_dir():
            watch_folder = folder_path
            break

    if watch_folder is None:
        watch_folder = Path.home()

        print(f"⚠️ Default folders unavailable.")
        print(f"🟡 Using home directory: {watch_folder}")

    start_watching(
        str(watch_folder),
        process_event
    )


if __name__ == "__main__":
    main()
