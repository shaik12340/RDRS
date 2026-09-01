import time
from pathlib import Path
from collections import deque

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.core.security import calculate_sha256
from app.detectors.risk_engine import RiskEngine
from app.reports.alert_manager import AlertManager
from app.detectors.response_engine import ResponseEngine
from app.reports.incident_manager import IncidentManager


class RDRSEventHandler(FileSystemEventHandler):

    def __init__(self):
        self.risk_engine = RiskEngine()
        self.alert_manager = AlertManager()
        self.response_engine = ResponseEngine()
        self.incident_manager = IncidentManager()

        self.recent_events = deque(maxlen=20)

        # Prevent duplicate watchdog events
        self.last_file_event = {}
        self.debounce_seconds = 2

        # Prevent duplicate incident creation for the same file
        self.processed_files = {}

    def process_event(self, event_type, file_path):

        path = Path(file_path)

        if not path.is_file():
            return

        # Ignore repeated watchdog events
        current_time = time.time()
        last_event_time = self.last_file_event.get(str(path), 0)

        if current_time - last_event_time < self.debounce_seconds:
            print(
                f"[RDRS] Duplicate event ignored: "
                f"{event_type} -> {file_path}"
            )
            return

        self.last_file_event[str(path)] = current_time

        # Prevent duplicate incident creation for the same file
        # during the same monitoring session.
        file_key = str(path.resolve())

        if file_key in self.processed_files:
            print(
                f"[RDRS] Duplicate incident ignored: "
                f"{event_type} -> {file_path}"
            )
            return

        self.processed_files[file_key] = current_time

        # SHA-256
        file_hash = calculate_sha256(str(path))

        if not file_hash:
            return

        # Track recent activity
        self.recent_events.append(current_time)

        recent_count = sum(
            1
            for event_time in self.recent_events
            if current_time - event_time <= 10
        )

        # 5+ events within 10 seconds = rapid activity
        rapid_changes = recent_count >= 5

        print("\n" + "=" * 50)
        print("[RDRS] FILE EVENT DETECTED")
        print("=" * 50)

        print(f"[RDRS] Event          : {event_type}")
        print(f"[RDRS] File           : {file_path}")
        print(f"[RDRS] SHA-256        : {file_hash}")
        print(f"[RDRS] Recent events  : {recent_count}")
        print(f"[RDRS] Rapid activity : {rapid_changes}")

        # ==========================================
        # SMART RISK ENGINE
        # ==========================================

        risk = self.risk_engine.calculate_score(
            changed_files=recent_count,
            rapid_changes=rapid_changes
        )

        print(
            f"[RDRS] Risk Score     : "
            f"{risk['risk_score']}/100"
        )

        print(
            f"[RDRS] Risk Level     : "
            f"{risk['risk_level']}"
        )

        print("[RDRS] Risk Reasons:")

        for reason in risk["reasons"]:
            print(f"         - {reason}")

        # ==========================================
        # ALERT
        # ==========================================

        scan_result = {
            "changed_files": [
                {
                    "path": file_path,
                    "sha256": file_hash
                }
            ],
            "new_files": [],
            "deleted_files": []
        }

        alert = self.alert_manager.create_alert(
            scan_result,
            risk
        )

        print(
            f"[RDRS] Alert          : "
            f"{alert['message']}"
        )

        # ==========================================
        # RESPONSE ENGINE
        # ==========================================

        response = self.response_engine.respond(
            risk["risk_level"],
            file_path
        )

        response_status = response.get(
            "status",
            "no_action"
        )

        print(
            f"[RDRS] Response       : "
            f"{response_status}"
        )

        if response_status == "quarantined":

            print(
                f"[RDRS] Quarantined    : "
                f"{response.get('quarantine_path', 'N/A')}"
            )

        # ==========================================
        # INCIDENT MANAGER
        # ==========================================

        incident = self.incident_manager.create_incident(
            risk=risk,
            event_type=event_type,
            file_path=file_path,
            file_hash=file_hash,
            response_status=response_status
        )

        print(
            f"[RDRS] Incident ID    : "
            f"{incident['incident_id']}"
        )

        print(
            f"[RDRS] Incident Status: "
            f"{incident['status']}"
        )

        print("=" * 50)


    # ==========================================
    # FILE MODIFIED
    # ==========================================

    def on_modified(self, event):
        # Ignore modified events to prevent duplicate incidents
        return

    # ==========================================
    # FILE CREATED
    # ==========================================

    def on_created(self, event):

        if not event.is_directory:

            self.process_event(
                "CREATED",
                event.src_path
            )





# ==========================================
# START MONITOR
# ==========================================

def start_monitor(directory):

    path = Path(directory)

    if not path.exists():
        print(f"[RDRS] Directory not found: {directory}")
        return

    event_handler = RDRSEventHandler()
    observer = Observer()

    observer.schedule(
        event_handler,
        str(path),
        recursive=True
    )

    observer.start()

    print("=" * 50)
    print("RDRS SMART REAL-TIME MONITOR")
    print("=" * 50)
    print(f"Monitoring          : {path}")
    print("Status              : ACTIVE")
    print("SHA-256             : ACTIVE")
    print("Smart Risk Engine   : ACTIVE")
    print("Alert Manager       : ACTIVE")
    print("Response Engine     : ACTIVE")
    print("Incident Manager    : ACTIVE")
    print("=" * 50)
    print("Press Ctrl+C to stop")
    print("=" * 50)

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[RDRS] Stopping monitor...")
        observer.stop()

    observer.join()
    print("[RDRS] Monitor stopped.")
