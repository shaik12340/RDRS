from pathlib import Path

from agent.config import DEFAULT_FOLDERS
from agent.scanner import RDRSScanner
from agent.watcher import start_watching
from agent.detection_engine import RDRSDetectionEngine
from agent.risk_engine import RDRSRiskEngine
from agent.containment import ContainmentEngine
from agent.incident_manager import RDRSIncidentManager


scanner = RDRSScanner()

detection_engine = RDRSDetectionEngine(
    window_seconds=10,
    medium_threshold=5,
    high_threshold=10,
    critical_threshold=25
)

risk_engine = RDRSRiskEngine()
containment_engine = ContainmentEngine()

incident_manager = RDRSIncidentManager()


def print_file_result(result):
    print()
    print("=" * 70)
    print("🛡️ RDRS FILE SCAN RESULT")
    print("=" * 70)

    print("📁 FILE       :", result.get("file"))
    print("📄 FILENAME   :", result.get("filename"))
    print("📦 SIZE       :", result.get("size"), "bytes")
    print("📄 EXTENSION  :", result.get("extension"))
    print("🔐 SHA-256    :", result.get("sha256"))
    print("📊 ENTROPY    :", result.get("entropy"))
    print("⚠️ RISK SCORE :", result.get("risk_score"), "/100")
    print("🛡️ RISK LEVEL :", result.get("risk_level"))
    print("🚨 INDICATORS :", result.get("indicators"))

    print("=" * 70)
    print()


def scan_file():
    file_path = input(
        "Enter full file path: "
    ).strip()

    if not file_path:
        print("❌ No file path entered.")
        return

    try:
        result = scanner.scan_file(file_path)
        print_file_result(result)

    except FileNotFoundError:
        print("❌ File not found.")

    except ValueError as error:
        print(f"❌ {error}")

    except PermissionError:
        print("❌ Permission denied.")

    except OSError as error:
        print(f"❌ Unable to read file: {error}")


def scan_folder():
    folder_path = input(
        "Enter full folder path: "
    ).strip()

    if not folder_path:
        print("❌ No folder path entered.")
        return

    try:
        folder = Path(folder_path).expanduser().resolve()

        if not folder.exists():
            print(f"❌ Folder not found: {folder}")
            return

        if not folder.is_dir():
            print(f"❌ Not a directory: {folder}")
            return

        print()
        print("=" * 70)
        print("🛡️ RDRS FOLDER SCAN")
        print("=" * 70)
        print("📁 FOLDER :", folder)
        print("🔍 Scanning files...")
        print("=" * 70)

        results = scanner.scan_folder(str(folder))

        if not results:
            print("ℹ️ No files found.")
            return

        low = 0
        medium = 0
        high = 0
        critical = 0
        errors = 0

        for result in results:

            if "error" in result:
                errors += 1
                print(
                    f"ERROR    | {result['file']} | "
                    f"{result['error']}"
                )
                continue

            level = result["risk_level"]

            if level == "LOW":
                low += 1
            elif level == "MEDIUM":
                medium += 1
            elif level == "HIGH":
                high += 1
            elif level == "CRITICAL":
                critical += 1

            print(
                f"{level:<8} | "
                f"{result['risk_score']:>3}/100 | "
                f"{result['file']}"
            )

        print()
        print("=" * 70)
        print("📊 SCAN SUMMARY")
        print("=" * 70)
        print("🟢 LOW      :", low)
        print("🟡 MEDIUM   :", medium)
        print("🟠 HIGH     :", high)
        print("🔴 CRITICAL :", critical)
        print("⚠️ ERRORS   :", errors)
        print("📁 TOTAL    :", len(results))
        print("=" * 70)
        print()

    except PermissionError:
        print("❌ Permission denied.")

    except OSError as error:
        print(f"❌ Unable to scan folder: {error}")


def process_event(event_type, file_path):

    print()
    print("=" * 70)
    print("🚨 REAL-TIME EVENT")
    print("=" * 70)
    print("EVENT :", event_type)
    print("FILE  :", file_path)

    # Phase 6: record filesystem activity
    activity = detection_engine.record_event(
        event_type,
        file_path
    )

    print()
    print("🧠 DETECTION ENGINE")
    print("WINDOW       :", activity["window_seconds"], "seconds")
    print("EVENT COUNT  :", activity["event_count"])
    print("MODIFIED     :", activity["modified_count"])
    print("CREATED      :", activity["created_count"])
    print("DELETED      :", activity["deleted_count"])
    print("MOVED        :", activity["moved_count"])
    print("RAPID SCORE  :", activity["rapid_score"], "/40")
    print("RAPID LEVEL  :", activity["rapid_level"])

    try:
        result = scanner.scan_file(file_path)

        # Phase 7: combine scanner signals with rapid activity
        components = result["risk_components"]

        final_risk = risk_engine.calculate_score(
            entropy_score=components["entropy"],
            extension_score=components["extension"],
            filename_score=components["filename"],
            rapid_score=activity["rapid_score"],
            activity_score=0,
            other_score=0
        )

        print()
        print("🔍 FILE ANALYSIS")
        print("SHA-256      :", result["sha256"])
        print("ENTROPY      :", result["entropy"])
        print("SIZE         :", result["size"], "bytes")
        print("EXTENSION    :", result["extension"])
        print("INDICATORS   :", result["indicators"])

        print()
        print("📊 FINAL RISK ENGINE")
        print("ENTROPY SCORE :", final_risk["components"]["entropy"])
        print("EXTENSION     :", final_risk["components"]["extension"])
        print("FILENAME      :", final_risk["components"]["filename"])
        print("RAPID CHANGES :", final_risk["components"]["rapid_changes"])
        print("FILE ACTIVITY :", final_risk["components"]["file_activity"])
        print("OTHER         :", final_risk["components"]["other_indicators"])
        print("──────────────────────────────────────────────")
        print("FINAL SCORE   :", final_risk["risk_score"], "/100")
        print("FINAL LEVEL   :", final_risk["risk_level"])
        print("ACTION        :", final_risk["action"])

        # Phase 8: automatically create an incident
        # for suspicious activity (MEDIUM/HIGH/CRITICAL).
        if final_risk["risk_level"] in {
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        }:

            incident_event = "Suspicious File Activity"

            if activity["rapid_level"] in {
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            }:
                incident_event = "Rapid File Modification"

            # Phase 8: aggregate events into one active incident.
            incident = incident_manager.get_or_update_active_incident(
                severity=final_risk["risk_level"],
                risk_score=final_risk["risk_score"],
                event=incident_event,
                file_path=file_path,
                files_affected=1
            )

            print()
            print("🚨 INCIDENT CREATED")
            print("INCIDENT ID   :", incident["incident_id"])
            print("SEVERITY      :", incident["severity"])
            print("RISK SCORE    :", incident["risk_score"])
            print("EVENT         :", incident["event"])
            print("FILES AFFECTED:", incident["files_affected"])
            print("STATUS        :", incident["status"])
            print("CREATED AT    :", incident["created_at"])

            # Phase 9: automatic containment for HIGH/CRITICAL activity.
            if final_risk["risk_level"] in {
                "HIGH",
                "CRITICAL"
            }:

                print()
                print("🛡️ PHASE 9 — CONTAINMENT TRIGGERED")
                print("CONTAINMENT LEVEL :", final_risk["risk_level"])

                containment_result = containment_engine.quarantine(
                    incident_id=incident["incident_id"],
                    file_path=file_path,
                    risk_score=final_risk["risk_score"]
                )

                print("CONTAINMENT STATUS :", containment_result.get("status"))
                print("ORIGINAL PATH      :", containment_result.get("original_path"))
                print("QUARANTINE PATH    :", containment_result.get("quarantine_path"))
                print("SHA-256            :", containment_result.get("sha256"))
                print("TIMESTAMP          :", containment_result.get("timestamp"))
                print("INCIDENT ID        :", containment_result.get("incident_id"))
                print("RISK SCORE         :", containment_result.get("risk_score"))

    except (FileNotFoundError, ValueError, PermissionError, OSError):

        if event_type == "DELETED":
            print()
            print("ℹ️ File no longer exists.")
        else:
            print()
            print("⚠️ File could not be analyzed.")

    print("=" * 70)

def start_monitoring():
    folder = input(
        "Enter folder to monitor: "
    ).strip()

    if not folder:
        print("❌ No folder entered.")
        return

    folder_path = Path(folder).expanduser().resolve()

    if not folder_path.exists():
        print("❌ Folder does not exist.")
        return

    if not folder_path.is_dir():
        print("❌ Path is not a directory.")
        return

    start_watching(
        str(folder_path),
        process_event
    )


def show_menu():

    while True:

        print()
        print("=" * 70)
        print("🛡️ RDRS ENDPOINT AGENT")
        print("Computer File Security Scanner")
        print("=" * 70)

        print("1. 📄 Select File")
        print("2. 📁 Select Folder")
        print("3. 👁️ Monitor Folder")
        print("4. 🚪 Exit")

        print("=" * 70)

        choice = input("Enter choice: ").strip()

        if choice == "1":
            scan_file()

        elif choice == "2":
            scan_folder()

        elif choice == "3":
            start_monitoring()

        elif choice == "4":
            print()
            print("🛑 RDRS Agent stopped.")
            break

        else:
            print("❌ Invalid choice.")


def main():

    print()
    print("=" * 70)
    print("🛡️ RDRS ENDPOINT AGENT")
    print("Version: 1.0.0")
    print("=" * 70)

    print()
    print("Agent capabilities:")
    print("  ✅ Computer file scanning")
    print("  ✅ Computer folder scanning")
    print("  ✅ SHA-256 analysis")
    print("  ✅ Entropy analysis")
    print("  ✅ Filename analysis")
    print("  ✅ Extension analysis")
    print("  ✅ Risk analysis")
    print("  ✅ Real-time folder monitoring")
    print()

    show_menu()


if __name__ == "__main__":
    main()
