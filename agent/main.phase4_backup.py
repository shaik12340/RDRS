import json
from pathlib import Path

from .config import DEFAULT_FOLDERS
from .scanner import RDRSScanner
from .watcher import start_watching


scanner = RDRSScanner()


def print_scan_result(result):
    print()
    print("=" * 60)
    print("🔍 RDRS MANUAL SCAN RESULT")
    print("=" * 60)

    print(f"📁 FILE       : {result.get('file')}")
    print(f"🔐 SHA-256    : {result.get('sha256')}")
    print(f"📊 ENTROPY    : {result.get('entropy')}")
    print(f"📦 SIZE       : {result.get('size')} bytes")
    print(f"📄 EXTENSION  : {result.get('extension')}")
    print(f"⚠️ RISK SCORE : {result.get('risk_score')}/100")
    print(f"🛡️ RISK LEVEL : {result.get('risk_level')}")
    print(f"🚨 INDICATORS : {result.get('indicators')}")

    print("=" * 60)
    print()


def scan_file(file_path):
    try:
        result = scanner.scan_file(file_path)
        print_scan_result(result)
        return result

    except Exception as error:
        print(f"❌ File scan failed: {error}")
        return None


def scan_folder(folder_path):
    try:
        results = scanner.scan_folder(folder_path)

        print()
        print("=" * 60)
        print("📂 RDRS FOLDER SCAN")
        print("=" * 60)
        print(f"📁 FOLDER : {folder_path}")
        print(f"📊 FILES  : {len(results)}")
        print("=" * 60)

        for result in results:
            if "error" in result:
                print(f"⚠️ {result['file']} -> {result['error']}")
                continue

            print(
                f"{result['risk_level']:8} | "
                f"{result['risk_score']:3}/100 | "
                f"{result['file']}"
            )

        print("=" * 60)
        print()

        return results

    except Exception as error:
        print(f"❌ Folder scan failed: {error}")
        return []


def manual_scan_menu():
    while True:
        print()
        print("=" * 60)
        print("🛡️ RDRS MANUAL FILE SCANNER")
        print("=" * 60)
        print("1. Select File")
        print("2. Select Folder")
        print("3. Exit")
        print("=" * 60)

        choice = input("Enter choice: ").strip()

        if choice == "1":
            file_path = input("Enter file path: ").strip()

            if not file_path:
                print("❌ File path cannot be empty.")
                continue

            scan_file(file_path)

        elif choice == "2":
            folder_path = input("Enter folder path: ").strip()

            if not folder_path:
                print("❌ Folder path cannot be empty.")
                continue

            scan_folder(folder_path)

        elif choice == "3":
            print("👋 Exiting manual scanner.")
            break

        else:
            print("❌ Invalid choice.")


def main():
    print()
    print("=" * 60)
    print("🛡️ RDRS ENDPOINT AGENT")
    print("Version: 1.0.0")
    print("=" * 60)
    print()

    print("RDRS Agent capabilities:")
    print("  ✅ Real-time monitoring")
    print("  ✅ Manual file scanning")
    print("  ✅ Manual folder scanning")
    print("  ✅ SHA-256 analysis")
    print("  ✅ Entropy analysis")
    print("  ✅ Risk analysis")
    print()

    manual_scan_menu()


if __name__ == "__main__":
    main()
