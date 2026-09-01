from pathlib import Path
from datetime import datetime
import hashlib
import json
import shutil


class RecoveryEngine:

    def __init__(self):
        self.quarantine_dir = Path("quarantine")
        self.log_file = Path("data/quarantine_log.json")

        self.quarantine_dir.mkdir(exist_ok=True)
        self.log_file.parent.mkdir(exist_ok=True)

        if not self.log_file.exists():
            self.log_file.write_text("[]")

    def _load_logs(self):
        try:
            return json.loads(self.log_file.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _save_logs(self, logs):
        self.log_file.write_text(
            json.dumps(logs, indent=4)
        )

    def sha256(self, file_path):
        path = Path(file_path)

        h = hashlib.sha256()

        with path.open("rb") as f:
            while True:
                chunk = f.read(4096)

                if not chunk:
                    break

                h.update(chunk)

        return h.hexdigest()

    def list_quarantined(self):
        logs = self._load_logs()

        results = []

        for record in logs:
            quarantine_path = Path(
                record.get("quarantine_path", "")
            )

            if quarantine_path.exists():
                current_hash = self.sha256(
                    quarantine_path
                )

                record_copy = dict(record)

                record_copy["current_sha256"] = current_hash
                record_copy["integrity"] = (
                    current_hash == record.get("sha256")
                )

                results.append(record_copy)

        return results

    def get_file(self, incident_id):
        logs = self._load_logs()

        for record in logs:
            if record.get("incident_id") == incident_id:
                return record

        return None

    def verify_integrity(self, incident_id):
        record = self.get_file(incident_id)

        if not record:
            raise FileNotFoundError(
                f"Incident not found: {incident_id}"
            )

        quarantine_path = Path(
            record["quarantine_path"]
        )

        if not quarantine_path.exists():
            raise FileNotFoundError(
                quarantine_path
            )

        original_hash = record.get("sha256")
        current_hash = self.sha256(
            quarantine_path
        )

        verified = (
            current_hash == original_hash
        )

        return {
            "incident_id": incident_id,
            "original_sha256": original_hash,
            "current_sha256": current_hash,
            "integrity": verified,
            "status": (
                "VERIFIED"
                if verified
                else "INTEGRITY_FAILED"
            )
        }

    def restore(self, incident_id):
        record = self.get_file(incident_id)

        if not record:
            raise FileNotFoundError(
                f"Incident not found: {incident_id}"
            )

        verification = self.verify_integrity(
            incident_id
        )

        if not verification["integrity"]:
            raise ValueError(
                "SHA-256 verification failed. "
                "Restore blocked."
            )

        quarantine_path = Path(
            record["quarantine_path"]
        )

        original_path = Path(
            record["original_path"]
        )

        if original_path.exists():
            raise FileExistsError(
                f"Original path already exists: "
                f"{original_path}"
            )

        original_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        shutil.move(
            str(quarantine_path),
            str(original_path)
        )

        logs = self._load_logs()

        for item in logs:
            if item.get("incident_id") == incident_id:
                item["status"] = "RESTORED"
                item["restored_at"] = (
                    datetime.now().isoformat(
                        timespec="seconds"
                    )
                )
                item["restored_sha256"] = (
                    verification["current_sha256"]
                )

        self._save_logs(logs)

        return {
            "incident_id": incident_id,
            "status": "RESTORED",
            "original_path": str(original_path),
            "quarantine_path": str(quarantine_path),
            "sha256": verification["current_sha256"],
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            )
        }

    def permanent_delete(self, incident_id):
        record = self.get_file(incident_id)

        if not record:
            raise FileNotFoundError(
                f"Incident not found: {incident_id}"
            )

        quarantine_path = Path(
            record["quarantine_path"]
        )

        if quarantine_path.exists():
            quarantine_path.unlink()

        logs = self._load_logs()

        for item in logs:
            if item.get("incident_id") == incident_id:
                item["status"] = "PERMANENTLY_DELETED"
                item["deleted_at"] = (
                    datetime.now().isoformat(
                        timespec="seconds"
                    )
                )

        self._save_logs(logs)

        return {
            "incident_id": incident_id,
            "status": "PERMANENTLY_DELETED",
            "quarantine_path": str(quarantine_path),
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            )
        }
