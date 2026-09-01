
from pathlib import Path
from datetime import datetime
import hashlib
import json
import shutil


class ContainmentEngine:

    def __init__(self):
        self.quarantine_dir = Path("quarantine")
        self.log_file = Path("data/quarantine_log.json")

        self.quarantine_dir.mkdir(exist_ok=True)
        self.log_file.parent.mkdir(exist_ok=True)

        if not self.log_file.exists():
            self.log_file.write_text("[]")

    def sha256(self, file_path):

        h = hashlib.sha256()

        with open(file_path, "rb") as f:

            while True:

                chunk = f.read(4096)

                if not chunk:
                    break

                h.update(chunk)

        return h.hexdigest()

    def quarantine(
        self,
        incident_id,
        file_path,
        risk_score
    ):

        source = Path(file_path)

        if not source.exists():
            raise FileNotFoundError(source)

        checksum = self.sha256(source)

        quarantine_name = (
            f"{incident_id}_{source.name}"
        )

        destination = (
            self.quarantine_dir / quarantine_name
        )

        shutil.move(str(source), str(destination))

        record = {
            "incident_id": incident_id,
            "original_path": str(source),
            "quarantine_path": str(destination),
            "sha256": checksum,
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
            "status": "QUARANTINED"
        }

        logs = json.loads(
            self.log_file.read_text()
        )

        logs.append(record)

        self.log_file.write_text(
            json.dumps(logs, indent=4)
        )

        return record
