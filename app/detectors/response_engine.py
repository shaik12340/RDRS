import shutil
from pathlib import Path
from datetime import datetime


class ResponseEngine:

    def __init__(
        self,
        quarantine_directory="/home/kali/rdrs/quarantine"
    ):
        self.quarantine_directory = Path(
            quarantine_directory
        )

        self.quarantine_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def quarantine_file(self, file_path):

        source = Path(file_path)

        if not source.exists():
            return {
                "status": "error",
                "message": "File does not exist",
                "original_path": str(source)
            }

        timestamp = datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )

        destination = (
            self.quarantine_directory
            / f"{timestamp}_{source.name}"
        )

        try:

            shutil.move(
                str(source),
                str(destination)
            )

            return {
                "status": "quarantined",
                "original_path": str(source),
                "quarantine_path": str(destination)
            }

        except (OSError, shutil.Error) as error:

            return {
                "status": "error",
                "message": str(error),
                "original_path": str(source)
            }

    def respond(self, risk_level, file_path):

        if risk_level in ["HIGH", "CRITICAL"]:

            return self.quarantine_file(
                file_path
            )

        return {
            "status": "no_action",
            "message": (
                f"No containment required for "
                f"{risk_level} risk"
            )
        }
