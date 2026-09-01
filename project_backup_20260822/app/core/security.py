import hashlib
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(1024 * 1024):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (OSError, PermissionError):
        return ""
