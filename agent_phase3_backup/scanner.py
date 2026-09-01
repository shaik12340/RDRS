import hashlib
import math
from pathlib import Path


def sha256_file(file_path):
    """Calculate SHA-256 hash of a file."""

    path = Path(file_path)

    if not path.is_file():
        return None

    sha256 = hashlib.sha256()

    try:
        with path.open("rb") as file:
            while True:
                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except (OSError, PermissionError):
        return None


def calculate_entropy(file_path):
    """Calculate Shannon entropy of a file."""

    path = Path(file_path)

    if not path.is_file():
        return 0.0

    try:
        with path.open("rb") as file:
            data = file.read(1024 * 1024)

        if not data:
            return 0.0

        frequency = [0] * 256

        for byte in data:
            frequency[byte] += 1

        length = len(data)
        entropy = 0.0

        for count in frequency:
            if count:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    except (OSError, PermissionError):
        return 0.0


def scan_file(file_path):
    """Return basic security information about a file."""

    path = Path(file_path)

    if not path.is_file():
        return None

    file_hash = sha256_file(path)
    entropy = calculate_entropy(path)

    return {
        "path": str(path.resolve()),
        "filename": path.name,
        "extension": path.suffix.lower(),
        "size": path.stat().st_size,
        "sha256": file_hash,
        "entropy": entropy,
    }
