import os
import math
import re
from pathlib import Path
from collections import Counter

from app.core.security import calculate_sha256
from app.database.database import load_baseline, save_baseline


class RansomwareDetector:

    def __init__(self, watch_directory: str):
        self.watch_directory = Path(watch_directory)

    # ==========================================
    # FILE COLLECTION
    # ==========================================

    def collect_files(self):

        files = []

        for root, _, filenames in os.walk(self.watch_directory):

            for filename in filenames:

                path = Path(root) / filename

                try:

                    stat = path.stat()
                    file_hash = calculate_sha256(str(path))

                    files.append({
                        "name": filename,
                        "path": str(path),
                        "size": stat.st_size,
                        "sha256": file_hash,
                        "modified": stat.st_mtime
                    })

                except OSError:
                    continue

        return files

    # ==========================================
    # BASELINE
    # ==========================================

    def create_baseline(self):

        files = self.collect_files()

        baseline = {
            file["path"]: file["sha256"]
            for file in files
        }

        save_baseline(baseline)

        return {
            "status": "success",
            "message": "Baseline created",
            "files_baselined": len(baseline)
        }

    # ==========================================
    # BASELINE COMPARISON
    # ==========================================

    def compare_baseline(self):

        files = self.collect_files()
        baseline = load_baseline()

        changed = []
        new_files = []

        current_paths = set()

        for file in files:

            path = file["path"]
            current_paths.add(path)

            old_hash = baseline.get(path)

            if old_hash is None:

                new_files.append(file)

            elif old_hash != file["sha256"]:

                changed.append({
                    "path": path,
                    "old_hash": old_hash,
                    "new_hash": file["sha256"]
                })

        deleted = [
            path
            for path in baseline
            if path not in current_paths
        ]

        return {
            "status": "success",
            "changed_files": changed,
            "new_files": new_files,
            "deleted_files": deleted,
            "total_changes": (
                len(changed)
                + len(new_files)
                + len(deleted)
            )
        }

    # ==========================================
    # ENTROPY
    # ==========================================

    def calculate_entropy(self, file_path):

        try:

            with open(file_path, "rb") as f:
                data = f.read(1024 * 1024)

            if not data:
                return 0.0

            counts = Counter(data)
            length = len(data)

            entropy = 0.0

            for count in counts.values():

                probability = count / length

                entropy -= (
                    probability *
                    math.log2(probability)
                )

            return round(entropy, 3)

        except OSError:

            return 0.0

    # ==========================================
    # STATIC FILE ANALYSIS
    # ==========================================

    def analyze_file(self, file_path):

        path = Path(file_path)

        if not path.is_file():

            return {
                "status": "error",
                "message": "File does not exist"
            }

        try:

            stat = path.stat()
            entropy = self.calculate_entropy(path)

            suspicious_reasons = []
            score = 0

            filename = path.name.lower()

            # Suspicious ransomware-like filename indicators
            suspicious_names = [
                "ransom",
                "decrypt",
                "encrypted",
                "locked",
                "readme",
                "recover"
            ]

            if any(
                word in filename
                for word in suspicious_names
            ):

                score += 25

                suspicious_reasons.append(
                    "Suspicious filename indicator"
                )

            # Suspicious extensions
            suspicious_extensions = {
                ".encrypted",
                ".locked",
                ".enc",
                ".crypt",
                ".crypto",
                ".ransom"
            }

            if path.suffix.lower() in suspicious_extensions:

                score += 35

                suspicious_reasons.append(
                    "Suspicious ransomware-like extension"
                )

            # High entropy indicator
            if entropy >= 7.5:

                score += 20

                suspicious_reasons.append(
                    "High file entropy detected"
                )

            # Look for suspicious text indicators
            try:

                if stat.st_size <= 5 * 1024 * 1024:

                    with open(path, "rb") as f:
                        raw = f.read()

                    text = raw.decode(
                        "utf-8",
                        errors="ignore"
                    ).lower()

                    indicators = [
                        "your files have been encrypted",
                        "decrypt your files",
                        "bitcoin",
                        "ransom",
                        "pay the ransom",
                        "decryption key"
                    ]

                    matches = [
                        item
                        for item in indicators
                        if item in text
                    ]

                    if matches:

                        score += min(
                            40,
                            len(matches) * 15
                        )

                        suspicious_reasons.append(
                            "Ransomware-related text indicator"
                        )

            except OSError:
                pass

            score = min(score, 100)

            if score >= 80:
                risk_level = "CRITICAL"

            elif score >= 60:
                risk_level = "HIGH"

            elif score >= 30:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

            return {

                "status": "success",

                "file": {
                    "name": path.name,
                    "path": str(path),
                    "size": stat.st_size,
                    "sha256": calculate_sha256(
                        str(path)
                    )
                },

                "analysis": {
                    "entropy": entropy,
                    "risk_score": score,
                    "risk_level": risk_level,
                    "suspicious": len(
                        suspicious_reasons
                    ) > 0,
                    "reasons": suspicious_reasons
                }

            }

        except OSError as error:

            return {
                "status": "error",
                "message": str(error)
            }

    # ==========================================
    # DIRECTORY SCAN
    # ==========================================

    def scan(self):

        if not self.watch_directory.exists():

            return {
                "status": "error",
                "message": "Directory does not exist"
            }

        files = self.collect_files()

        extensions = Counter(
            Path(file["name"]).suffix.lower()
            for file in files
        )

        return {
            "status": "success",
            "directory": str(self.watch_directory),
            "files_scanned": len(files),
            "extensions": dict(extensions),
            "files": files
        }
