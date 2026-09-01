import hashlib
import math
from pathlib import Path
from collections import Counter
from agent.risk_engine import RDRSRiskEngine


class RDRSScanner:

    def __init__(self):
        self.risk_engine = RDRSRiskEngine()

        self.suspicious_extensions = {
            ".locked",
            ".encrypted",
            ".enc",
            ".crypt",
            ".crypto",
            ".ryk",
            ".wncry",
            ".wcry",
            ".lockbit",
        }

        self.suspicious_keywords = {
            "ransom",
            "encrypted",
            "decrypt",
            "locked",
            "lockbit",
            "wannacry",
            "crypt",
        }

    def calculate_sha256(self, file_path):
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    def calculate_entropy(self, file_path):
        with open(file_path, "rb") as file:
            data = file.read()

        if not data:
            return 0.0

        frequency = Counter(data)
        length = len(data)

        entropy = 0.0

        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def analyze_file(self, file_path):
        path = Path(file_path).expanduser().resolve()

        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if not path.is_file():
            raise ValueError(f"Not a file: {path}")

        size = path.stat().st_size
        extension = path.suffix.lower()
        filename = path.name.lower()

        sha256 = self.calculate_sha256(path)
        entropy = self.calculate_entropy(path)

        indicators = []

        extension_score = 0
        filename_score = 0
        entropy_score = 0

        if extension in self.suspicious_extensions:
            extension_score = 40
            indicators.append("Suspicious extension")

        for keyword in self.suspicious_keywords:
            if keyword in filename:
                filename_score = 20
                indicators.append(
                    f"Suspicious filename keyword: {keyword}"
                )
                break

        if entropy >= 7.5:
            entropy_score = 30
            indicators.append("High entropy")

        risk_result = self.risk_engine.calculate_score(
            entropy_score=entropy_score,
            extension_score=extension_score,
            filename_score=filename_score,
            rapid_score=0,
            activity_score=0,
            other_score=0
        )

        risk_score = risk_result["risk_score"]
        risk_level = risk_result["risk_level"]
        action = risk_result["action"]

        return {
            "file": str(path),
            "filename": path.name,
            "extension": extension,
            "size": size,
            "sha256": sha256,
            "entropy": entropy,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "action": action,
            "indicators": indicators,
            "risk_components": risk_result["components"],
        }

    def scan_file(self, file_path):
        return self.analyze_file(file_path)

    def scan_folder(self, folder_path):
        folder = Path(folder_path).expanduser().resolve()

        if not folder.exists():
            raise FileNotFoundError(f"Folder not found: {folder}")

        if not folder.is_dir():
            raise ValueError(f"Not a directory: {folder}")

        results = []

        for file_path in folder.rglob("*"):
            if file_path.is_file():
                try:
                    results.append(self.analyze_file(file_path))
                except (PermissionError, OSError) as error:
                    results.append({
                        "file": str(file_path),
                        "error": str(error),
                    })

        return results
