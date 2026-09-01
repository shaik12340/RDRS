import hashlib
import math
from pathlib import Path
from collections import Counter


class RDRSScanner:

    def __init__(self):
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

        risk_score = 0
        indicators = []

        if extension in self.suspicious_extensions:
            risk_score += 40
            indicators.append("Suspicious extension")

        for keyword in self.suspicious_keywords:
            if keyword in filename:
                risk_score += 20
                indicators.append(f"Suspicious filename keyword: {keyword}")
                break

        if entropy >= 7.5:
            risk_score += 30
            indicators.append("High entropy")

        risk_score = min(risk_score, 100)

        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "file": str(path),
            "filename": path.name,
            "extension": extension,
            "size": size,
            "sha256": sha256,
            "entropy": entropy,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
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
