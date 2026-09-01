class RiskEngine:

    def calculate_score(
        self,
        changed_files=0,
        new_files=0,
        deleted_files=0,
        suspicious_extensions=0,
        rapid_changes=False,
        suspicious_filename=False,
        high_entropy=False
    ):

        score = 0
        reasons = []

        # ==========================================
        # MODIFIED FILES
        # ==========================================

        if changed_files > 0:

            points = min(changed_files * 10, 40)
            score += points

            reasons.append(
                f"{changed_files} file(s) modified"
            )

        # ==========================================
        # NEW FILES
        # ==========================================

        if new_files > 0:

            points = min(new_files * 5, 25)
            score += points

            reasons.append(
                f"{new_files} new file(s) detected"
            )

        # ==========================================
        # DELETED FILES
        # ==========================================

        if deleted_files > 0:

            points = min(deleted_files * 15, 30)
            score += points

            reasons.append(
                f"{deleted_files} file(s) deleted"
            )

        # ==========================================
        # SUSPICIOUS EXTENSIONS
        # ==========================================

        if suspicious_extensions > 0:

            points = min(
                suspicious_extensions * 10,
                25
            )

            score += points

            reasons.append(
                f"{suspicious_extensions} suspicious extension(s)"
            )

        # ==========================================
        # RAPID FILE ACTIVITY
        # ==========================================

        if rapid_changes:

            score += 25

            reasons.append(
                "Rapid file activity detected"
            )

        # ==========================================
        # SUSPICIOUS FILENAME
        # ==========================================

        if suspicious_filename:

            score += 20

            reasons.append(
                "Suspicious filename indicator"
            )

        # ==========================================
        # HIGH ENTROPY
        # ==========================================

        if high_entropy:

            score += 25

            reasons.append(
                "High file entropy detected"
            )

        # ==========================================
        # CAP SCORE
        # ==========================================

        score = min(score, 100)

        # ==========================================
        # RISK LEVEL
        # ==========================================

        if score >= 80:

            level = "CRITICAL"

        elif score >= 60:

            level = "HIGH"

        elif score >= 30:

            level = "MEDIUM"

        else:

            level = "LOW"

        return {

            "risk_score": score,

            "risk_level": level,

            "reasons": reasons
        }
