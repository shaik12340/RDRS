class RDRSRiskEngine:

    def __init__(self):
        self.max_score = 100

    def calculate_score(
        self,
        entropy_score=0,
        extension_score=0,
        filename_score=0,
        rapid_score=0,
        activity_score=0,
        other_score=0
    ):
        """
        Calculate final RDRS risk score.

        All individual scores are expected to be
        non-negative numeric values.
        """

        scores = {
            "entropy": entropy_score,
            "extension": extension_score,
            "filename": filename_score,
            "rapid_changes": rapid_score,
            "file_activity": activity_score,
            "other_indicators": other_score
        }

        total_score = 0

        for name, value in scores.items():
            try:
                value = float(value)
            except (TypeError, ValueError):
                value = 0

            if value < 0:
                value = 0

            total_score += value

        final_score = min(round(total_score), self.max_score)

        if final_score >= 80:
            risk_level = "CRITICAL"
            action = "QUARANTINE"

        elif final_score >= 60:
            risk_level = "HIGH"
            action = "CONTAIN"

        elif final_score >= 30:
            risk_level = "MEDIUM"
            action = "ALERT"

        else:
            risk_level = "LOW"
            action = "ALLOW"

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "action": action,
            "components": {
                "entropy": entropy_score,
                "extension": extension_score,
                "filename": filename_score,
                "rapid_changes": rapid_score,
                "file_activity": activity_score,
                "other_indicators": other_score
            }
        }
