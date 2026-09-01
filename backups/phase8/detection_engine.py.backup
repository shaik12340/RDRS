import time
from collections import deque
from pathlib import Path


class RDRSDetectionEngine:

    def __init__(
        self,
        window_seconds=10,
        medium_threshold=5,
        high_threshold=10,
        critical_threshold=25
    ):
        self.window_seconds = window_seconds

        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold

        self.events = deque()

    def record_event(self, event_type, file_path):
        """
        Record a filesystem event and calculate
        rapid-change activity within the configured
        time window.
        """

        now = time.time()

        self.events.append({
            "timestamp": now,
            "event_type": event_type,
            "file": str(Path(file_path).expanduser().resolve())
        })

        self._remove_old_events(now)

        return self.analyze_activity()

    def _remove_old_events(self, now):
        cutoff = now - self.window_seconds

        while self.events and self.events[0]["timestamp"] < cutoff:
            self.events.popleft()

    def analyze_activity(self):
        """
        Analyze recent filesystem activity.

        Only modification/creation/deletion/move events
        are counted as rapid activity.
        """

        rapid_events = list(self.events)

        event_count = len(rapid_events)

        modified_count = sum(
            1
            for event in rapid_events
            if event["event_type"] == "MODIFIED"
        )

        created_count = sum(
            1
            for event in rapid_events
            if event["event_type"] == "CREATED"
        )

        deleted_count = sum(
            1
            for event in rapid_events
            if event["event_type"] == "DELETED"
        )

        moved_count = sum(
            1
            for event in rapid_events
            if event["event_type"] == "MOVED"
        )

        if event_count >= self.critical_threshold:
            rapid_score = 40
            rapid_level = "CRITICAL"

        elif event_count >= self.high_threshold:
            rapid_score = 30
            rapid_level = "HIGH"

        elif event_count >= self.medium_threshold:
            rapid_score = 15
            rapid_level = "MEDIUM"

        else:
            rapid_score = 0
            rapid_level = "LOW"

        return {
            "window_seconds": self.window_seconds,
            "event_count": event_count,
            "modified_count": modified_count,
            "created_count": created_count,
            "deleted_count": deleted_count,
            "moved_count": moved_count,
            "rapid_score": rapid_score,
            "rapid_level": rapid_level
        }

    def reset(self):
        """Clear tracked filesystem activity."""
        self.events.clear()
