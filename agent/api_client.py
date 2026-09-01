import json
import urllib.error
import urllib.request


class RDRSAPIClient:

    def __init__(self, server_url):
        self.server_url = server_url.rstrip("/")

    def send_event(self, event_data):
        """Send an event to the RDRS server."""

        url = f"{self.server_url}/api/agent/events"

        payload = json.dumps(event_data).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))

        except (urllib.error.URLError, urllib.error.HTTPError) as error:
            print(f"⚠️ Server communication unavailable: {error}")
            return None
