import time
import requests
from loguru import logger

_MAX_RETRIES = 3
_RETRY_DELAY = 2  # seconds between retries


def _request(method: str, url: str, *, json=None, headers=None) -> dict | None:
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, json=json, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            logger.warning(f"[{attempt}/{_MAX_RETRIES}] Cannot connect to {url}")
        except requests.exceptions.Timeout:
            logger.warning(f"[{attempt}/{_MAX_RETRIES}] Timeout connecting to {url}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP {e.response.status_code} from {url}: {e.response.text[:200]}")
            return None  # HTTP errors are not retried
        except Exception as e:
            logger.error(f"Unexpected error calling {url}: {e}")

        if attempt < _MAX_RETRIES:
            time.sleep(_RETRY_DELAY)

    logger.error(f"Giving up after {_MAX_RETRIES} attempts for {url}")
    return None


class DLPApiClient:
    def __init__(self, backend_url: str, classifier_url: str, agent_token: str | None = None):
        self.backend_url = backend_url.rstrip("/")
        self.classifier_url = classifier_url.rstrip("/")
        self.agent_token = agent_token

    @property
    def _agent_headers(self) -> dict:
        return {"x-agent-token": self.agent_token} if self.agent_token else {}

    def enroll(self, hostname: str, os_info: str, version: str = "1.0.0") -> dict | None:
        return _request(
            "POST",
            f"{self.backend_url}/api/agents/enroll",
            json={"hostname": hostname, "os": os_info, "version": version},
        )

    def heartbeat(self, agent_id: str) -> dict | None:
        return _request(
            "PATCH",
            f"{self.backend_url}/api/agents/{agent_id}/heartbeat",
            headers=self._agent_headers,
        )

    def classify(self, text: str | None = None, file_b64: str | None = None) -> dict | None:
        payload: dict = {}
        if text is not None:
            payload["text"] = text
        if file_b64 is not None:
            payload["file"] = file_b64
        if not payload:
            return None
        return _request("POST", f"{self.classifier_url}/classify", json=payload)

    def report_ai_leak_attempt(
        self,
        agent_id: str,
        platform: str,
        method: str,
        content_sample: str | None,
        risk_score: float,
        blocked: bool = True,
    ) -> dict | None:
        return _request(
            "POST",
            f"{self.backend_url}/api/ai-policy/attempt",
            json={
                "agentId":       agent_id,
                "platform":      platform,
                "method":        method,
                "contentSample": content_sample,
                "riskScore":     risk_score,
                "blocked":       blocked,
            },
            headers=self._agent_headers,
        )

    def post_ueba_event(
        self,
        agent_id: str,
        user_id: str,
        event_type: str,
        metadata: dict,
    ) -> dict | None:
        return _request(
            "POST",
            f"{self.backend_url}/api/ueba/events",
            json={
                "agentId":   agent_id,
                "userId":    user_id,
                "eventType": event_type,
                "metadata":  metadata,
            },
            headers=self._agent_headers,
        )

    def create_incident(
        self,
        agent_id: str,
        policy_id: str,
        severity: str,
        channel: str,
        evidence: str,
        risk_score: float,
    ) -> dict | None:
        return _request(
            "POST",
            f"{self.backend_url}/api/incidents",
            json={
                "agentId":    agent_id,
                "policyId":   policy_id,
                "severity":   severity,
                "channel":    channel,
                "evidence":   evidence,
                "evidenceType": "filename",
                "riskScore":  risk_score,
            },
            headers=self._agent_headers,
        )
