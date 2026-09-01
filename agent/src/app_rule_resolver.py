"""
Fetches the admin-configured "restricted apps" list from the backend and
matches it against a window title / process name.

This mirrors Microsoft Purview Endpoint DLP's "Restricted apps" list: being
on this list does NOT block an app from running -- it's an additional
risky-destination signal (alongside the AI-platform table in
ai_domain_monitor.py) that only matters when sensitive content is about to
touch it. The actual block/quarantine decision still comes from
PolicyResolver, based on what was detected -- this module only answers
"is a restricted app the current risky destination".

Rules are fetched once at construction and re-fetched on a timer (see
main.py's _policy_refresh_loop -- app rules use the same refresh cadence),
so an edit made in the dashboard reaches the agent without a restart.
"""

from loguru import logger

from api_client import DLPApiClient


class AppRuleResolver:
    def __init__(self, client: DLPApiClient) -> None:
        self._client = client
        self._rules: list[tuple[str, str]] = []  # (keyword, label)

    def refresh(self) -> None:
        """Fetch current enabled app rules from the backend."""
        rules = self._client.list_app_rules()
        if rules is None:
            logger.warning("[APP-RULES] Could not fetch app rules from backend -- keeping previous list")
            return

        self._rules = [
            (r["keyword"].lower(), r.get("label") or r["keyword"])
            for r in rules
            if r.get("enabled", True)
        ]
        logger.info(f"[APP-RULES] Loaded {len(self._rules)} restricted-app rule(s)")

    def match(self, text: str) -> str | None:
        """Return the matched rule's label if `text` (a window title or
        process name) contains one of the restricted-app keywords, else
        None."""
        lower = text.lower()
        for keyword, label in self._rules:
            if keyword in lower:
                return label
        return None
