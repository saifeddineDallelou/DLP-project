"""
Maps a classifier detection to the right Policy for an incident, and to the
action (ALLOW / ALERT / BLOCK / QUARANTINE) that policy says to take.

Policies carry a compliance-rule tag in their `conditions.complianceRule`
field (e.g. "PCI-DSS", "HIPAA", "GDPR", "INTERNAL"). The classifier already
tags every detection it returns with the same compliance-rule vocabulary
(see classifier/src/engine.py's `rule` field on each pattern/keyword), so
resolving "which policy does this incident violate" is just matching one
against the other -- no re-implementation of the classification logic here.

Policies are fetched from the backend once (refresh()), not hardcoded, so
editing/adding policies in the dashboard takes effect on the next agent
restart without a code change.
"""

import threading
from loguru import logger

from api_client import DLPApiClient

# Used when no detection's rule matches a configured policy, or when the
# policy list couldn't be fetched at all (backend unreachable at startup).
DEFAULT_POLICY_ID = "seed-policy-pii-001"
DEFAULT_ACTION     = "BLOCK"


class PolicyResolver:
    def __init__(
        self,
        client: DLPApiClient,
        default_policy_id: str = DEFAULT_POLICY_ID,
        default_action: str = DEFAULT_ACTION,
    ) -> None:
        self._client = client
        self._lock = threading.Lock()
        self._rule_to_policy: dict[str, dict] = {}
        self._default_policy = {"id": default_policy_id, "action": default_action, "name": None}

    def refresh(self) -> None:
        """Fetch current policies and rebuild the compliance-rule -> policy map."""
        policies = self._client.list_policies()
        if not policies:
            logger.warning(
                "[POLICY] Could not fetch policies from backend -- "
                f"all incidents will use the default policy ({self._default_policy['id']})"
            )
            return

        mapping: dict[str, dict] = {}
        default_candidate = None
        for policy in policies:
            if not policy.get("enabled", True):
                continue
            entry = {
                "id": policy["id"],
                "action": policy.get("action") or DEFAULT_ACTION,
                "name": policy.get("name"),
            }
            rule = (policy.get("conditions") or {}).get("complianceRule")
            if rule:
                mapping[rule] = entry
            if policy.get("name") == "PII Detection":
                default_candidate = entry

        with self._lock:
            self._rule_to_policy = mapping
            if default_candidate:
                self._default_policy = default_candidate

        logger.info(
            f"[POLICY] Loaded {len(mapping)} compliance-mapped polic{'y' if len(mapping) == 1 else 'ies'}: "
            f"{list(mapping)}"
        )

    def resolve(self, detections: list[dict]) -> dict:
        """
        Return {"id", "action", "name"} for the policy matching the first
        (highest-priority) detection whose compliance rule has a configured
        policy, else the default policy.

        A rule like "GDPR/loi-09-08" matches a policy tagged just "GDPR" --
        only the part before the slash is the compliance-framework name, the
        rest is a specific-law citation.
        """
        with self._lock:
            mapping = self._rule_to_policy
            default = self._default_policy

        for detection in detections:
            rule = detection.get("rule", "")
            base_rule = rule.split("/")[0]
            if base_rule in mapping:
                return mapping[base_rule]

        return default
