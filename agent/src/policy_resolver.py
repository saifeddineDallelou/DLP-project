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
            conditions = policy.get("conditions") or {}
            entry = {
                "id": policy["id"],
                "action": policy.get("action") or DEFAULT_ACTION,
                "name": policy.get("name"),
                # Patterns are stored upper-cased with spaces normalized to
                # underscores (e.g. "CREDIT CARD" -> "CREDIT_CARD") to match
                # the classifier's detection `type`/keyword-`value` field --
                # a human typing a pattern into the dashboard naturally uses
                # spaces, but engine.py's types are underscore-separated. See
                # _matches_gate() / _detection_matches_patterns().
                "patterns": [str(p).upper().replace(" ", "_") for p in (conditions.get("patterns") or [])],
                "threshold": conditions.get("threshold") or 1,
            }
            rule = conditions.get("complianceRule")
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
        policy AND whose patterns/threshold gate (see _matches_gate) is
        satisfied by the full detection set, else the default policy.

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
            candidate = mapping.get(base_rule)
            if candidate and self._matches_gate(candidate, base_rule, detections):
                return candidate

        return default

    @staticmethod
    def _matches_gate(candidate: dict, base_rule: str, detections: list[dict]) -> bool:
        """
        A policy's `patterns`/`threshold` conditions (edited in the dashboard's
        ConditionsEditor) restrict when it actually applies, on top of the
        compliance-rule match:

        - `patterns` (e.g. ["CREDIT_CARD", "SSN"]): if set, only detections
          matching one of these count -- see _detection_matches_patterns for
          what "matching" means. If unset/empty, any detection sharing this
          policy's compliance rule counts (unrestricted, same behavior as
          before patterns existed).
        - `threshold`: minimum number of matching detections required
          (default 1).
        """
        patterns = candidate.get("patterns") or []
        threshold = candidate.get("threshold") or 1
        if patterns:
            matching = sum(1 for d in detections if PolicyResolver._detection_matches_patterns(d, patterns))
        else:
            matching = sum(1 for d in detections if d.get("rule", "").split("/")[0] == base_rule)
        return matching >= threshold

    @staticmethod
    def _detection_matches_patterns(detection: dict, patterns: list[str]) -> bool:
        """
        A structured-pattern detection (credit_card, ssn, iban, ...) is
        identified by its `type`, so "CREDIT_CARD" in a policy's patterns
        matches a detection with type "credit_card" directly.

        A keyword-hit detection is different: the classifier always tags
        those with type "keyword" (see classifier/src/engine.py
        _run_keywords) -- the actual keyword is in `value` instead (e.g.
        type="keyword", value="password"). So "PASSWORD" in a policy's
        patterns has to match against `value`, not the always-"keyword" type.
        """
        dtype = (detection.get("type") or "").upper()
        if dtype in patterns:
            return True
        if dtype == "KEYWORD":
            value = (detection.get("value") or "").upper().replace(" ", "_")
            return value in patterns
        return False
