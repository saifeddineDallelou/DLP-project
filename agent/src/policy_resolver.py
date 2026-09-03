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



# Channels where the data is at REST. A file already sitting in a folder has
# no in-flight action to intercept, so "stop it" can only mean moving it --
# and conversely a paste cannot be moved to a quarantine folder. A ladder
# expresses the INTENT to stop; each channel realises it with the action it
# can actually perform.
_AT_REST_CHANNELS = frozenset({"FILE"})
_STOP_ACTIONS = frozenset({"BLOCK", "QUARANTINE"})

_VALID_ACTIONS = frozenset({"ALLOW", "ALERT", "BLOCK", "QUARANTINE"})
_VALID_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


def _clean_tiers(raw) -> list[dict]:
    """Validate and sort a risk ladder, highest threshold first.

    Anything malformed is dropped rather than trusted. These arrive from an
    API and end up deciding what an endpoint agent does to a user's files, so
    a tier with a non-numeric threshold or an action outside the enum must not
    survive to be enforced.
    """
    if not isinstance(raw, list):
        return []
    cleaned: list[dict] = []
    for tier in raw:
        if not isinstance(tier, dict):
            continue
        try:
            min_risk = float(tier.get("minRisk"))
        except (TypeError, ValueError):
            continue
        action = str(tier.get("action") or "").upper()
        if action not in _VALID_ACTIONS:
            continue
        severity = str(tier.get("severity") or "").upper()
        cleaned.append({
            "minRisk": min_risk,
            "action": action,
            "severity": severity if severity in _VALID_SEVERITIES else None,
        })
    # Highest first, so the first match is the most severe that applies.
    cleaned.sort(key=lambda t: t["minRisk"], reverse=True)
    return cleaned


def realise_for_channel(action: str, channel: str | None) -> str:
    """The concrete action this channel can actually carry out.

    A ladder says "stop this". Whether stopping means cancelling something in
    flight or moving a file off disk depends entirely on where the data is,
    and asking an admin to know that for every channel is how BLOCK on a file
    at rest came to mean nothing at all.
    """
    if not channel or action not in _STOP_ACTIONS:
        return action
    at_rest = str(channel).upper() in _AT_REST_CHANNELS
    return "QUARANTINE" if at_rest else "BLOCK"


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
                # The admin's judgement of how much this matters. Carried so
                # incidents can use it -- it was previously stored, displayed
                # and read by nothing.
                "severity": policy.get("severity"),
                # Graduated response by detection confidence. Sorted high to
                # low once here rather than on every lookup, and validated on
                # the way in: a malformed tier must not become the action an
                # endpoint enforces.
                "tiers": _clean_tiers(policy.get("tiers")),
                # Patterns are stored upper-cased with spaces normalized to
                # underscores (e.g. "CREDIT CARD" -> "CREDIT_CARD") to match
                # the classifier's detection `type`/keyword-`value` field --
                # a human typing a pattern into the dashboard naturally uses
                # spaces, but engine.py's types are underscore-separated. See
                # _matches_gate() / _detection_matches_patterns().
                "patterns": [str(p).upper().replace(" ", "_") for p in (conditions.get("patterns") or [])],
                "threshold": conditions.get("threshold") or 1,
                # {"FILE": "QUARANTINE", "CLIPBOARD": "BLOCK"} -- the response
                # for a given channel, where it differs from `action`.
                "channelActions": {
                    str(k).upper(): str(v).upper()
                    for k, v in (policy.get("channelActions") or {}).items()
                    if isinstance(v, str)
                },
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

    def resolve(self, detections: list[dict], channel: str | None = None,
                risk_score: float | None = None) -> dict:
        """
        Return {"id", "action", "name"} for the policy matching the first
        (highest-priority) detection whose compliance rule has a configured
        policy AND whose patterns/threshold gate (see _matches_gate) is
        satisfied by the full detection set, else the default policy.

        A rule like "GDPR/loi-09-08" matches a policy tagged just "GDPR" --
        only the part before the slash is the compliance-framework name, the
        rest is a specific-law citation.

        `channel` selects the response, because the right one depends on where
        the data is moving and not only on what it is. A paste, a drag or a
        file-picker selection is an action IN FLIGHT and can be stopped; a
        file sitting in a watched folder is not doing anything, so there is
        nothing to intercept and the only real response is to move it.

        Omitting the channel keeps the policy's plain `action`, which is what
        every caller did before this existed.
        """
        with self._lock:
            mapping = self._rule_to_policy
            default = self._default_policy

        chosen = default
        for detection in detections:
            rule = detection.get("rule", "")
            base_rule = rule.split("/")[0]
            candidate = mapping.get(base_rule)
            if candidate and self._matches_gate(candidate, base_rule, detections):
                chosen = candidate
                break

        return self._apply(chosen, channel, risk_score)

    @staticmethod
    def _apply(policy: dict, channel: str | None, risk_score: float | None) -> dict:
        """Resolve a policy into the concrete response for this event.

        Order matters, and it is the order of who decided:

        1. The RISK LADDER, when the policy has one and a risk score is known.
           The detector's confidence chooses the tier, and the tier carries
           both the action and the severity -- so those two can no longer
           disagree with the score or with each other. Content below the
           lowest tier produces nothing: `action` is NONE and callers skip it.
        2. Otherwise the per-CHANNEL override, then the policy's flat action.
        3. The action is then REALISED for the channel: a ladder says "stop
           this", and whether that means cancelling something in flight or
           moving a file off disk depends on where the data is.

        A copy is always returned. The entries are shared cache state read
        from several monitor threads, and rewriting them in place would leak
        one event's resolution into the next.
        """
        resolved = dict(policy)
        source = None

        tiers = policy.get("tiers") or []
        if tiers and risk_score is not None:
            tier = next((t for t in tiers if risk_score >= t["minRisk"]), None)
            if tier is None:
                # Below every rung. Not "allowed" -- simply not covered by
                # this policy at this confidence, so nothing is recorded.
                resolved["action"] = "NONE"
                resolved["actionSource"] = "below-lowest-tier"
                return resolved
            # A tier says "stop this at this confidence"; the channel decides
            # what stopping means. Translation is confined to this path on
            # purpose: doing it for the flat `action` too would silently turn
            # an existing BLOCK policy into one that MOVES people's files,
            # which is an escalation nobody asked for. An explicitly
            # configured FILE+BLOCK is rejected by the backend instead, where
            # the admin can be told why.
            resolved["action"] = realise_for_channel(tier["action"], channel)
            if tier["severity"]:
                resolved["severity"] = tier["severity"]
            source = f"tier:>={tier['minRisk']}"
            if resolved["action"] != tier["action"]:
                source += f"+{str(channel).lower()}"
            resolved["actionSource"] = source
            return resolved
        elif channel:
            override = (policy.get("channelActions") or {}).get(str(channel).upper())
            if override and override != policy.get("action"):
                resolved["action"] = override
                source = f"channel:{channel}"

        if source:
            resolved["actionSource"] = source
        return resolved


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
