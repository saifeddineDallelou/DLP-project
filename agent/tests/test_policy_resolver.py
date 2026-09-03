from unittest.mock import MagicMock

from policy_resolver import PolicyResolver, DEFAULT_POLICY_ID, DEFAULT_ACTION


def _policy(id_, rule, enabled=True, action="BLOCK", name=None, patterns=None, threshold=None):
    conditions = {"complianceRule": rule}
    if patterns is not None:
        conditions["patterns"] = patterns
    if threshold is not None:
        conditions["threshold"] = threshold
    return {
        "id": id_, "enabled": enabled, "action": action, "name": name or id_,
        "conditions": conditions,
    }


class TestRefresh:
    def test_builds_rule_to_policy_map_from_conditions(self):
        client = MagicMock()
        client.list_policies.return_value = [
            _policy("pci-1", "PCI-DSS"),
            _policy("hipaa-1", "HIPAA"),
        ]
        resolver = PolicyResolver(client)
        resolver.refresh()

        assert resolver.resolve([{"rule": "PCI-DSS"}])["id"] == "pci-1"
        assert resolver.resolve([{"rule": "HIPAA"}])["id"] == "hipaa-1"

    def test_resolved_policy_carries_its_action(self):
        client = MagicMock()
        client.list_policies.return_value = [_policy("pci-1", "PCI-DSS", action="QUARANTINE")]
        resolver = PolicyResolver(client)
        resolver.refresh()

        assert resolver.resolve([{"rule": "PCI-DSS"}])["action"] == "QUARANTINE"

    def test_defaults_action_when_policy_has_none(self):
        client = MagicMock()
        client.list_policies.return_value = [_policy("pci-1", "PCI-DSS", action=None)]
        resolver = PolicyResolver(client)
        resolver.refresh()

        assert resolver.resolve([{"rule": "PCI-DSS"}])["action"] == DEFAULT_ACTION

    def test_ignores_disabled_policies(self):
        client = MagicMock()
        client.list_policies.return_value = [_policy("pci-1", "PCI-DSS", enabled=False)]
        resolver = PolicyResolver(client, default_policy_id="fallback")
        resolver.refresh()

        assert resolver.resolve([{"rule": "PCI-DSS"}])["id"] == "fallback"

    def test_ignores_policies_without_a_compliance_rule(self):
        client = MagicMock()
        client.list_policies.return_value = [{"id": "manual-1", "enabled": True, "action": "ALERT", "conditions": {"patterns": ["TEST"]}}]
        resolver = PolicyResolver(client, default_policy_id="fallback")
        resolver.refresh()

        assert resolver.resolve([{"rule": "PCI-DSS"}])["id"] == "fallback"

    def test_keeps_default_when_fetch_fails(self):
        client = MagicMock()
        client.list_policies.return_value = None
        resolver = PolicyResolver(client, default_policy_id="fallback")
        resolver.refresh()

        assert resolver.resolve([{"rule": "PCI-DSS"}])["id"] == "fallback"

    def test_keeps_default_when_fetch_returns_empty_list(self):
        client = MagicMock()
        client.list_policies.return_value = []
        resolver = PolicyResolver(client, default_policy_id="fallback")
        resolver.refresh()

        assert resolver.resolve([{"rule": "PCI-DSS"}])["id"] == "fallback"

    def test_uses_pii_detection_named_policy_as_new_default(self):
        client = MagicMock()
        client.list_policies.return_value = [
            _policy("gdpr-1", "GDPR", action="ALERT", name="PII Detection"),
        ]
        resolver = PolicyResolver(client, default_policy_id="fallback")
        resolver.refresh()

        # An unmapped rule falls through to the default -- which should now
        # be the real "PII Detection" policy fetched from the backend, not
        # the constructor's placeholder fallback.
        assert resolver.resolve([{"rule": "SOMETHING_UNMAPPED"}])["id"] == "gdpr-1"
        assert resolver.resolve([{"rule": "SOMETHING_UNMAPPED"}])["action"] == "ALERT"


class TestResolve:
    def _resolver_with(self, mapping: dict[str, str], actions: dict[str, str] | None = None) -> PolicyResolver:
        actions = actions or {}
        client = MagicMock()
        client.list_policies.return_value = [
            _policy(pid, rule, action=actions.get(rule, "BLOCK")) for rule, pid in mapping.items()
        ]
        resolver = PolicyResolver(client, default_policy_id="fallback", default_action="BLOCK")
        resolver.refresh()
        return resolver

    def test_falls_back_to_default_with_no_detections(self):
        resolver = self._resolver_with({"PCI-DSS": "pci-1"})
        assert resolver.resolve([])["id"] == "fallback"

    def test_falls_back_to_default_when_no_rule_matches(self):
        resolver = self._resolver_with({"PCI-DSS": "pci-1"})
        assert resolver.resolve([{"rule": "HIPAA"}])["id"] == "fallback"

    def test_uses_default_class_constant_when_not_overridden(self):
        client = MagicMock()
        client.list_policies.return_value = []
        resolver = PolicyResolver(client)
        resolver.refresh()
        result = resolver.resolve([{"rule": "anything"}])
        assert result["id"] == DEFAULT_POLICY_ID
        assert result["action"] == DEFAULT_ACTION

    def test_strips_law_citation_suffix_from_rule(self):
        resolver = self._resolver_with({"GDPR": "gdpr-1"})
        assert resolver.resolve([{"rule": "GDPR/loi-09-08"}])["id"] == "gdpr-1"

    def test_first_matching_detection_wins(self):
        resolver = self._resolver_with({"PCI-DSS": "pci-1", "HIPAA": "hipaa-1"})
        detections = [{"rule": "PCI-DSS"}, {"rule": "HIPAA"}]
        assert resolver.resolve(detections)["id"] == "pci-1"

    def test_skips_unmapped_rule_and_matches_next_detection(self):
        resolver = self._resolver_with({"HIPAA": "hipaa-1"})
        detections = [{"rule": "UNMAPPED_RULE"}, {"rule": "HIPAA"}]
        assert resolver.resolve(detections)["id"] == "hipaa-1"

    def test_handles_detections_missing_rule_key(self):
        resolver = self._resolver_with({"HIPAA": "hipaa-1"})
        detections = [{"type": "keyword"}, {"rule": "HIPAA"}]
        assert resolver.resolve(detections)["id"] == "hipaa-1"

    def test_different_policies_can_have_different_actions(self):
        resolver = self._resolver_with(
            {"PCI-DSS": "pci-1", "HIPAA": "hipaa-1"},
            actions={"PCI-DSS": "ALERT", "HIPAA": "QUARANTINE"},
        )
        assert resolver.resolve([{"rule": "PCI-DSS"}])["action"] == "ALERT"
        assert resolver.resolve([{"rule": "HIPAA"}])["action"] == "QUARANTINE"


class TestPatternsAndThresholdGate:
    def _resolver_with_policy(self, patterns=None, threshold=None):
        client = MagicMock()
        client.list_policies.return_value = [
            _policy("pci-1", "PCI-DSS", patterns=patterns, threshold=threshold),
        ]
        resolver = PolicyResolver(client, default_policy_id="fallback")
        resolver.refresh()
        return resolver

    def test_matches_when_a_detection_type_is_in_patterns(self):
        resolver = self._resolver_with_policy(patterns=["CREDIT_CARD", "SSN"])
        detections = [{"rule": "PCI-DSS", "type": "credit_card"}]
        assert resolver.resolve(detections)["id"] == "pci-1"

    def test_falls_through_to_default_when_no_detection_type_is_in_patterns(self):
        # The policy's patterns list no longer includes CREDIT_CARD -- a
        # credit-card-only detection should no longer trigger this policy,
        # even though it still matches the compliance rule.
        resolver = self._resolver_with_policy(patterns=["SSN"])
        detections = [{"rule": "PCI-DSS", "type": "credit_card"}]
        assert resolver.resolve(detections)["id"] == "fallback"

    def test_empty_patterns_list_means_unrestricted(self):
        resolver = self._resolver_with_policy(patterns=[])
        detections = [{"rule": "PCI-DSS", "type": "credit_card"}]
        assert resolver.resolve(detections)["id"] == "pci-1"

    def test_threshold_requires_enough_matching_detections(self):
        resolver = self._resolver_with_policy(patterns=["CREDIT_CARD"], threshold=2)
        detections = [{"rule": "PCI-DSS", "type": "credit_card"}]
        assert resolver.resolve(detections)["id"] == "fallback"

        detections_x2 = [
            {"rule": "PCI-DSS", "type": "credit_card"},
            {"rule": "PCI-DSS", "type": "credit_card"},
        ]
        assert resolver.resolve(detections_x2)["id"] == "pci-1"

    def test_threshold_without_patterns_counts_rule_matching_detections(self):
        resolver = self._resolver_with_policy(threshold=2)
        assert resolver.resolve([{"rule": "PCI-DSS", "type": "credit_card"}])["id"] == "fallback"
        assert resolver.resolve([
            {"rule": "PCI-DSS", "type": "credit_card"},
            {"rule": "PCI-DSS", "type": "iban"},
        ])["id"] == "pci-1"

    def test_gate_is_case_insensitive_on_detection_type(self):
        resolver = self._resolver_with_policy(patterns=["CREDIT_CARD"])
        assert resolver.resolve([{"rule": "PCI-DSS", "type": "credit_card"}])["id"] == "pci-1"

    def test_keyword_detection_matches_patterns_via_value_not_type(self):
        # Classifier keyword hits always carry type="keyword" -- the actual
        # keyword is in `value` -- so a policy listing "PASSWORD" in its
        # patterns must match against value, not the always-"keyword" type.
        resolver = self._resolver_with_policy(patterns=["PASSWORD", "API_KEY"])
        detections = [{"rule": "PCI-DSS", "type": "keyword", "value": "password"}]
        assert resolver.resolve(detections)["id"] == "pci-1"

    def test_keyword_detection_with_unmatched_value_falls_through(self):
        resolver = self._resolver_with_policy(patterns=["PASSWORD"])
        detections = [{"rule": "PCI-DSS", "type": "keyword", "value": "salary"}]
        assert resolver.resolve(detections)["id"] == "fallback"

    def test_pattern_typed_with_a_space_still_matches_underscored_detection_type(self):
        # A human typing into the dashboard naturally writes "CREDIT CARD",
        # not "CREDIT_CARD" -- the classifier's detection type is always
        # underscore-separated ("credit_card"), so the stored pattern must
        # be normalized the same way or it silently never matches.
        resolver = self._resolver_with_policy(patterns=["CREDIT CARD"])
        detections = [{"rule": "PCI-DSS", "type": "credit_card"}]
        assert resolver.resolve(detections)["id"] == "pci-1"

    def test_keyword_detection_value_match_is_case_and_space_insensitive(self):
        resolver = self._resolver_with_policy(patterns=["API_KEY"])
        detections = [{"rule": "PCI-DSS", "type": "keyword", "value": "api key"}]
        assert resolver.resolve(detections)["id"] == "pci-1"

    def test_failed_gate_falls_through_to_next_matching_detection(self):
        client = MagicMock()
        client.list_policies.return_value = [
            _policy("pci-1", "PCI-DSS", patterns=["SSN"]),
            _policy("hipaa-1", "HIPAA"),
        ]
        resolver = PolicyResolver(client, default_policy_id="fallback")
        resolver.refresh()

        detections = [{"rule": "PCI-DSS", "type": "credit_card"}, {"rule": "HIPAA", "type": "keyword"}]
        assert resolver.resolve(detections)["id"] == "hipaa-1"


class TestPerChannelActions:
    """
    The right response depends on where the data is moving, not only on what
    it is. A paste, a drag or a file-picker selection is an action IN FLIGHT
    and can be stopped; a file sitting in a watched folder is not doing
    anything, so there is nothing to intercept and the only real response is
    to move it.

    Without this, BLOCK on a file at rest wrote an incident and left the file
    exactly where it was -- indistinguishable from ALERT, while the log
    claimed action=BLOCK. Purview and Netskope split the same way: one policy
    for what is sensitive, then a response per location.
    """

    def _resolver(self, channel_actions):
        client = MagicMock()
        client.list_policies.return_value = [{
            "id": "p-pii",
            "name": "PII Detection",
            "action": "BLOCK",
            "enabled": True,
            "channelActions": channel_actions,
            "conditions": {"complianceRule": "GDPR", "threshold": 1},
        }]
        r = PolicyResolver(client)
        r.refresh()
        return r

    DETECTIONS = [{"type": "email", "rule": "GDPR"}]

    def test_a_channel_override_replaces_the_default_action(self):
        r = self._resolver({"FILE": "QUARANTINE"})
        assert r.resolve(self.DETECTIONS, channel="FILE")["action"] == "QUARANTINE"

    def test_an_unlisted_channel_keeps_the_default(self):
        r = self._resolver({"FILE": "QUARANTINE"})
        assert r.resolve(self.DETECTIONS, channel="CLIPBOARD")["action"] == "BLOCK"

    def test_no_channel_at_all_keeps_the_default(self):
        # Every caller behaved this way before channels existed.
        r = self._resolver({"FILE": "QUARANTINE"})
        assert r.resolve(self.DETECTIONS)["action"] == "BLOCK"

    def test_a_policy_with_no_overrides_is_unchanged(self):
        r = self._resolver(None)
        assert r.resolve(self.DETECTIONS, channel="FILE")["action"] == "BLOCK"

    def test_the_channel_name_is_matched_case_insensitively(self):
        r = self._resolver({"file": "quarantine"})
        assert r.resolve(self.DETECTIONS, channel="FILE")["action"] == "QUARANTINE"

    def test_resolving_one_channel_does_not_affect_another(self):
        # The entries are shared cache state read from several monitor
        # threads. Rewriting `action` in place would leak one channel's
        # response into every other channel's next lookup.
        r = self._resolver({"FILE": "QUARANTINE"})
        assert r.resolve(self.DETECTIONS, channel="FILE")["action"] == "QUARANTINE"
        assert r.resolve(self.DETECTIONS, channel="CLIPBOARD")["action"] == "BLOCK"
        assert r.resolve(self.DETECTIONS, channel="FILE")["action"] == "QUARANTINE"

    def test_the_override_says_where_it_came_from(self):
        # An incident showing QUARANTINE when the policy reads BLOCK is
        # confusing unless the record says which channel rule applied.
        r = self._resolver({"FILE": "QUARANTINE"})
        assert r.resolve(self.DETECTIONS, channel="FILE")["actionSource"] == "channel:FILE"
        assert "actionSource" not in r.resolve(self.DETECTIONS, channel="CLIPBOARD")

    def test_an_override_equal_to_the_default_is_not_marked_as_one(self):
        r = self._resolver({"FILE": "BLOCK"})
        resolved = r.resolve(self.DETECTIONS, channel="FILE")
        assert resolved["action"] == "BLOCK"
        assert "actionSource" not in resolved

    def test_a_malformed_override_is_ignored_rather_than_obeyed(self):
        # Policies are edited in a dashboard; a value that is not a string
        # must not become the action a monitor enforces.
        r = self._resolver({"FILE": {"nested": "object"}, "CLIPBOARD": 42})
        assert r.resolve(self.DETECTIONS, channel="FILE")["action"] == "BLOCK"
        assert r.resolve(self.DETECTIONS, channel="CLIPBOARD")["action"] == "BLOCK"

    def test_the_default_policy_also_honours_channels(self):
        # A detection with no matching compliance rule falls back to the
        # default policy -- which must still respect its own channel rules,
        # or the fallback silently ignores them.
        r = self._resolver({"FILE": "QUARANTINE"})
        unmatched = [{"type": "credit_card", "rule": "PCI-DSS"}]
        assert r.resolve(unmatched, channel="FILE")["action"] == "QUARANTINE"

class TestRiskLadder:
    """
    Risk, severity and action used to be three fields nothing reconciled,
    which is how an incident could read "risk 0.93, severity CRITICAL, action
    ALLOW" -- three statements that cannot all be sensible at once.

    A ladder makes the detector's confidence choose the tier, and the tier
    carries both of the others. They can no longer disagree by accident.
    """

    LADDER = [
        {"minRisk": 0.9, "action": "QUARANTINE", "severity": "CRITICAL"},
        {"minRisk": 0.7, "action": "ALERT",      "severity": "HIGH"},
    ]

    def _resolver(self, tiers=None, **extra):
        client = MagicMock()
        client.list_policies.return_value = [{
            "id": "p", "name": "PII Detection", "action": "BLOCK",
            "severity": "MEDIUM", "enabled": True, "tiers": tiers,
            "conditions": {"complianceRule": "GDPR", "threshold": 1},
            **extra,
        }]
        r = PolicyResolver(client); r.refresh()
        return r

    DETS = [{"type": "email", "rule": "GDPR"}]

    def test_the_top_rung_wins_for_high_confidence(self):
        r = self._resolver(self.LADDER)
        got = r.resolve(self.DETS, channel="FILE", risk_score=0.95)
        assert got["action"] == "QUARANTINE"
        assert got["severity"] == "CRITICAL"

    def test_a_lower_rung_gives_a_softer_response_and_severity(self):
        # Same policy, same data, lower confidence -- and severity moves WITH
        # the action rather than being set independently.
        r = self._resolver(self.LADDER)
        got = r.resolve(self.DETS, channel="FILE", risk_score=0.75)
        assert got["action"] == "ALERT"
        assert got["severity"] == "HIGH"

    def test_below_the_lowest_rung_nothing_happens(self):
        # Not "allowed" -- simply not covered at this confidence. Callers skip
        # NONE entirely, so no incident is written.
        r = self._resolver(self.LADDER)
        assert r.resolve(self.DETS, channel="FILE", risk_score=0.4)["action"] == "NONE"

    def test_the_ladder_says_where_the_decision_came_from(self):
        r = self._resolver(self.LADDER)
        got = r.resolve(self.DETS, channel="FILE", risk_score=0.95)
        assert got["actionSource"].startswith("tier:>=0.9")

    def test_a_stop_is_realised_as_the_action_the_channel_can_perform(self):
        # The ladder expresses intent. A file at rest is stopped by moving it;
        # a paste is stopped by cancelling it. Asking an admin to know that
        # per channel is how BLOCK on a file came to mean nothing at all.
        r = self._resolver([{"minRisk": 0.5, "action": "BLOCK", "severity": "HIGH"}])
        assert r.resolve(self.DETS, channel="FILE", risk_score=0.9)["action"] == "QUARANTINE"
        assert r.resolve(self.DETS, channel="CLIPBOARD", risk_score=0.9)["action"] == "BLOCK"

    def test_allow_on_a_rung_is_still_allow(self):
        # Only BLOCK/QUARANTINE are "stop"; permitting is not translated.
        r = self._resolver([{"minRisk": 0.0, "action": "ALLOW", "severity": "LOW"}])
        assert r.resolve(self.DETS, channel="FILE", risk_score=0.99)["action"] == "ALLOW"

    def test_rungs_are_evaluated_highest_first_whatever_order_they_arrive_in(self):
        r = self._resolver(list(reversed(self.LADDER)))
        assert r.resolve(self.DETS, channel="FILE", risk_score=0.95)["action"] == "QUARANTINE"

    def test_a_policy_with_no_ladder_behaves_exactly_as_before(self):
        r = self._resolver(None, channelActions={"FILE": "QUARANTINE"})
        assert r.resolve(self.DETS, channel="FILE", risk_score=0.95)["action"] == "QUARANTINE"
        assert r.resolve(self.DETS, channel="CLIPBOARD", risk_score=0.95)["action"] == "BLOCK"

    def test_a_ladder_is_ignored_when_no_risk_score_is_supplied(self):
        # An older caller that does not pass one must not fall through to
        # "nothing happens" and silently stop enforcing.
        r = self._resolver(self.LADDER)
        assert r.resolve(self.DETS, channel="FILE")["action"] == "BLOCK"

    def test_a_malformed_rung_is_dropped_rather_than_enforced(self):
        # These arrive from an API and end up deciding what happens to a
        # user's files.
        r = self._resolver([
            {"minRisk": "high", "action": "QUARANTINE"},      # threshold not a number
            {"minRisk": 0.8, "action": "DELETE_EVERYTHING"},  # not in the enum
            {"minRisk": 0.5, "action": "ALERT", "severity": "HIGH"},
        ])
        got = r.resolve(self.DETS, channel="FILE", risk_score=0.95)
        assert got["action"] == "ALERT"

    def test_resolving_one_event_does_not_affect_the_next(self):
        # Shared cache state read from several monitor threads.
        r = self._resolver(self.LADDER)
        assert r.resolve(self.DETS, channel="FILE", risk_score=0.95)["action"] == "QUARANTINE"
        assert r.resolve(self.DETS, channel="FILE", risk_score=0.75)["action"] == "ALERT"
        assert r.resolve(self.DETS, channel="FILE", risk_score=0.95)["action"] == "QUARANTINE"
