from unittest.mock import MagicMock

from policy_resolver import PolicyResolver, DEFAULT_POLICY_ID, DEFAULT_ACTION


def _policy(id_, rule, enabled=True, action="BLOCK", name=None):
    return {
        "id": id_, "enabled": enabled, "action": action, "name": name or id_,
        "conditions": {"complianceRule": rule},
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
