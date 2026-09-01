from unittest.mock import MagicMock

from app_rule_resolver import AppRuleResolver


class TestRefresh:
    def test_loads_enabled_rules(self):
        client = MagicMock()
        client.list_app_rules.return_value = [
            {"keyword": "teamviewer", "label": "TeamViewer remote access", "enabled": True},
            {"keyword": "winrar", "label": "WinRAR archiver", "enabled": True},
        ]
        resolver = AppRuleResolver(client)
        resolver.refresh()

        assert resolver.match("TeamViewer.exe") == "TeamViewer remote access"
        assert resolver.match("WinRAR - archive.rar") == "WinRAR archiver"

    def test_skips_disabled_rules(self):
        client = MagicMock()
        client.list_app_rules.return_value = [
            {"keyword": "teamviewer", "label": "TeamViewer remote access", "enabled": False},
        ]
        resolver = AppRuleResolver(client)
        resolver.refresh()

        assert resolver.match("TeamViewer.exe") is None

    def test_keeps_previous_rules_when_fetch_fails(self):
        client = MagicMock()
        client.list_app_rules.return_value = [
            {"keyword": "teamviewer", "label": "TeamViewer", "enabled": True},
        ]
        resolver = AppRuleResolver(client)
        resolver.refresh()

        client.list_app_rules.return_value = None
        resolver.refresh()

        assert resolver.match("TeamViewer.exe") == "TeamViewer"

    def test_defaults_missing_enabled_field_to_true(self):
        client = MagicMock()
        client.list_app_rules.return_value = [{"keyword": "teamviewer", "label": "TeamViewer"}]
        resolver = AppRuleResolver(client)
        resolver.refresh()

        assert resolver.match("teamviewer.exe") == "TeamViewer"


class TestMatch:
    def _resolver_with(self, rules: dict[str, str]) -> AppRuleResolver:
        client = MagicMock()
        client.list_app_rules.return_value = [
            {"keyword": kw, "label": label, "enabled": True} for kw, label in rules.items()
        ]
        resolver = AppRuleResolver(client)
        resolver.refresh()
        return resolver

    def test_no_match_returns_none(self):
        resolver = self._resolver_with({"teamviewer": "TeamViewer"})
        assert resolver.match("Untitled - Notepad") is None

    def test_match_is_case_insensitive(self):
        resolver = self._resolver_with({"teamviewer": "TeamViewer"})
        assert resolver.match("TEAMVIEWER.EXE") == "TeamViewer"

    def test_starts_empty_before_any_refresh(self):
        client = MagicMock()
        resolver = AppRuleResolver(client)
        assert resolver.match("TeamViewer.exe") is None
        client.list_app_rules.assert_not_called()
