"""Tests for Azure DevOps project settings rules (AOG001-AOG005)."""

from unittest.mock import MagicMock

from pipeaudit.azure.project_settings import audit_project_settings


def _make_client(properties=None, teams=None):
    client = MagicMock()
    client.get_project_properties.return_value = properties or []
    client.list_project_teams.return_value = teams or []
    return client


class TestAOG001:
    def test_guest_access_enabled(self):
        props = [{"name": "System.GuestAccessEnabled", "value": "True"}]
        client = _make_client(properties=props)
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "private"},
        )
        aog001 = [f for f in findings if f["rule_id"] == "AOG001"]
        assert len(aog001) == 1
        assert aog001[0]["severity"] == "high"

    def test_guest_access_disabled(self):
        props = [{"name": "System.GuestAccessEnabled", "value": "False"}]
        client = _make_client(properties=props)
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "private"},
        )
        aog001 = [f for f in findings if f["rule_id"] == "AOG001"]
        assert len(aog001) == 0


class TestAOG002:
    def test_public_project(self):
        client = _make_client()
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "public"},
        )
        aog002 = [f for f in findings if f["rule_id"] == "AOG002"]
        assert len(aog002) == 1

    def test_private_project(self):
        client = _make_client()
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "private"},
        )
        aog002 = [f for f in findings if f["rule_id"] == "AOG002"]
        assert len(aog002) == 0


class TestAOG003:
    def test_third_party_oauth_enabled(self):
        props = [{"name": "System.ThirdPartyOAuthEnabled", "value": "True"}]
        client = _make_client(properties=props)
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "private"},
        )
        aog003 = [f for f in findings if f["rule_id"] == "AOG003"]
        assert len(aog003) == 1


class TestAOG004:
    def test_ssh_unrestricted(self):
        client = _make_client()
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "private"},
        )
        aog004 = [f for f in findings if f["rule_id"] == "AOG004"]
        assert len(aog004) == 1
        assert aog004[0]["severity"] == "low"

    def test_ssh_disabled(self):
        props = [{"name": "System.SSHAuthenticationDisabled", "value": "True"}]
        client = _make_client(properties=props)
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "private"},
        )
        aog004 = [f for f in findings if f["rule_id"] == "AOG004"]
        assert len(aog004) == 0


class TestAOG005:
    def test_contributors_elevated(self):
        teams = [{"name": "MyProject Contributors", "identity": {"isTeamAdmin": True}}]
        client = _make_client(teams=teams)
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "private"},
        )
        aog005 = [f for f in findings if f["rule_id"] == "AOG005"]
        assert len(aog005) == 1

    def test_contributors_normal(self):
        teams = [{"name": "MyProject Contributors", "identity": {"isTeamAdmin": False}}]
        client = _make_client(teams=teams)
        findings = audit_project_settings(
            client, "MyProject", {"id": "p1", "visibility": "private"},
        )
        aog005 = [f for f in findings if f["rule_id"] == "AOG005"]
        assert len(aog005) == 0
