"""Tests for GitLab group settings rules (GLG001-GLG005)."""

from unittest.mock import MagicMock

from pipeaudit.gitlab.group_settings import audit_group_settings


def _make_client(group_data=None):
    client = MagicMock()
    client.get_group.return_value = group_data or {}
    return client


class TestGLG001:
    def test_public_group(self):
        client = _make_client({"visibility": "public"})
        findings = audit_group_settings(client, "my-group")
        glg001 = [f for f in findings if f["rule_id"] == "GLG001"]
        assert len(glg001) == 1

    def test_private_group(self):
        client = _make_client({"visibility": "private"})
        findings = audit_group_settings(client, "my-group")
        glg001 = [f for f in findings if f["rule_id"] == "GLG001"]
        assert len(glg001) == 0


class TestGLG002:
    def test_2fa_not_required(self):
        client = _make_client({"require_two_factor_authentication": False})
        findings = audit_group_settings(client, "my-group")
        glg002 = [f for f in findings if f["rule_id"] == "GLG002"]
        assert len(glg002) == 1

    def test_2fa_required(self):
        client = _make_client({"require_two_factor_authentication": True})
        findings = audit_group_settings(client, "my-group")
        glg002 = [f for f in findings if f["rule_id"] == "GLG002"]
        assert len(glg002) == 0


class TestGLG003:
    def test_developer_can_create(self):
        client = _make_client({"project_creation_level": "developer"})
        findings = audit_group_settings(client, "my-group")
        glg003 = [f for f in findings if f["rule_id"] == "GLG003"]
        assert len(glg003) == 1

    def test_maintainer_only(self):
        client = _make_client({"project_creation_level": "maintainer"})
        findings = audit_group_settings(client, "my-group")
        glg003 = [f for f in findings if f["rule_id"] == "GLG003"]
        assert len(glg003) == 0


class TestGLG004:
    def test_forking_allowed(self):
        client = _make_client({"prevent_forking_outside_group": False})
        findings = audit_group_settings(client, "my-group")
        glg004 = [f for f in findings if f["rule_id"] == "GLG004"]
        assert len(glg004) == 1

    def test_forking_prevented(self):
        client = _make_client({"prevent_forking_outside_group": True})
        findings = audit_group_settings(client, "my-group")
        glg004 = [f for f in findings if f["rule_id"] == "GLG004"]
        assert len(glg004) == 0


class TestGLG005:
    def test_shared_runners_enabled(self):
        client = _make_client({"shared_runners_setting": "enabled"})
        findings = audit_group_settings(client, "my-group")
        glg005 = [f for f in findings if f["rule_id"] == "GLG005"]
        assert len(glg005) == 1

    def test_shared_runners_disabled(self):
        client = _make_client({"shared_runners_setting": "disabled_and_unoverridable"})
        findings = audit_group_settings(client, "my-group")
        glg005 = [f for f in findings if f["rule_id"] == "GLG005"]
        assert len(glg005) == 0
