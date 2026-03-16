"""Tests for GitLab identity/access rules (GLI001-GLI005)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from pipeaudit.gitlab.identity import audit_identity


def _make_client(members=None, access_requests=None):
    client = MagicMock()
    client.list_group_members.return_value = members or []
    client.list_group_access_requests.return_value = access_requests or []
    return client


class TestGLI001:
    def test_excessive_owners(self):
        members = [
            {"username": f"owner{i}", "access_level": 50}
            for i in range(7)
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli001 = [f for f in report["findings"] if f["rule_id"] == "GLI001"]
        assert len(gli001) == 1
        assert "7" in gli001[0]["title"]

    def test_normal_owner_count(self):
        members = [
            {"username": f"owner{i}", "access_level": 50}
            for i in range(3)
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli001 = [f for f in report["findings"] if f["rule_id"] == "GLI001"]
        assert len(gli001) == 0


class TestGLI002:
    def test_inactive_members(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%d")
        members = [
            {"username": "old-user", "access_level": 30, "last_activity_on": old_date},
            {"username": "active-user", "access_level": 30, "last_activity_on": datetime.now(timezone.utc).strftime("%Y-%m-%d")},
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli002 = [f for f in report["findings"] if f["rule_id"] == "GLI002"]
        assert len(gli002) == 1
        assert "1 inactive" in gli002[0]["title"]

    def test_no_inactive_members(self):
        recent = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        members = [
            {"username": "user1", "access_level": 30, "last_activity_on": recent},
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli002 = [f for f in report["findings"] if f["rule_id"] == "GLI002"]
        assert len(gli002) == 0


class TestGLI003:
    def test_external_user_elevated(self):
        members = [
            {"username": "external-dev", "access_level": 30, "external": True},
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli003 = [f for f in report["findings"] if f["rule_id"] == "GLI003"]
        assert len(gli003) == 1

    def test_external_user_low_access(self):
        members = [
            {"username": "external-guest", "access_level": 10, "external": True},
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli003 = [f for f in report["findings"] if f["rule_id"] == "GLI003"]
        assert len(gli003) == 0


class TestGLI004:
    def test_pending_requests(self):
        client = _make_client(
            access_requests=[{"username": "requester1"}, {"username": "requester2"}]
        )
        report = audit_identity(client, "my-group")
        gli004 = [f for f in report["findings"] if f["rule_id"] == "GLI004"]
        assert len(gli004) == 1
        assert "2 pending" in gli004[0]["title"]

    def test_no_pending_requests(self):
        client = _make_client(access_requests=[])
        report = audit_identity(client, "my-group")
        gli004 = [f for f in report["findings"] if f["rule_id"] == "GLI004"]
        assert len(gli004) == 0


class TestGLI005:
    def test_bot_account(self):
        members = [
            {"username": "project-bot", "access_level": 30, "user_type": "project_bot"},
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli005 = [f for f in report["findings"] if f["rule_id"] == "GLI005"]
        assert len(gli005) == 1

    def test_service_account(self):
        members = [
            {"username": "svc-account", "access_level": 30, "user_type": "service_account"},
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli005 = [f for f in report["findings"] if f["rule_id"] == "GLI005"]
        assert len(gli005) == 1

    def test_normal_user(self):
        members = [
            {"username": "normal-user", "access_level": 30, "user_type": ""},
        ]
        client = _make_client(members=members)
        report = audit_identity(client, "my-group")
        gli005 = [f for f in report["findings"] if f["rule_id"] == "GLI005"]
        assert len(gli005) == 0
