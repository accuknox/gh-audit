"""Tests for Azure DevOps identity/access rules (AIM001-AIM005)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from pipeaudit.azure.identity import audit_identity


def _make_client(users=None, groups=None, members_by_descriptor=None, connections=None):
    client = MagicMock()
    client.list_users.return_value = users or []
    client.list_groups.return_value = groups or []
    client.list_service_connections.return_value = connections or []

    def _list_members(descriptor):
        return (members_by_descriptor or {}).get(descriptor, [])

    client.list_group_members.side_effect = _list_members
    return client


class TestAIM001:
    def test_excessive_admins(self):
        groups = [{
            "displayName": "Project Administrators",
            "principalName": "[TestProject]\\Project Administrators",
            "descriptor": "admin-desc",
        }]
        members = {
            "admin-desc": [{"displayName": f"User{i}"} for i in range(7)],
        }
        client = _make_client(groups=groups, members_by_descriptor=members)
        projects = [{"name": "TestProject"}]
        report = audit_identity(client, projects)
        aim001 = [f for f in report["findings"] if f["rule_id"] == "AIM001"]
        assert len(aim001) == 1
        assert "7" in aim001[0]["title"]

    def test_normal_admin_count(self):
        groups = [{
            "displayName": "Project Administrators",
            "principalName": "[TestProject]\\Project Administrators",
            "descriptor": "admin-desc",
        }]
        members = {
            "admin-desc": [{"displayName": f"User{i}"} for i in range(3)],
        }
        client = _make_client(groups=groups, members_by_descriptor=members)
        projects = [{"name": "TestProject"}]
        report = audit_identity(client, projects)
        aim001 = [f for f in report["findings"] if f["rule_id"] == "AIM001"]
        assert len(aim001) == 0


class TestAIM002:
    def test_inactive_users(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        users = [
            {"displayName": "OldUser", "lastAccessedDate": old_date},
            {"displayName": "ActiveUser", "lastAccessedDate": datetime.now(timezone.utc).isoformat()},
        ]
        client = _make_client(users=users)
        report = audit_identity(client, [])
        aim002 = [f for f in report["findings"] if f["rule_id"] == "AIM002"]
        assert len(aim002) == 1
        assert "OldUser" in aim002[0]["users"]

    def test_no_inactive_users(self):
        recent = datetime.now(timezone.utc).isoformat()
        users = [
            {"displayName": "User1", "lastAccessedDate": recent},
        ]
        client = _make_client(users=users)
        report = audit_identity(client, [])
        aim002 = [f for f in report["findings"] if f["rule_id"] == "AIM002"]
        assert len(aim002) == 0


class TestAIM003:
    def test_guest_in_privileged_group(self):
        groups = [{
            "displayName": "Project Administrators",
            "descriptor": "pa-desc",
        }]
        members = {
            "pa-desc": [{
                "displayName": "External Guest",
                "origin": "aad",
                "subjectKind": "user",
                "mailAddress": "guest#EXT#@company.onmicrosoft.com",
            }],
        }
        client = _make_client(groups=groups, members_by_descriptor=members)
        report = audit_identity(client, [])
        aim003 = [f for f in report["findings"] if f["rule_id"] == "AIM003"]
        assert len(aim003) == 1

    def test_regular_user_in_privileged_group(self):
        groups = [{
            "displayName": "Project Administrators",
            "descriptor": "pa-desc",
        }]
        members = {
            "pa-desc": [{
                "displayName": "Normal User",
                "origin": "aad",
                "subjectKind": "user",
                "mailAddress": "user@company.com",
            }],
        }
        client = _make_client(groups=groups, members_by_descriptor=members)
        report = audit_identity(client, [])
        aim003 = [f for f in report["findings"] if f["rule_id"] == "AIM003"]
        assert len(aim003) == 0


class TestAIM004:
    def test_service_connection_no_expiry(self):
        connections = [{
            "name": "azure-sub",
            "type": "azurerm",
            "authorization": {"parameters": {}},
            "data": {},
        }]
        client = _make_client(connections=connections)
        projects = [{"name": "TestProject"}]
        report = audit_identity(client, projects)
        aim004 = [f for f in report["findings"] if f["rule_id"] == "AIM004"]
        assert len(aim004) == 1

    def test_service_connection_with_expiry(self):
        connections = [{
            "name": "azure-sub",
            "type": "azurerm",
            "authorization": {"parameters": {"tenantExpirationDate": "2025-12-31"}},
            "data": {},
        }]
        client = _make_client(connections=connections)
        projects = [{"name": "TestProject"}]
        report = audit_identity(client, projects)
        aim004 = [f for f in report["findings"] if f["rule_id"] == "AIM004"]
        assert len(aim004) == 0

    def test_non_azurerm_connection_ignored(self):
        connections = [{
            "name": "generic",
            "type": "generic",
            "authorization": {"parameters": {}},
            "data": {},
        }]
        client = _make_client(connections=connections)
        projects = [{"name": "TestProject"}]
        report = audit_identity(client, projects)
        aim004 = [f for f in report["findings"] if f["rule_id"] == "AIM004"]
        assert len(aim004) == 0
