"""Tests for org-level settings audit (ORG001-ORG005)."""

import responses

from pipeaudit.github_client import GitHubClient
from pipeaudit.org_settings import audit_org_settings
from pipeaudit.token_validator import GITHUB_API


class TestOrgSettings:
    @responses.activate
    def test_2fa_not_required(self):
        """2FA not required => ORG001."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": False,
                "default_repository_permission": "read",
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            json={
                "allowed_actions": "selected",
                "default_workflow_permissions": "read",
            },
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "ORG001" in rule_ids
        org001 = [f for f in result["findings"] if f["rule_id"] == "ORG001"]
        assert org001[0]["severity"] == "critical"

    @responses.activate
    def test_2fa_required(self):
        """2FA required => no ORG001."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": True,
                "default_repository_permission": "read",
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            json={
                "allowed_actions": "selected",
                "default_workflow_permissions": "read",
            },
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "ORG001" not in rule_ids

    @responses.activate
    def test_default_permission_write(self):
        """Default permission is 'write' => ORG002."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": True,
                "default_repository_permission": "write",
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            json={
                "allowed_actions": "selected",
                "default_workflow_permissions": "read",
            },
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "ORG002" in rule_ids
        org002 = [f for f in result["findings"] if f["rule_id"] == "ORG002"]
        assert org002[0]["severity"] == "high"

    @responses.activate
    def test_actions_allow_all(self):
        """All actions allowed => ORG003."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": True,
                "default_repository_permission": "read",
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            json={
                "allowed_actions": "all",
                "default_workflow_permissions": "read",
            },
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "ORG003" in rule_ids

    @responses.activate
    def test_default_token_write(self):
        """Default workflow permissions is 'write' => ORG004."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": True,
                "default_repository_permission": "read",
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            json={
                "allowed_actions": "selected",
                "default_workflow_permissions": "write",
            },
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "ORG004" in rule_ids
        org004 = [f for f in result["findings"] if f["rule_id"] == "ORG004"]
        assert org004[0]["severity"] == "high"

    @responses.activate
    def test_all_secure_no_findings(self):
        """All settings secure => no findings."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": True,
                "default_repository_permission": "read",
                "members_can_create_repositories": False,
                "is_verified": True,
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            json={
                "allowed_actions": "selected",
                "default_workflow_permissions": "read",
            },
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        assert len(result["findings"]) == 0

    @responses.activate
    def test_actions_permissions_unavailable(self):
        """Actions permissions 403 => only org-level findings."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": False,
                "default_repository_permission": "write",
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            status=403,
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "ORG001" in rule_ids
        assert "ORG002" in rule_ids
        # No ORG003-ORG005 since actions permissions unavailable
        assert "ORG003" not in rule_ids
        assert "ORG004" not in rule_ids

    @responses.activate
    def test_repo_creation_not_restricted(self):
        """Members can create repos => ORG006."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": True,
                "default_repository_permission": "read",
                "members_can_create_repositories": True,
                "members_can_create_public_repositories": True,
                "members_can_create_private_repositories": True,
                "is_verified": True,
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            json={"allowed_actions": "selected", "default_workflow_permissions": "read"},
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "ORG006" in rule_ids
        org006 = [f for f in result["findings"] if f["rule_id"] == "ORG006"]
        assert org006[0]["severity"] == "medium"

    @responses.activate
    def test_org_not_verified(self):
        """Org not verified => ORG007."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg",
            json={
                "two_factor_requirement_enabled": True,
                "default_repository_permission": "read",
                "members_can_create_repositories": False,
                "is_verified": False,
            },
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/testorg/actions/permissions",
            json={"allowed_actions": "selected", "default_workflow_permissions": "read"},
        )

        client = GitHubClient("test-token")
        result = audit_org_settings(client, "testorg")

        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "ORG007" in rule_ids
        org007 = [f for f in result["findings"] if f["rule_id"] == "ORG007"]
        assert org007[0]["severity"] == "low"
