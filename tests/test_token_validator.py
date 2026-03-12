"""Tests for token validation."""

import pytest
import responses

from gh_auditor.token_validator import (
    TokenPermissionError,
    validate_token,
    _reject_classic_pat,
    _check_required_read_permissions,
    GITHUB_API,
)


class TestRejectClassicPat:
    def test_rejects_classic_with_repo_scope(self):
        with pytest.raises(TokenPermissionError, match="Classic PAT.*write/admin"):
            _reject_classic_pat("repo, read:org")

    def test_rejects_classic_with_public_repo_scope(self):
        with pytest.raises(TokenPermissionError, match="Classic PAT.*write/admin"):
            _reject_classic_pat("public_repo")

    def test_rejects_classic_with_admin_org_scope(self):
        with pytest.raises(TokenPermissionError, match="Classic PAT.*write/admin"):
            _reject_classic_pat("admin:org")

    def test_rejects_classic_with_delete_repo_scope(self):
        with pytest.raises(TokenPermissionError, match="Classic PAT.*write/admin"):
            _reject_classic_pat("delete_repo")

    def test_rejects_classic_with_read_only_scopes(self):
        """Even read-only classic PATs are rejected (can't access private repos)."""
        with pytest.raises(TokenPermissionError, match="Classic PAT detected"):
            _reject_classic_pat("read:org, repo:status")

    def test_rejects_classic_with_empty_scopes(self):
        with pytest.raises(TokenPermissionError, match="Classic PAT detected"):
            _reject_classic_pat("")


class TestCheckRequiredReadPermissions:
    @responses.activate
    def test_passes_with_all_permissions(self):
        """Token with all required read permissions should pass."""
        # Members: Read
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/members",
            json=[{"login": "user1"}],
            status=200,
        )
        # Metadata: Read (list repos)
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/repos",
            json=[{"full_name": "myorg/repo1"}],
            status=200,
        )
        # Contents: Read
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/contents/.github",
            json=[],
            status=200,
        )
        # Administration: Read (repo-level)
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/collaborators",
            json=[{"login": "user1"}],
            status=200,
        )
        # Administration: Read (org-level, for apps & tokens)
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/installations",
            json={"total_count": 0, "installations": []},
            status=200,
        )
        # Should not raise
        _check_required_read_permissions("good-token", "myorg")

    @responses.activate
    def test_fails_missing_members_read(self):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/members",
            status=403,
            json={"message": "Resource not accessible"},
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/repos",
            json=[{"full_name": "myorg/repo1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/contents/.github",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/collaborators",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/installations",
            json={"total_count": 0, "installations": []},
            status=200,
        )
        with pytest.raises(TokenPermissionError, match="Members.*Read-only"):
            _check_required_read_permissions("bad-token", "myorg")

    @responses.activate
    def test_fails_missing_contents_read(self):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/members",
            json=[{"login": "user1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/repos",
            json=[{"full_name": "myorg/repo1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/contents/.github",
            status=403,
            json={"message": "Resource not accessible"},
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/collaborators",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/installations",
            json={"total_count": 0, "installations": []},
            status=200,
        )
        with pytest.raises(TokenPermissionError, match="Contents.*Read-only"):
            _check_required_read_permissions("bad-token", "myorg")

    @responses.activate
    def test_warns_missing_admin_read(self):
        """Missing Administration:Read is a warning, not a hard failure.

        Some orgs restrict fine-grained PAT access to admin endpoints.
        The audit continues with degraded functionality.
        """
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/members",
            json=[{"login": "user1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/repos",
            json=[{"full_name": "myorg/repo1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/contents/.github",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/collaborators",
            status=403,
            json={"message": "Resource not accessible"},
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/installations",
            json={"total_count": 0, "installations": []},
            status=200,
        )
        # Should not raise — admin read is optional
        _check_required_read_permissions("limited-token", "myorg")

    @responses.activate
    def test_contents_404_is_ok(self):
        """A 404 on .github dir means dir doesn't exist, not a permission issue."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/members",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/repos",
            json=[{"full_name": "myorg/repo1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/contents/.github",
            status=404,
            json={"message": "Not Found"},
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/collaborators",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/installations",
            json={"total_count": 0, "installations": []},
            status=200,
        )
        # Should not raise — 404 is fine, it just means no .github dir
        _check_required_read_permissions("good-token", "myorg")


class TestValidateToken:
    @responses.activate
    def test_rejects_invalid_token(self):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/user",
            status=401,
            json={"message": "Bad credentials"},
        )
        with pytest.raises(TokenPermissionError, match="authentication failed"):
            validate_token("bad-token", "myorg")

    @responses.activate
    def test_rejects_classic_pat_with_write_scopes(self):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/user",
            status=200,
            json={"login": "testuser"},
            headers={"X-OAuth-Scopes": "repo, read:org"},
        )
        with pytest.raises(TokenPermissionError, match="Classic PAT"):
            validate_token("classic-write-token", "myorg")

    @responses.activate
    def test_rejects_classic_pat_with_read_only_scopes(self):
        """Classic PATs are always rejected, even with read-only scopes."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/user",
            status=200,
            json={"login": "testuser"},
            headers={"X-OAuth-Scopes": "read:org, repo:status"},
        )
        with pytest.raises(TokenPermissionError, match="Classic PAT"):
            validate_token("classic-ro-token", "myorg")

    @responses.activate
    def test_accepts_fine_grained_pat_with_correct_permissions(self):
        # Fine-grained PATs don't return X-OAuth-Scopes header
        responses.add(
            responses.GET,
            f"{GITHUB_API}/user",
            status=200,
            json={"login": "testuser"},
            headers={},  # no X-OAuth-Scopes
        )
        # Read permission checks
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/members",
            json=[{"login": "user1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/repos",
            json=[{"full_name": "myorg/repo1"}],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/contents/.github",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/myorg/repo1/collaborators",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/installations",
            json={"total_count": 0, "installations": []},
            status=200,
        )

        result = validate_token("fine-grained-ro", "myorg")
        assert result["login"] == "testuser"

    @responses.activate
    def test_rejects_fine_grained_pat_missing_read_permissions(self):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/user",
            status=200,
            json={"login": "testuser"},
            headers={},
        )
        # Members: Read fails
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/members",
            status=403,
            json={"message": "Resource not accessible"},
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/repos",
            json=[],
            status=200,
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/myorg/installations",
            json={"total_count": 0, "installations": []},
            status=200,
        )
        with pytest.raises(TokenPermissionError, match="missing required permissions"):
            validate_token("insufficient-token", "myorg")
