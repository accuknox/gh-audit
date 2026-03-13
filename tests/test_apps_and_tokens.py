"""Tests for the apps_and_tokens audit module."""

from datetime import datetime, timedelta, timezone

import responses

from pipeaudit.apps_and_tokens import audit_apps_and_tokens, INACTIVITY_DAYS
from pipeaudit.github_client import GitHubClient, GITHUB_API


def _make_client():
    return GitHubClient("fake-token")


def _old_date(days: int = INACTIVITY_DAYS + 10) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _recent_date() -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=5)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _mock_installations(apps: list[dict], status: int = 200):
    responses.add(
        responses.GET,
        f"{GITHUB_API}/orgs/test-org/installations",
        json={"total_count": len(apps), "installations": apps},
        status=status,
    )


def _mock_pats(pats: list[dict], status: int = 200):
    responses.add(
        responses.GET,
        f"{GITHUB_API}/orgs/test-org/personal-access-tokens",
        json=pats,
        status=status,
    )


class TestAppChecks:
    @responses.activate
    def test_inactive_app(self):
        _mock_installations([{
            "app_slug": "old-bot",
            "updated_at": _old_date(),
            "permissions": {},
            "repository_selection": "selected",
            "suspended_at": None,
            "events": [],
        }])
        _mock_pats([])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "APP001" in rule_ids

    @responses.activate
    def test_overly_permissive_app(self):
        _mock_installations([{
            "app_slug": "admin-bot",
            "updated_at": _recent_date(),
            "permissions": {"contents": "write", "administration": "admin"},
            "repository_selection": "selected",
            "suspended_at": None,
            "events": [],
        }])
        _mock_pats([])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "APP002" in rule_ids

    @responses.activate
    def test_app_all_repos(self):
        _mock_installations([{
            "app_slug": "wide-bot",
            "updated_at": _recent_date(),
            "permissions": {},
            "repository_selection": "all",
            "suspended_at": None,
            "events": [],
        }])
        _mock_pats([])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "APP003" in rule_ids

    @responses.activate
    def test_suspended_app(self):
        _mock_installations([{
            "app_slug": "paused-bot",
            "updated_at": _recent_date(),
            "permissions": {},
            "repository_selection": "selected",
            "suspended_at": "2024-01-01T00:00:00Z",
            "events": [],
        }])
        _mock_pats([])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "APP004" in rule_ids

    @responses.activate
    def test_sensitive_events(self):
        _mock_installations([{
            "app_slug": "event-bot",
            "updated_at": _recent_date(),
            "permissions": {},
            "repository_selection": "selected",
            "suspended_at": None,
            "events": ["push", "member"],
        }])
        _mock_pats([])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "APP005" in rule_ids

    @responses.activate
    def test_clean_app_no_findings(self):
        _mock_installations([{
            "app_slug": "clean-bot",
            "updated_at": _recent_date(),
            "permissions": {"metadata": "read"},
            "repository_selection": "selected",
            "suspended_at": None,
            "events": ["issues"],
        }])
        _mock_pats([])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        assert len(result["findings"]) == 0


class TestPatChecks:
    @responses.activate
    def test_pat_no_expiration(self):
        _mock_installations([])
        _mock_pats([{
            "id": 1,
            "name": "no-expire-token",
            "owner": {"login": "alice"},
            "token_expires_at": None,
            "token_last_used_at": _recent_date(),
            "permissions": {"repository": {"metadata": "read"}},
            "repository_selection": "selected",
            "token_expired": False,
        }])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "PAT001" in rule_ids

    @responses.activate
    def test_inactive_pat(self):
        _mock_installations([])
        _mock_pats([{
            "id": 2,
            "name": "stale-token",
            "owner": {"login": "bob"},
            "token_expires_at": "2027-01-01T00:00:00Z",
            "token_last_used_at": _old_date(),
            "permissions": {"repository": {"metadata": "read"}},
            "repository_selection": "selected",
            "token_expired": False,
        }])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "PAT002" in rule_ids

    @responses.activate
    def test_pat_broad_permissions(self):
        _mock_installations([])
        _mock_pats([{
            "id": 3,
            "name": "admin-token",
            "owner": {"login": "charlie"},
            "token_expires_at": "2027-01-01T00:00:00Z",
            "token_last_used_at": _recent_date(),
            "permissions": {"repository": {"administration": "write", "contents": "write"}},
            "repository_selection": "selected",
            "token_expired": False,
        }])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "PAT003" in rule_ids

    @responses.activate
    def test_pat_all_repos(self):
        _mock_installations([])
        _mock_pats([{
            "id": 4,
            "name": "wide-token",
            "owner": {"login": "dave"},
            "token_expires_at": "2027-01-01T00:00:00Z",
            "token_last_used_at": _recent_date(),
            "permissions": {"repository": {"metadata": "read"}},
            "repository_selection": "all",
            "token_expired": False,
        }])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "PAT004" in rule_ids

    @responses.activate
    def test_pat_expired(self):
        _mock_installations([])
        _mock_pats([{
            "id": 5,
            "name": "expired-token",
            "owner": {"login": "eve"},
            "token_expires_at": "2024-01-01T00:00:00Z",
            "token_last_used_at": _recent_date(),
            "permissions": {"repository": {"metadata": "read"}},
            "repository_selection": "selected",
            "token_expired": True,
        }])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert "PAT005" in rule_ids

    @responses.activate
    def test_clean_pat_no_findings(self):
        _mock_installations([])
        _mock_pats([{
            "id": 6,
            "name": "good-token",
            "owner": {"login": "frank"},
            "token_expires_at": "2027-01-01T00:00:00Z",
            "token_last_used_at": _recent_date(),
            "permissions": {"repository": {"metadata": "read"}},
            "repository_selection": "selected",
            "token_expired": False,
        }])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        assert len(result["findings"]) == 0


class TestGracefulDegradation:
    @responses.activate
    def test_graceful_403_installations(self):
        _mock_installations([], status=403)
        _mock_pats([])
        result = audit_apps_and_tokens(_make_client(), "test-org")
        assert result["findings"] == []
        assert result["app_installations"] == []

    @responses.activate
    def test_graceful_403_pats(self):
        _mock_installations([])
        _mock_pats([], status=403)
        result = audit_apps_and_tokens(_make_client(), "test-org")
        assert result["findings"] == []
        assert result["fine_grained_pats"] == []


class TestPaginateKey:
    """Test that _paginate correctly unwraps envelope-style responses."""

    @responses.activate
    def test_paginate_with_key(self):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/test-org/installations",
            json={"total_count": 2, "installations": [
                {"app_slug": "a"}, {"app_slug": "b"},
            ]},
            status=200,
        )
        client = _make_client()
        items = client._paginate(
            f"{GITHUB_API}/orgs/test-org/installations",
            params={"per_page": 100},
            key="installations",
        )
        assert len(items) == 2
        assert items[0]["app_slug"] == "a"

    @responses.activate
    def test_paginate_without_key(self):
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/test-org/personal-access-tokens",
            json=[{"id": 1}, {"id": 2}],
            status=200,
        )
        client = _make_client()
        items = client._paginate(
            f"{GITHUB_API}/orgs/test-org/personal-access-tokens",
            params={"per_page": 100},
        )
        assert len(items) == 2


class TestScoringIntegration:
    """Test that apps_tokens_penalty integrates into org scoring."""

    def test_apps_tokens_penalty_deducted(self):
        from pipeaudit.scoring import score_org

        report = {
            "repos": [{"repo": "org/r1", "findings": []}],
            "apps_and_tokens": {
                "findings": [
                    {"rule_id": "APP002", "severity": "high"},
                    {"rule_id": "PAT001", "severity": "high"},
                ],
            },
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        assert result["apps_tokens_penalty"] == 14.0  # 7 + 7 (under cap of 15)
        assert result["score"] == 86.0  # 100 - 14

    def test_apps_tokens_penalty_capped(self):
        """Many findings should be capped at ORG_CATEGORY_PENALTY_CAP."""
        from pipeaudit.scoring import score_org, ORG_CATEGORY_PENALTY_CAP

        report = {
            "repos": [{"repo": "org/r1", "findings": []}],
            "apps_and_tokens": {
                "findings": [
                    {"rule_id": "APP001", "severity": "medium"},
                    {"rule_id": "APP002", "severity": "high"},
                    {"rule_id": "APP003", "severity": "high"},
                    {"rule_id": "PAT001", "severity": "high"},
                    {"rule_id": "PAT002", "severity": "medium"},
                    {"rule_id": "PAT003", "severity": "high"},
                ],
            },
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        # Raw: 4+7+7+7+4+7 = 36, but capped at 15
        assert result["apps_tokens_penalty"] == ORG_CATEGORY_PENALTY_CAP
        assert result["score"] == 100.0 - ORG_CATEGORY_PENALTY_CAP
