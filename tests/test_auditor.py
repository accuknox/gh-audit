"""Tests for the auditor orchestration."""

import base64
import json

import pytest
import responses
import yaml

from gh_auditor.auditor import AuditConfig, RepoSpec, run_audit, _audit_branch_protection, _audit_repo_security
from gh_auditor.github_client import GitHubClient
from gh_auditor.token_validator import GITHUB_API


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _mock_branch_protection_404(org: str, repo: str, branch: str = "main"):
    """Add a 404 response for branch protection (no protection configured)."""
    responses.add(
        responses.GET,
        f"{GITHUB_API}/repos/{org}/{repo}/branches/{branch}/protection",
        status=404,
    )


SAMPLE_WORKFLOW = yaml.dump({
    "on": {"pull_request_target": {}},
    "jobs": {
        "build": {
            "runs-on": "ubuntu-latest",
            "steps": [
                {"uses": "actions/checkout@v4"},
                {"run": 'echo "${{ github.event.pull_request.title }}"'},
            ],
        }
    },
})


class TestRunAudit:
    @responses.activate
    def test_audits_org_repos(self):
        org = "testorg"

        # List repos
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/repos",
            json=[
                {
                    "full_name": f"{org}/myrepo",
                    "name": "myrepo",
                    "private": False,
                    "visibility": "public",
                    "archived": False,
                    "fork": False,
                    "default_branch": "main",
                },
            ],
        )

        # List workflow files
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/myrepo/contents/.github/workflows",
            json=[
                {"name": "ci.yml", "type": "file"},
            ],
        )

        # Get file content
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/myrepo/contents/.github/workflows/ci.yml",
            json={
                "content": _b64(SAMPLE_WORKFLOW),
                "encoding": "base64",
            },
        )

        _mock_branch_protection_404(org, "myrepo")

        config = AuditConfig(org=org, token="test-token")
        report = run_audit(config)

        assert report["audit_metadata"]["total_repos_scanned"] == 1
        assert report["audit_metadata"]["total_workflows_scanned"] == 1
        assert report["audit_metadata"]["total_findings"] > 0

        # Should detect pull_request_target (GHA001) and script injection (GHA002)
        repo_findings = report["repos"][0]["findings"]
        rule_ids = {f["rule_id"] for f in repo_findings}
        assert "GHA001" in rule_ids
        assert "GHA002" in rule_ids

    @responses.activate
    def test_skips_archived_by_default(self):
        org = "testorg"
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/repos",
            json=[
                {
                    "full_name": f"{org}/archived-repo",
                    "name": "archived-repo",
                    "private": False,
                    "visibility": "public",
                    "archived": True,
                    "fork": False,
                    "default_branch": "main",
                },
            ],
        )

        config = AuditConfig(org=org, token="test-token")
        report = run_audit(config)
        assert report["audit_metadata"]["total_repos_scanned"] == 0

    @responses.activate
    def test_audits_specific_repo_and_branch(self):
        org = "testorg"

        # Get repo metadata
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/myrepo",
            json={
                "full_name": f"{org}/myrepo",
                "name": "myrepo",
                "private": False,
                "visibility": "public",
                "archived": False,
                "fork": False,
                "default_branch": "main",
            },
        )

        # List workflow files on develop branch
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/myrepo/contents/.github/workflows",
            json=[],
        )

        _mock_branch_protection_404(org, "myrepo", branch="develop")

        config = AuditConfig(
            org=org,
            token="test-token",
            repo_specs=[RepoSpec(owner=org, repo="myrepo", branch="develop")],
        )
        report = run_audit(config)
        assert report["repos"][0]["branch"] == "develop"

    @responses.activate
    def test_handles_repo_with_no_workflows(self):
        org = "testorg"
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/repos",
            json=[
                {
                    "full_name": f"{org}/empty-repo",
                    "name": "empty-repo",
                    "private": True,
                    "visibility": "private",
                    "archived": False,
                    "fork": False,
                    "default_branch": "main",
                },
            ],
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/empty-repo/contents/.github/workflows",
            status=404,
        )

        _mock_branch_protection_404(org, "empty-repo")

        config = AuditConfig(org=org, token="test-token")
        report = run_audit(config)
        assert report["repos"][0]["workflows_scanned"] == 0
        # Should have branch protection findings even with no workflows
        bpr_findings = [f for f in report["repos"][0]["findings"] if f["rule_id"].startswith("BPR")]
        assert len(bpr_findings) > 0

    @responses.activate
    def test_regex_repo_spec_matches_multiple_repos(self):
        org = "testorg"

        # List all org repos (fetched because of regex spec)
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/repos",
            json=[
                {
                    "full_name": f"{org}/frontend-app",
                    "name": "frontend-app",
                    "private": False,
                    "archived": False,
                    "fork": False,
                    "default_branch": "main",
                },
                {
                    "full_name": f"{org}/frontend-lib",
                    "name": "frontend-lib",
                    "private": False,
                    "archived": False,
                    "fork": False,
                    "default_branch": "main",
                },
                {
                    "full_name": f"{org}/backend-api",
                    "name": "backend-api",
                    "private": False,
                    "archived": False,
                    "fork": False,
                    "default_branch": "main",
                },
            ],
        )

        # Workflow listing for matched repos
        for repo in ("frontend-app", "frontend-lib"):
            responses.add(
                responses.GET,
                f"{GITHUB_API}/repos/{org}/{repo}/contents/.github/workflows",
                json=[],
            )
            _mock_branch_protection_404(org, repo)

        config = AuditConfig(
            org=org,
            token="test-token",
            repo_specs=[RepoSpec(owner=org, repo="frontend-.*", is_regex=True)],
        )
        report = run_audit(config)

        scanned_repos = {r["repo"] for r in report["repos"]}
        assert f"{org}/frontend-app" in scanned_repos
        assert f"{org}/frontend-lib" in scanned_repos
        assert f"{org}/backend-api" not in scanned_repos

    @responses.activate
    def test_regex_skips_archived_by_default(self):
        org = "testorg"

        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/repos",
            json=[
                {
                    "full_name": f"{org}/frontend-old",
                    "name": "frontend-old",
                    "private": False,
                    "archived": True,
                    "fork": False,
                    "default_branch": "main",
                },
                {
                    "full_name": f"{org}/frontend-new",
                    "name": "frontend-new",
                    "private": False,
                    "archived": False,
                    "fork": False,
                    "default_branch": "main",
                },
            ],
        )

        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/frontend-new/contents/.github/workflows",
            json=[],
        )
        _mock_branch_protection_404(org, "frontend-new")

        config = AuditConfig(
            org=org,
            token="test-token",
            repo_specs=[RepoSpec(owner=org, repo="frontend-.*", is_regex=True)],
        )
        report = run_audit(config)

        scanned_repos = {r["repo"] for r in report["repos"]}
        assert f"{org}/frontend-new" in scanned_repos
        assert f"{org}/frontend-old" not in scanned_repos

    @responses.activate
    def test_regex_and_exact_specs_combined(self):
        org = "testorg"

        # Org repos (for regex matching)
        responses.add(
            responses.GET,
            f"{GITHUB_API}/orgs/{org}/repos",
            json=[
                {
                    "full_name": f"{org}/svc-auth",
                    "name": "svc-auth",
                    "private": False,
                    "archived": False,
                    "fork": False,
                    "default_branch": "main",
                },
                {
                    "full_name": f"{org}/svc-billing",
                    "name": "svc-billing",
                    "private": False,
                    "archived": False,
                    "fork": False,
                    "default_branch": "main",
                },
            ],
        )

        # Exact repo spec
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/{org}/infra",
            json={
                "full_name": f"{org}/infra",
                "name": "infra",
                "private": True,
                "archived": False,
                "fork": False,
                "default_branch": "main",
            },
        )

        # Workflow listings
        for repo in ("svc-auth", "svc-billing", "infra"):
            responses.add(
                responses.GET,
                f"{GITHUB_API}/repos/{org}/{repo}/contents/.github/workflows",
                json=[],
            )
            _mock_branch_protection_404(org, repo)

        config = AuditConfig(
            org=org,
            token="test-token",
            repo_specs=[
                RepoSpec(owner=org, repo="svc-.*", is_regex=True),
                RepoSpec(owner=org, repo="infra"),
            ],
        )
        report = run_audit(config)

        scanned_repos = {r["repo"] for r in report["repos"]}
        assert f"{org}/svc-auth" in scanned_repos
        assert f"{org}/svc-billing" in scanned_repos
        assert f"{org}/infra" in scanned_repos


class TestBranchProtectionAudit:
    """Tests for branch protection rule checks (BPR001, BPR002)."""

    @responses.activate
    def test_no_protection_reports_both_findings(self):
        """No branch protection at all should report BPR001."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            status=404,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        rule_ids = [f["rule_id"] for f in repo_report["findings"]]
        assert "BPR001" in rule_ids
        # The single finding covers both missing reviews and missing push restrictions
        assert any("No branch protection" in f["title"] for f in repo_report["findings"])

    @responses.activate
    def test_protection_without_required_reviews(self):
        """Branch protection exists but no required PR reviews."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        rule_ids = [f["rule_id"] for f in repo_report["findings"]]
        assert "BPR001" in rule_ids
        assert "BPR002" not in rule_ids

    @responses.activate
    def test_protection_with_zero_required_approvals(self):
        """Required reviews enabled but count is 0."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 0,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr001 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR001"]
        assert len(bpr001) == 1
        assert "0" in bpr001[0]["title"]

    @responses.activate
    def test_protection_with_sufficient_approvals_no_finding(self):
        """At least 1 required approval should produce no BPR001 finding."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 2,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        rule_ids = [f["rule_id"] for f in repo_report["findings"]]
        assert "BPR001" not in rule_ids
        assert "BPR002" not in rule_ids

    @responses.activate
    def test_no_enforce_admins_and_no_restrictions(self):
        """No push restrictions and enforce_admins disabled => BPR002 high."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
                "enforce_admins": {"enabled": False},
                "allow_force_pushes": {"enabled": False},
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr002 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR002"]
        assert len(bpr002) == 1
        assert bpr002[0]["severity"] == "high"

    @responses.activate
    def test_enforce_admins_disabled_with_restrictions(self):
        """Push restrictions exist but enforce_admins off => BPR002 medium."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
                "enforce_admins": {"enabled": False},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr002 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR002"]
        assert len(bpr002) == 1
        assert bpr002[0]["severity"] == "medium"
        assert "Admins can bypass" in bpr002[0]["title"]

    @responses.activate
    def test_force_pushes_allowed(self):
        """Force pushes enabled => BPR002 critical."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": True},
                "restrictions": {"users": [], "teams": []},
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr002 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR002"]
        assert len(bpr002) == 1
        assert bpr002[0]["severity"] == "critical"
        assert "Force pushes" in bpr002[0]["title"]

    @responses.activate
    def test_fully_protected_branch_no_findings(self):
        """Fully protected branch should produce no BPR findings."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True,
                    "dismissal_restrictions": {"users": [], "teams": []},
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["ci/build"],
                },
                "required_signatures": {"enabled": True},
                "required_linear_history": {"enabled": True},
                "required_conversation_resolution": {"enabled": True},
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr_findings = [f for f in repo_report["findings"] if f["rule_id"].startswith("BPR")]
        assert len(bpr_findings) == 0

    @responses.activate
    def test_no_required_status_checks(self):
        """Protection exists but no required_status_checks => BPR003."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr003 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR003"]
        assert len(bpr003) == 1
        assert bpr003[0]["severity"] == "high"

    @responses.activate
    def test_empty_status_checks_contexts(self):
        """required_status_checks with empty contexts and checks => BPR003."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
                "required_status_checks": {
                    "strict": True,
                    "contexts": [],
                    "checks": [],
                },
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr003 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR003"]
        assert len(bpr003) == 1

    @responses.activate
    def test_required_status_checks_configured(self):
        """Proper status checks configured => no BPR003."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["ci/build"],
                },
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr003 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR003"]
        assert len(bpr003) == 0

    @responses.activate
    def test_stale_reviews_not_dismissed(self):
        """dismiss_stale_reviews is false => BPR004."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": False,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["ci/build"],
                },
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr004 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR004"]
        assert len(bpr004) == 1
        assert bpr004[0]["severity"] == "medium"

    @responses.activate
    def test_stale_reviews_dismissed(self):
        """dismiss_stale_reviews is true => no BPR004."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["ci/build"],
                },
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr004 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR004"]
        assert len(bpr004) == 0

    @responses.activate
    def test_branch_deletion_allowed(self):
        """allow_deletions enabled => BPR005 critical."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": True},
                "restrictions": {"users": [], "teams": []},
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["ci/build"],
                },
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr005 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR005"]
        assert len(bpr005) == 1
        assert bpr005[0]["severity"] == "critical"

    @responses.activate
    def test_branch_deletion_not_allowed(self):
        """allow_deletions disabled => no BPR005."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json={
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                },
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["ci/build"],
                },
            },
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr005 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR005"]
        assert len(bpr005) == 0

    def _make_protection(self, **overrides):
        """Build a fully-protected branch protection dict, with overrides."""
        base = {
            "required_pull_request_reviews": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews": True,
                "require_code_owner_reviews": True,
                "dismissal_restrictions": {"users": [], "teams": []},
            },
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "restrictions": {"users": [], "teams": []},
            "required_status_checks": {
                "strict": True,
                "contexts": ["ci/build"],
            },
            "required_signatures": {"enabled": True},
            "required_linear_history": {"enabled": True},
            "required_conversation_resolution": {"enabled": True},
        }
        base.update(overrides)
        return base

    @responses.activate
    def test_signed_commits_not_required(self):
        """Missing required_signatures => BPR006."""
        prot = self._make_protection(required_signatures={"enabled": False})
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr006 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR006"]
        assert len(bpr006) == 1
        assert bpr006[0]["severity"] == "medium"

    @responses.activate
    def test_signed_commits_required(self):
        """required_signatures enabled => no BPR006."""
        prot = self._make_protection()
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr006 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR006"]
        assert len(bpr006) == 0

    @responses.activate
    def test_code_owner_reviews_not_required(self):
        """require_code_owner_reviews false => BPR007."""
        prot = self._make_protection()
        prot["required_pull_request_reviews"]["require_code_owner_reviews"] = False
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr007 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR007"]
        assert len(bpr007) == 1
        assert bpr007[0]["severity"] == "medium"

    @responses.activate
    def test_code_owner_reviews_required(self):
        """require_code_owner_reviews true => no BPR007."""
        prot = self._make_protection()
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr007 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR007"]
        assert len(bpr007) == 0

    @responses.activate
    def test_dismissal_restrictions_missing(self):
        """No dismissal_restrictions => BPR008."""
        prot = self._make_protection()
        del prot["required_pull_request_reviews"]["dismissal_restrictions"]
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr008 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR008"]
        assert len(bpr008) == 1
        assert bpr008[0]["severity"] == "low"

    @responses.activate
    def test_dismissal_restrictions_present(self):
        """dismissal_restrictions set => no BPR008."""
        prot = self._make_protection()
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr008 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR008"]
        assert len(bpr008) == 0

    @responses.activate
    def test_linear_history_not_required(self):
        """required_linear_history disabled => BPR009."""
        prot = self._make_protection(required_linear_history={"enabled": False})
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr009 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR009"]
        assert len(bpr009) == 1
        assert bpr009[0]["severity"] == "low"

    @responses.activate
    def test_linear_history_required(self):
        """required_linear_history enabled => no BPR009."""
        prot = self._make_protection()
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr009 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR009"]
        assert len(bpr009) == 0

    @responses.activate
    def test_conversation_resolution_not_required(self):
        """required_conversation_resolution disabled => BPR010."""
        prot = self._make_protection(required_conversation_resolution={"enabled": False})
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr010 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR010"]
        assert len(bpr010) == 1
        assert bpr010[0]["severity"] == "low"

    @responses.activate
    def test_conversation_resolution_required(self):
        """required_conversation_resolution enabled => no BPR010."""
        prot = self._make_protection()
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/branches/main/protection",
            json=prot,
        )
        client = GitHubClient("test-token")
        repo_report = {"findings": []}
        _audit_branch_protection(client, "org", "repo", "main", repo_report)

        bpr010 = [f for f in repo_report["findings"] if f["rule_id"] == "BPR010"]
        assert len(bpr010) == 0


class TestRepoSecurity:
    """Tests for repository security feature checks (SEC001-SEC005)."""

    @responses.activate
    def test_secret_scanning_disabled(self):
        """Secret scanning not enabled => SEC001."""
        client = GitHubClient("test-token")
        repo_meta = {
            "security_and_analysis": {
                "secret_scanning": {"status": "disabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
                "dependabot_security_updates": {"status": "enabled"},
            }
        }
        repo_report = {"findings": []}
        _audit_repo_security(client, "org", "repo", "main", repo_meta, repo_report)

        sec001 = [f for f in repo_report["findings"] if f["rule_id"] == "SEC001"]
        assert len(sec001) == 1
        assert sec001[0]["severity"] == "high"

    @responses.activate
    def test_secret_scanning_enabled(self):
        """Secret scanning enabled => no SEC001."""
        client = GitHubClient("test-token")
        repo_meta = {
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
                "dependabot_security_updates": {"status": "enabled"},
            }
        }
        repo_report = {"findings": []}
        _audit_repo_security(client, "org", "repo", "main", repo_meta, repo_report)

        sec001 = [f for f in repo_report["findings"] if f["rule_id"] == "SEC001"]
        assert len(sec001) == 0

    @responses.activate
    def test_push_protection_disabled(self):
        """Push protection not enabled => SEC002."""
        client = GitHubClient("test-token")
        repo_meta = {
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "disabled"},
                "dependabot_security_updates": {"status": "enabled"},
            }
        }
        repo_report = {"findings": []}
        _audit_repo_security(client, "org", "repo", "main", repo_meta, repo_report)

        sec002 = [f for f in repo_report["findings"] if f["rule_id"] == "SEC002"]
        assert len(sec002) == 1
        assert sec002[0]["severity"] == "high"

    @responses.activate
    def test_dependabot_disabled(self):
        """Dependabot security updates disabled => SEC003."""
        client = GitHubClient("test-token")
        repo_meta = {
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
                "dependabot_security_updates": {"status": "disabled"},
            }
        }
        repo_report = {"findings": []}
        _audit_repo_security(client, "org", "repo", "main", repo_meta, repo_report)

        sec003 = [f for f in repo_report["findings"] if f["rule_id"] == "SEC003"]
        assert len(sec003) == 1
        assert sec003[0]["severity"] == "medium"

    @responses.activate
    def test_no_codeowners(self):
        """No CODEOWNERS file found => SEC004."""
        for path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]:
            responses.add(
                responses.GET,
                f"{GITHUB_API}/repos/org/repo/contents/{path}",
                status=404,
            )

        client = GitHubClient("test-token")
        repo_meta = {}
        repo_report = {"findings": []}
        _audit_repo_security(client, "org", "repo", "main", repo_meta, repo_report)

        sec004 = [f for f in repo_report["findings"] if f["rule_id"] == "SEC004"]
        assert len(sec004) == 1
        assert sec004[0]["severity"] == "medium"

    @responses.activate
    def test_codeowners_present(self):
        """CODEOWNERS file exists => no SEC004."""
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/contents/CODEOWNERS",
            json={"content": _b64("* @org/team"), "encoding": "base64"},
        )

        # Also mock SECURITY.md paths to avoid SEC005
        for path in ["SECURITY.md", ".github/SECURITY.md"]:
            responses.add(
                responses.GET,
                f"{GITHUB_API}/repos/org/repo/contents/{path}",
                status=404,
            )

        client = GitHubClient("test-token")
        repo_meta = {}
        repo_report = {"findings": []}
        _audit_repo_security(client, "org", "repo", "main", repo_meta, repo_report)

        sec004 = [f for f in repo_report["findings"] if f["rule_id"] == "SEC004"]
        assert len(sec004) == 0

    @responses.activate
    def test_no_security_md(self):
        """No SECURITY.md file found => SEC005."""
        # Mock CODEOWNERS as found so we only test SEC005
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/contents/CODEOWNERS",
            json={"content": _b64("* @org/team"), "encoding": "base64"},
        )
        for path in ["SECURITY.md", ".github/SECURITY.md"]:
            responses.add(
                responses.GET,
                f"{GITHUB_API}/repos/org/repo/contents/{path}",
                status=404,
            )

        client = GitHubClient("test-token")
        repo_meta = {}
        repo_report = {"findings": []}
        _audit_repo_security(client, "org", "repo", "main", repo_meta, repo_report)

        sec005 = [f for f in repo_report["findings"] if f["rule_id"] == "SEC005"]
        assert len(sec005) == 1
        assert sec005[0]["severity"] == "low"

    @responses.activate
    def test_security_md_present(self):
        """SECURITY.md exists => no SEC005."""
        # Mock CODEOWNERS as found
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/contents/CODEOWNERS",
            json={"content": _b64("* @org/team"), "encoding": "base64"},
        )
        responses.add(
            responses.GET,
            f"{GITHUB_API}/repos/org/repo/contents/SECURITY.md",
            json={"content": _b64("# Security Policy"), "encoding": "base64"},
        )

        client = GitHubClient("test-token")
        repo_meta = {}
        repo_report = {"findings": []}
        _audit_repo_security(client, "org", "repo", "main", repo_meta, repo_report)

        sec005 = [f for f in repo_report["findings"] if f["rule_id"] == "SEC005"]
        assert len(sec005) == 0
