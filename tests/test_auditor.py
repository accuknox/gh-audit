"""Tests for the auditor orchestration."""

import base64
import json

import pytest
import responses
import yaml

from gh_auditor.auditor import AuditConfig, RepoSpec, run_audit
from gh_auditor.token_validator import GITHUB_API


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


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

        config = AuditConfig(org=org, token="test-token")
        report = run_audit(config)
        assert report["repos"][0]["workflows_scanned"] == 0
        assert report["repos"][0]["findings"] == []

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
