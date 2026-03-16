"""Integration tests for the GitLab auditor orchestrator."""

from unittest.mock import MagicMock, patch

from pipeaudit.gitlab.gitlab_auditor import GitLabAuditConfig, run_gitlab_audit


def _mock_client():
    """Create a mock GitLabClient with all necessary methods."""
    client = MagicMock()
    client.list_projects.return_value = [
        {
            "id": 1,
            "name": "project-a",
            "path_with_namespace": "my-group/project-a",
            "default_branch": "main",
            "visibility": "private",
            "archived": False,
        },
    ]
    client.get_group.return_value = {
        "full_path": "my-group",
        "name": "My Group",
        "visibility": "private",
        "require_two_factor_authentication": True,
        "project_creation_level": "maintainer",
        "prevent_forking_outside_group": True,
        "shared_runners_setting": "disabled_and_unoverridable",
    }
    client.list_protected_branches.return_value = [
        {"name": "main", "allow_force_push": False, "code_owner_approval_required": True},
    ]
    client.get_project_approval_config.return_value = {
        "approvals_before_merge": 1,
        "merge_requests_author_approval": False,
        "merge_requests_disable_committers_approval": True,
    }
    client.list_approval_rules.return_value = []
    client.get_file_content.return_value = None
    client.list_project_variables.return_value = []
    client.list_project_runners.return_value = []
    client.list_group_members.return_value = []
    client.list_group_access_requests.return_value = []
    client.get_push_rules.return_value = None
    return client


@patch("pipeaudit.gitlab.gitlab_auditor.GitLabClient")
def test_full_audit_produces_report(mock_client_class):
    mock_client_class.return_value = _mock_client()

    config = GitLabAuditConfig(
        org="my-group",
        token="fake-token",
    )
    report = run_gitlab_audit(config)

    assert "audit_metadata" in report
    assert report["audit_metadata"]["platform"] == "gitlab"
    assert report["audit_metadata"]["organization"] == "my-group"
    assert report["audit_metadata"]["total_repos_scanned"] == 1
    assert "repos" in report
    assert len(report["repos"]) == 1
    assert report["repos"][0]["repo"] == "my-group/project-a"


@patch("pipeaudit.gitlab.gitlab_auditor.GitLabClient")
def test_audit_excludes_archived(mock_client_class):
    client = _mock_client()
    client.list_projects.return_value = [
        {
            "id": 1,
            "name": "archived-proj",
            "path_with_namespace": "my-group/archived-proj",
            "default_branch": "main",
            "visibility": "private",
            "archived": True,
        },
    ]
    mock_client_class.return_value = client

    config = GitLabAuditConfig(
        org="my-group",
        token="fake-token",
        include_archived=False,
    )
    report = run_gitlab_audit(config)
    assert report["audit_metadata"]["total_repos_scanned"] == 0


@patch("pipeaudit.gitlab.gitlab_auditor.GitLabClient")
def test_audit_repo_filter(mock_client_class):
    client = _mock_client()
    client.list_projects.return_value = [
        {
            "id": 1,
            "name": "project-a",
            "path_with_namespace": "my-group/project-a",
            "default_branch": "main",
            "visibility": "private",
            "archived": False,
        },
        {
            "id": 2,
            "name": "project-b",
            "path_with_namespace": "my-group/project-b",
            "default_branch": "main",
            "visibility": "private",
            "archived": False,
        },
    ]
    mock_client_class.return_value = client

    config = GitLabAuditConfig(
        org="my-group",
        token="fake-token",
        repos=["project-a"],
    )
    report = run_gitlab_audit(config)
    assert report["audit_metadata"]["total_repos_scanned"] == 1
    assert report["repos"][0]["repo"] == "my-group/project-a"


@patch("pipeaudit.gitlab.gitlab_auditor.GitLabClient")
def test_audit_findings_tallied(mock_client_class):
    client = _mock_client()
    # No .gitlab-ci.yml → will get GLS001, GLS002, GLS003 findings
    mock_client_class.return_value = client

    config = GitLabAuditConfig(
        org="my-group",
        token="fake-token",
    )
    report = run_gitlab_audit(config)
    assert report["audit_metadata"]["total_findings"] > 0
    # Verify severity counts add up
    total = sum(report["audit_metadata"]["findings_by_severity"].values())
    assert total == report["audit_metadata"]["total_findings"]


@patch("pipeaudit.gitlab.gitlab_auditor.GitLabClient")
def test_audit_has_org_settings(mock_client_class):
    mock_client_class.return_value = _mock_client()

    config = GitLabAuditConfig(
        org="my-group",
        token="fake-token",
    )
    report = run_gitlab_audit(config)
    assert "org_settings" in report
    assert "findings" in report["org_settings"]


@patch("pipeaudit.gitlab.gitlab_auditor.GitLabClient")
def test_audit_has_identity(mock_client_class):
    mock_client_class.return_value = _mock_client()

    config = GitLabAuditConfig(
        org="my-group",
        token="fake-token",
    )
    report = run_gitlab_audit(config)
    assert "identity" in report
    assert "findings" in report["identity"]
