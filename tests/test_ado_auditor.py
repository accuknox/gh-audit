"""Integration tests for the Azure DevOps auditor orchestrator."""

from unittest.mock import MagicMock, patch

from gh_auditor.azure.ado_auditor import AdoAuditConfig, run_ado_audit


def _mock_client():
    """Create a mock AzureDevOpsClient with all necessary methods."""
    client = MagicMock()
    client.list_projects.return_value = [
        {"name": "TestProject", "id": "p1", "visibility": "private"},
    ]
    client.list_repositories.return_value = [
        {
            "name": "repo1",
            "id": "r1",
            "defaultBranch": "refs/heads/main",
            "isDisabled": False,
            "advancedSecurity": {},
            "isForkingAllowed": False,
            "project": {"visibility": "private"},
        },
    ]
    client.list_policy_configurations.return_value = []
    client.list_environments.return_value = []
    client.list_variable_groups.return_value = []
    client.list_build_definitions.return_value = []
    client.get_file_content.return_value = None
    client.list_users.return_value = []
    client.list_groups.return_value = []
    client.list_service_connections.return_value = []
    client.get_project_properties.return_value = []
    client.list_project_teams.return_value = []
    return client


@patch("gh_auditor.azure.ado_auditor.AzureDevOpsClient")
def test_full_audit_produces_report(mock_client_class):
    mock_client_class.return_value = _mock_client()

    config = AdoAuditConfig(
        org="test-org",
        token="fake-pat",
    )
    report = run_ado_audit(config)

    assert "audit_metadata" in report
    assert report["audit_metadata"]["platform"] == "azure"
    assert report["audit_metadata"]["organization"] == "test-org"
    assert report["audit_metadata"]["total_repos_scanned"] == 1
    assert "repos" in report
    assert len(report["repos"]) == 1
    assert report["repos"][0]["repo"] == "TestProject/repo1"


@patch("gh_auditor.azure.ado_auditor.AzureDevOpsClient")
def test_audit_with_project_filter(mock_client_class):
    client = _mock_client()
    client.get_project.return_value = {
        "name": "SpecificProject", "id": "p2", "visibility": "private",
    }
    client.list_repositories.return_value = []
    mock_client_class.return_value = client

    config = AdoAuditConfig(
        org="test-org",
        token="fake-pat",
        projects=["SpecificProject"],
    )
    report = run_ado_audit(config)
    assert report["audit_metadata"]["total_repos_scanned"] == 0


@patch("gh_auditor.azure.ado_auditor.AzureDevOpsClient")
def test_audit_findings_tallied(mock_client_class):
    client = _mock_client()
    # Return a pipeline YAML with a known issue
    def _get_file(project, repo_id, path, branch):
        if path == "azure-pipelines.yml":
            return """
steps:
  - checkout: self
    persistCredentials: true
"""
        return None

    client.get_file_content.side_effect = _get_file
    mock_client_class.return_value = client

    config = AdoAuditConfig(org="test-org", token="fake-pat")
    report = run_ado_audit(config)

    assert report["audit_metadata"]["total_findings"] > 0
    # Should have at least AZP001 + branch policy findings + repo security findings
    rule_ids = {f["rule_id"] for repo in report["repos"] for f in repo["findings"]}
    assert "AZP001" in rule_ids


@patch("gh_auditor.azure.ado_auditor.AzureDevOpsClient")
def test_audit_skip_identity(mock_client_class):
    mock_client_class.return_value = _mock_client()

    config = AdoAuditConfig(
        org="test-org",
        token="fake-pat",
        skip_identity=True,
    )
    report = run_ado_audit(config)
    assert "identity" not in report


@patch("gh_auditor.azure.ado_auditor.AzureDevOpsClient")
def test_audit_skip_project_settings(mock_client_class):
    mock_client_class.return_value = _mock_client()

    config = AdoAuditConfig(
        org="test-org",
        token="fake-pat",
        skip_project_settings=True,
    )
    report = run_ado_audit(config)
    assert "org_settings" not in report


@patch("gh_auditor.azure.ado_auditor.AzureDevOpsClient")
def test_scoring_applied(mock_client_class):
    mock_client_class.return_value = _mock_client()

    config = AdoAuditConfig(org="test-org", token="fake-pat")
    report = run_ado_audit(config)

    # enrich_report should have been called
    assert "org_score" in report["audit_metadata"]
    assert "score" in report["audit_metadata"]["org_score"]
    assert "grade" in report["audit_metadata"]["org_score"]

    # Each repo should have a score
    for repo in report["repos"]:
        assert "score" in repo
