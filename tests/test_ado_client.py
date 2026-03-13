"""Tests for the Azure DevOps REST client."""

import responses

from pipeaudit.azure.ado_client import AzureDevOpsClient


@responses.activate
def test_list_projects():
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/_apis/projects",
        json={"value": [{"name": "ProjectA", "id": "p1"}], "count": 1},
        status=200,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    projects = client.list_projects()
    assert len(projects) == 1
    assert projects[0]["name"] == "ProjectA"


@responses.activate
def test_list_repositories():
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/ProjectA/_apis/git/repositories",
        json={"value": [{"name": "repo1", "id": "r1", "defaultBranch": "refs/heads/main"}]},
        status=200,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    repos = client.list_repositories("ProjectA")
    assert len(repos) == 1
    assert repos[0]["name"] == "repo1"


@responses.activate
def test_get_file_content():
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/ProjectA/_apis/git/repositories/r1/items",
        body="trigger: none\nsteps:\n  - script: echo hello",
        status=200,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    content = client.get_file_content("ProjectA", "r1", "azure-pipelines.yml", "main")
    assert content is not None
    assert "trigger" in content


@responses.activate
def test_get_file_content_404():
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/ProjectA/_apis/git/repositories/r1/items",
        json={"message": "not found"},
        status=404,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    content = client.get_file_content("ProjectA", "r1", "missing.yml", "main")
    assert content is None


@responses.activate
def test_pagination_with_continuation_token():
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/_apis/projects",
        json={"value": [{"name": "P1"}], "continuationToken": "abc123"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/_apis/projects",
        json={"value": [{"name": "P2"}]},
        status=200,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    projects = client.list_projects()
    assert len(projects) == 2
    assert projects[0]["name"] == "P1"
    assert projects[1]["name"] == "P2"


@responses.activate
def test_list_policy_configurations():
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/ProjectA/_apis/policy/configurations",
        json={"value": [{"id": 1, "type": {"id": "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"}}]},
        status=200,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    policies = client.list_policy_configurations("ProjectA")
    assert len(policies) == 1


@responses.activate
def test_list_users_graph_api():
    responses.add(
        responses.GET,
        "https://vssps.dev.azure.com/test-org/_apis/graph/users",
        json={"value": [{"displayName": "Alice"}]},
        status=200,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    users = client.list_users()
    assert len(users) == 1
    assert users[0]["displayName"] == "Alice"


@responses.activate
def test_list_environments():
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/ProjectA/_apis/pipelines/environments",
        json={"value": [{"id": 1, "name": "production"}]},
        status=200,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    envs = client.list_environments("ProjectA")
    assert len(envs) == 1
    assert envs[0]["name"] == "production"


@responses.activate
def test_list_service_connections():
    responses.add(
        responses.GET,
        "https://dev.azure.com/test-org/ProjectA/_apis/serviceendpoint/endpoints",
        json={"value": [{"name": "azure-sub", "type": "azurerm"}]},
        status=200,
    )
    client = AzureDevOpsClient("test-org", "fake-pat")
    conns = client.list_service_connections("ProjectA")
    assert len(conns) == 1
    assert conns[0]["name"] == "azure-sub"
