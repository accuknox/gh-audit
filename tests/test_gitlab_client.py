"""Tests for the GitLab REST client."""

import base64

import responses

from pipeaudit.gitlab.gitlab_client import GitLabClient


@responses.activate
def test_get_group():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/groups/my-group",
        json={"full_path": "my-group", "name": "My Group", "visibility": "private"},
        status=200,
    )
    client = GitLabClient("my-group", "fake-token")
    group = client.get_group()
    assert group["full_path"] == "my-group"
    assert group["name"] == "My Group"


@responses.activate
def test_list_projects():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/groups/my-group/projects",
        json=[
            {"id": 1, "name": "project-a", "path_with_namespace": "my-group/project-a"},
            {"id": 2, "name": "project-b", "path_with_namespace": "my-group/project-b"},
        ],
        status=200,
    )
    client = GitLabClient("my-group", "fake-token")
    projects = client.list_projects()
    assert len(projects) == 2
    assert projects[0]["name"] == "project-a"


@responses.activate
def test_list_projects_pagination():
    # Page 1 with Link header
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/groups/my-group/projects",
        json=[{"id": 1, "name": "project-a"}],
        status=200,
        headers={"Link": '<https://gitlab.com/api/v4/groups/my-group/projects?page=2>; rel="next"'},
    )
    # Page 2 with no Link header
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/groups/my-group/projects?page=2",
        json=[{"id": 2, "name": "project-b"}],
        status=200,
    )
    client = GitLabClient("my-group", "fake-token")
    projects = client.list_projects()
    assert len(projects) == 2


@responses.activate
def test_get_file_content_base64():
    content = "stages:\n  - test\n"
    b64 = base64.b64encode(content.encode()).decode()
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/1/repository/files/.gitlab-ci.yml",
        json={"content": b64, "encoding": "base64"},
        status=200,
    )
    client = GitLabClient("my-group", "fake-token")
    result = client.get_file_content(1, ".gitlab-ci.yml", "main")
    assert result == content


@responses.activate
def test_get_file_content_404():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/1/repository/files/missing.yml",
        json={"message": "404 File Not Found"},
        status=404,
    )
    client = GitLabClient("my-group", "fake-token")
    result = client.get_file_content(1, "missing.yml", "main")
    assert result is None


@responses.activate
def test_get_file_content_403():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/1/repository/files/secret.yml",
        json={"message": "403 Forbidden"},
        status=403,
    )
    client = GitLabClient("my-group", "fake-token")
    result = client.get_file_content(1, "secret.yml", "main")
    assert result is None


@responses.activate
def test_list_protected_branches():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/1/protected_branches",
        json=[{"name": "main", "allow_force_push": False}],
        status=200,
    )
    client = GitLabClient("my-group", "fake-token")
    branches = client.list_protected_branches(1)
    assert len(branches) == 1
    assert branches[0]["name"] == "main"


@responses.activate
def test_list_group_members():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/groups/my-group/members/all",
        json=[
            {"username": "user1", "access_level": 50},
            {"username": "user2", "access_level": 30},
        ],
        status=200,
    )
    client = GitLabClient("my-group", "fake-token")
    members = client.list_group_members()
    assert len(members) == 2


@responses.activate
def test_url_encoding_group_path():
    """Groups with slashes in path should be URL-encoded."""
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/groups/my-org%2Fsub-group",
        json={"full_path": "my-org/sub-group", "name": "sub-group"},
        status=200,
    )
    client = GitLabClient("my-org/sub-group", "fake-token")
    group = client.get_group()
    assert group["full_path"] == "my-org/sub-group"


@responses.activate
def test_list_project_variables():
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/1/variables",
        json=[
            {"key": "DB_PASSWORD", "protected": False, "masked": False},
        ],
        status=200,
    )
    client = GitLabClient("my-group", "fake-token")
    variables = client.list_project_variables(1)
    assert len(variables) == 1
    assert variables[0]["key"] == "DB_PASSWORD"


@responses.activate
def test_list_approval_rules_403():
    """Premium API returns 403 on free tier — should return empty list."""
    responses.add(
        responses.GET,
        "https://gitlab.com/api/v4/projects/1/approval_rules",
        json={"message": "403 Forbidden"},
        status=403,
    )
    client = GitLabClient("my-group", "fake-token")
    rules = client.list_approval_rules(1)
    assert rules == []
