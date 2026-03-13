"""REST client for Azure DevOps APIs."""

from __future__ import annotations

import base64
import logging

import requests

logger = logging.getLogger(__name__)

ADO_BASE = "https://dev.azure.com"
VSSPS_BASE = "https://vssps.dev.azure.com"
API_VERSION = "7.1"


class AzureDevOpsClient:
    """HTTP client for Azure DevOps REST APIs using PAT authentication."""

    def __init__(self, org: str, token: str):
        self._org = org
        self._session = requests.Session()
        b64 = base64.b64encode(f":{token}".encode()).decode()
        self._session.headers.update({
            "Authorization": f"Basic {b64}",
            "Content-Type": "application/json",
        })
        self._base = f"{ADO_BASE}/{org}"
        self._vssps = f"{VSSPS_BASE}/{org}"

    # -----------------------------------------------------------------
    # Projects
    # -----------------------------------------------------------------

    def list_projects(self) -> list[dict]:
        """List all projects in the organization."""
        return self._paginate(f"{self._base}/_apis/projects")

    def get_project(self, project: str) -> dict:
        """Get a single project by name or ID."""
        resp = self._get(f"{self._base}/_apis/projects/{project}")
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------
    # Repositories
    # -----------------------------------------------------------------

    def list_repositories(self, project: str) -> list[dict]:
        """List all Git repositories in a project."""
        resp = self._get(
            f"{self._base}/{project}/_apis/git/repositories"
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    def get_repository(self, project: str, repo_id: str) -> dict:
        """Get a single repository by ID."""
        resp = self._get(
            f"{self._base}/{project}/_apis/git/repositories/{repo_id}"
        )
        resp.raise_for_status()
        return resp.json()

    def list_refs(self, project: str, repo_id: str) -> list[dict]:
        """List refs (branches/tags) in a repository."""
        return self._paginate(
            f"{self._base}/{project}/_apis/git/repositories/{repo_id}/refs"
        )

    def get_file_content(
        self, project: str, repo_id: str, path: str, branch: str | None = None
    ) -> str | None:
        """Fetch file content from a repository."""
        params: dict = {"path": path}
        if branch:
            params["versionDescriptor.version"] = branch
            params["versionDescriptor.versionType"] = "branch"
        resp = self._get(
            f"{self._base}/{project}/_apis/git/repositories/{repo_id}/items",
            extra_params=params,
        )
        if resp.status_code == 404:
            return None
        if resp.status_code in (403,):
            logger.debug("No access to %s in %s/%s", path, project, repo_id)
            return None
        resp.raise_for_status()
        return resp.text

    # -----------------------------------------------------------------
    # Pipelines / Build definitions
    # -----------------------------------------------------------------

    def list_build_definitions(self, project: str) -> list[dict]:
        """List all build/pipeline definitions in a project."""
        return self._paginate(
            f"{self._base}/{project}/_apis/build/definitions"
        )

    def get_build_definition(self, project: str, definition_id: int) -> dict:
        """Get a single build definition with full YAML process details."""
        resp = self._get(
            f"{self._base}/{project}/_apis/build/definitions/{definition_id}"
        )
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------
    # Variable Groups
    # -----------------------------------------------------------------

    def list_variable_groups(self, project: str) -> list[dict]:
        """List variable groups in a project."""
        resp = self._get(
            f"{self._base}/{project}/_apis/distributedtask/variablegroups"
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    # -----------------------------------------------------------------
    # Environments
    # -----------------------------------------------------------------

    def list_environments(self, project: str) -> list[dict]:
        """List environments in a project."""
        resp = self._get(
            f"{self._base}/{project}/_apis/pipelines/environments"
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    def get_environment_checks(self, project: str, env_id: int) -> list[dict]:
        """Get approval/check configurations for an environment."""
        resp = self._get(
            f"{self._base}/{project}/_apis/pipelines/checks/configurations",
            extra_params={"resourceType": "environment", "resourceId": str(env_id)},
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    # -----------------------------------------------------------------
    # Service Connections
    # -----------------------------------------------------------------

    def list_service_connections(self, project: str) -> list[dict]:
        """List service connections (endpoints) in a project."""
        resp = self._get(
            f"{self._base}/{project}/_apis/serviceendpoint/endpoints"
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    # -----------------------------------------------------------------
    # Branch Policies
    # -----------------------------------------------------------------

    def list_policy_configurations(self, project: str) -> list[dict]:
        """List all policy configurations in a project."""
        return self._paginate(
            f"{self._base}/{project}/_apis/policy/configurations"
        )

    # -----------------------------------------------------------------
    # Identity & Graph (vssps)
    # -----------------------------------------------------------------

    def list_users(self) -> list[dict]:
        """List all users in the organization via Graph API."""
        return self._paginate_graph(
            f"{self._vssps}/_apis/graph/users"
        )

    def list_groups(self) -> list[dict]:
        """List all groups in the organization via Graph API."""
        return self._paginate_graph(
            f"{self._vssps}/_apis/graph/groups"
        )

    def list_group_members(self, descriptor: str) -> list[dict]:
        """List members of a group by its descriptor."""
        resp = self._get(
            f"{self._vssps}/_apis/graph/memberships/{descriptor}",
            extra_params={"direction": "down"},
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    def list_project_teams(self, project: str) -> list[dict]:
        """List teams in a project."""
        resp = self._get(
            f"{self._base}/_apis/projects/{project}/teams"
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    # -----------------------------------------------------------------
    # Organization Settings
    # -----------------------------------------------------------------

    def get_project_properties(self, project_id: str) -> list[dict]:
        """Get project properties (e.g., visibility settings)."""
        resp = self._get(
            f"{self._base}/_apis/projects/{project_id}/properties"
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json().get("value", [])

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _get(self, url: str, extra_params: dict | None = None) -> requests.Response:
        """GET with api-version parameter."""
        params = {"api-version": API_VERSION}
        if extra_params:
            params.update(extra_params)
        return self._session.get(url, params=params, timeout=30)

    def _paginate(self, url: str, extra_params: dict | None = None) -> list[dict]:
        """Paginate using continuationToken."""
        items: list[dict] = []
        params = {"api-version": API_VERSION, "$top": "200"}
        if extra_params:
            params.update(extra_params)

        while True:
            resp = self._session.get(url, params=params, timeout=30)
            if resp.status_code in (403, 404):
                break
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("value", []))
            token = data.get("continuationToken") or resp.headers.get("x-ms-continuationtoken")
            if not token:
                break
            params["continuationToken"] = token

        return items

    def _paginate_graph(self, url: str) -> list[dict]:
        """Paginate Graph API responses using continuationToken in body."""
        items: list[dict] = []
        params = {"api-version": f"{API_VERSION}-preview.1"}

        while True:
            resp = self._session.get(url, params=params, timeout=30)
            if resp.status_code in (403, 404):
                break
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("value", []))
            token = data.get("continuationToken")
            if not token:
                break
            params["continuationToken"] = token

        return items
