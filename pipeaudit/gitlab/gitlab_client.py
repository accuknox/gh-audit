"""REST client for GitLab API v4."""

from __future__ import annotations

import base64
import logging
import urllib.parse

import requests

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://gitlab.com/api/v4"


class GitLabClient:
    """HTTP client for GitLab REST API v4 using Private-Token authentication."""

    def __init__(self, group: str, token: str, base_url: str = DEFAULT_BASE_URL):
        self._group = group
        self._base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({
            "PRIVATE-TOKEN": token,
        })

    # -----------------------------------------------------------------
    # Groups
    # -----------------------------------------------------------------

    def get_group(self) -> dict:
        """Get group details by path."""
        encoded = urllib.parse.quote(self._group, safe="")
        resp = self._get(f"{self._base_url}/groups/{encoded}")
        resp.raise_for_status()
        return resp.json()

    def list_group_members(self, include_inherited: bool = True) -> list[dict]:
        """List all members of the group.

        Tries /members/all first (requires Maintainer+), falls back to
        /members (direct members only) on 403.
        """
        encoded = urllib.parse.quote(self._group, safe="")
        if include_inherited:
            url = f"{self._base_url}/groups/{encoded}/members/all"
            # Probe with a single-item request to check permissions
            resp = self._get(url, extra_params={"per_page": "1"})
            if resp.status_code == 403:
                logger.info("members/all returned 403, falling back to /members")
            else:
                return self._paginate(url)
        return self._paginate(f"{self._base_url}/groups/{encoded}/members")

    def list_group_access_requests(self) -> list[dict]:
        """List pending access requests for the group."""
        encoded = urllib.parse.quote(self._group, safe="")
        resp = self._get(f"{self._base_url}/groups/{encoded}/access_requests")
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        return resp.json() if isinstance(resp.json(), list) else []

    # -----------------------------------------------------------------
    # Projects
    # -----------------------------------------------------------------

    def list_projects(self) -> list[dict]:
        """List all projects in the group (including subgroups)."""
        encoded = urllib.parse.quote(self._group, safe="")
        return self._paginate(
            f"{self._base_url}/groups/{encoded}/projects",
            extra_params={"include_subgroups": "true", "with_shared": "false"},
        )

    def get_project(self, project_id: int) -> dict:
        """Get a single project by ID."""
        resp = self._get(f"{self._base_url}/projects/{project_id}")
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------
    # Project members
    # -----------------------------------------------------------------

    def list_project_members(self, project_id: int) -> list[dict]:
        """List all members of a project (including inherited)."""
        return self._paginate(
            f"{self._base_url}/projects/{project_id}/members/all"
        )

    # -----------------------------------------------------------------
    # Repository files
    # -----------------------------------------------------------------

    def get_file_content(
        self, project_id: int, file_path: str, ref: str = "HEAD"
    ) -> str | None:
        """Fetch file content from a project repository.

        Returns decoded file content or None if not found.
        """
        encoded_path = urllib.parse.quote(file_path, safe="")
        resp = self._get(
            f"{self._base_url}/projects/{project_id}/repository/files/{encoded_path}",
            extra_params={"ref": ref},
        )
        if resp.status_code in (403, 404):
            return None
        if not resp.ok:
            return None
        data = resp.json()
        content_b64 = data.get("content", "")
        encoding = data.get("encoding", "base64")
        if encoding == "base64" and content_b64:
            try:
                return base64.b64decode(content_b64).decode("utf-8", errors="replace")
            except Exception:
                return None
        return content_b64

    # -----------------------------------------------------------------
    # Protected branches
    # -----------------------------------------------------------------

    def list_protected_branches(self, project_id: int) -> list[dict]:
        """List protected branches for a project."""
        return self._paginate(
            f"{self._base_url}/projects/{project_id}/protected_branches"
        )

    # -----------------------------------------------------------------
    # Merge request approval rules (Premium)
    # -----------------------------------------------------------------

    def list_approval_rules(self, project_id: int) -> list[dict]:
        """List project-level MR approval rules (Premium feature)."""
        resp = self._get(
            f"{self._base_url}/projects/{project_id}/approval_rules"
        )
        if resp.status_code in (403, 404):
            return []
        if not resp.ok:
            return []
        data = resp.json()
        return data if isinstance(data, list) else []

    def get_project_approval_config(self, project_id: int) -> dict | None:
        """Get project-level approval configuration."""
        resp = self._get(
            f"{self._base_url}/projects/{project_id}/approvals"
        )
        if resp.status_code in (403, 404):
            return None
        if not resp.ok:
            return None
        return resp.json()

    # -----------------------------------------------------------------
    # CI/CD variables
    # -----------------------------------------------------------------

    def list_project_variables(self, project_id: int) -> list[dict]:
        """List CI/CD variables for a project."""
        resp = self._get(
            f"{self._base_url}/projects/{project_id}/variables"
        )
        if resp.status_code in (403, 404):
            return []
        if not resp.ok:
            return []
        data = resp.json()
        return data if isinstance(data, list) else []

    # -----------------------------------------------------------------
    # Runners
    # -----------------------------------------------------------------

    def list_project_runners(self, project_id: int) -> list[dict]:
        """List runners available to a project."""
        return self._paginate(
            f"{self._base_url}/projects/{project_id}/runners"
        )

    # -----------------------------------------------------------------
    # Push rules (Premium)
    # -----------------------------------------------------------------

    def get_push_rules(self, project_id: int) -> dict | None:
        """Get push rules for a project (Premium feature)."""
        resp = self._get(
            f"{self._base_url}/projects/{project_id}/push_rule"
        )
        if resp.status_code in (403, 404):
            return None
        if not resp.ok:
            return None
        return resp.json()

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _get(self, url: str, extra_params: dict | None = None) -> requests.Response:
        """GET request with timeout."""
        params = {}
        if extra_params:
            params.update(extra_params)
        return self._session.get(url, params=params, timeout=30)

    def _paginate(self, url: str, extra_params: dict | None = None) -> list[dict]:
        """Paginate using Link header (rel="next")."""
        items: list[dict] = []
        params = {"per_page": "100"}
        if extra_params:
            params.update(extra_params)

        next_url: str | None = url
        next_params: dict | None = params

        while next_url:
            resp = self._session.get(next_url, params=next_params, timeout=30)
            if resp.status_code in (403, 404):
                break
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                items.extend(data)
            elif isinstance(data, dict):
                items.extend(data.get("value", []))

            # Follow Link header for next page
            next_url = None
            next_params = None
            link_header = resp.headers.get("Link", "")
            for part in link_header.split(","):
                if 'rel="next"' in part:
                    # Extract URL from < >
                    start = part.find("<")
                    end = part.find(">")
                    if start != -1 and end != -1:
                        next_url = part[start + 1:end]
                    break

        return items
