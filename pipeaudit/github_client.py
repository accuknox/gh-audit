"""GitHub API client for fetching org repos and workflow files."""

import base64
import logging

import requests

GITHUB_API = "https://api.github.com"
logger = logging.getLogger(__name__)


class GitHubClient:
    def __init__(self, token: str):
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def list_org_repos(self, org: str) -> list[dict]:
        """List all repositories in an organization, handling pagination."""
        repos = []
        url = f"{GITHUB_API}/orgs/{org}/repos"
        params = {"per_page": 100, "type": "all"}

        while url:
            resp = self._session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            repos.extend(resp.json())
            url = resp.links.get("next", {}).get("url")
            params = None  # params are already encoded in the 'next' URL

        return repos

    def get_repo(self, owner: str, repo: str) -> dict:
        """Get a single repository's metadata."""
        resp = self._session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}", timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    def list_workflow_files(self, owner: str, repo: str, ref: str) -> list[str]:
        """List workflow YAML files under .github/workflows/ for a given ref."""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/.github/workflows"
        resp = self._session.get(url, params={"ref": ref}, timeout=30)

        if resp.status_code == 404:
            return []
        resp.raise_for_status()

        contents = resp.json()
        if not isinstance(contents, list):
            return []

        return [
            item["name"]
            for item in contents
            if item["type"] == "file"
            and (item["name"].endswith(".yml") or item["name"].endswith(".yaml"))
        ]

    def get_file_content(
        self, owner: str, repo: str, path: str, ref: str
    ) -> str | None:
        """Fetch the decoded content of a file at a given ref."""
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
        resp = self._session.get(url, params={"ref": ref}, timeout=30)

        if resp.status_code == 404:
            return None
        resp.raise_for_status()

        data = resp.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return data.get("content")

    # -----------------------------------------------------------------
    # Identity / access audit endpoints
    # -----------------------------------------------------------------

    def list_org_members(self, org: str, role: str = "all") -> list[dict]:
        """List org members. role: 'all', 'admin', or 'member'."""
        return self._paginate(
            f"{GITHUB_API}/orgs/{org}/members",
            params={"per_page": 100, "role": role},
        )

    def list_outside_collaborators(self, org: str) -> list[dict]:
        """List outside collaborators (non-members with repo access)."""
        return self._paginate(
            f"{GITHUB_API}/orgs/{org}/outside_collaborators",
            params={"per_page": 100},
        )

    def list_repo_collaborators(
        self, owner: str, repo: str
    ) -> list[dict]:
        """List collaborators on a repo with their permission level."""
        return self._paginate(
            f"{GITHUB_API}/repos/{owner}/{repo}/collaborators",
            params={"per_page": 100, "affiliation": "all"},
        )

    def list_org_teams(self, org: str) -> list[dict]:
        """List teams in an organization."""
        return self._paginate(
            f"{GITHUB_API}/orgs/{org}/teams",
            params={"per_page": 100},
        )

    def list_team_members(self, org: str, team_slug: str) -> list[dict]:
        """List members of a team."""
        return self._paginate(
            f"{GITHUB_API}/orgs/{org}/teams/{team_slug}/members",
            params={"per_page": 100},
        )

    def list_team_repos(self, org: str, team_slug: str) -> list[dict]:
        """List repos a team has access to, with permission levels."""
        return self._paginate(
            f"{GITHUB_API}/orgs/{org}/teams/{team_slug}/repos",
            params={"per_page": 100},
        )

    def list_pending_invitations(self, org: str) -> list[dict]:
        """List pending org invitations."""
        return self._paginate(
            f"{GITHUB_API}/orgs/{org}/invitations",
            params={"per_page": 100},
        )

    def get_org(self, org: str) -> dict:
        """Get organization metadata."""
        resp = self._session.get(f"{GITHUB_API}/orgs/{org}", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_org_membership(self, org: str, username: str) -> dict | None:
        """Get a user's org membership details (role and state).

        Returns the membership dict or None if not found / no permission.
        The 'role' field is 'admin' for org owners or 'member' for regular members.
        """
        resp = self._session.get(
            f"{GITHUB_API}/orgs/{org}/memberships/{username}", timeout=30
        )
        if resp.status_code in (403, 404):
            logger.debug(
                "Could not fetch membership for %s in %s: %d",
                username, org, resp.status_code,
            )
            return None
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------
    # Search endpoints
    # -----------------------------------------------------------------

    def search_user_commits_in_org(
        self, org: str, username: str, since: str
    ) -> dict:
        """Search for commits by a user in an org since a given date.

        Args:
            org: Organization name.
            username: GitHub login to search for.
            since: ISO date string (YYYY-MM-DD) for the lower bound.

        Returns:
            Search result dict with 'total_count' and 'items'.
            Only requests 1 result (per_page=1) since we mainly need
            total_count and the most recent commit date.
        """
        query = f"org:{org} author:{username} committer-date:>={since}"
        resp = self._session.get(
            f"{GITHUB_API}/search/commits",
            params={
                "q": query,
                "sort": "committer-date",
                "order": "desc",
                "per_page": 1,
            },
            timeout=30,
        )
        if resp.status_code in (403, 422):
            # Rate limited or validation error
            logger.debug(
                "Search commits failed for %s in %s: %d",
                username, org, resp.status_code,
            )
            return {"total_count": -1, "items": []}
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------
    # Branch protection
    # -----------------------------------------------------------------

    def get_branch_protection(self, owner: str, repo: str, branch: str) -> dict | None:
        """Fetch branch protection rules for a given branch.

        Returns the protection dict or None if no protection is configured
        or if the API returns 404/403.
        """
        resp = self._session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/branches/{branch}/protection",
            timeout=30,
        )
        if resp.status_code in (403, 404):
            logger.debug(
                "No branch protection for %s/%s:%s (HTTP %d)",
                owner, repo, branch, resp.status_code,
            )
            return None
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------
    # Org actions permissions
    # -----------------------------------------------------------------

    def get_org_actions_permissions(self, org: str) -> dict | None:
        """Fetch org-level Actions permissions and workflow settings.

        Returns None on 403/404 (insufficient permissions).
        """
        resp = self._session.get(
            f"{GITHUB_API}/orgs/{org}/actions/permissions",
            timeout=30,
        )
        if resp.status_code in (403, 404):
            logger.debug(
                "Could not fetch actions permissions for %s: %d",
                org, resp.status_code,
            )
            return None
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------
    # Apps & tokens endpoints
    # -----------------------------------------------------------------

    def list_org_installations(self, org: str) -> list[dict]:
        """List GitHub App installations for the organization."""
        return self._paginate(
            f"{GITHUB_API}/orgs/{org}/installations",
            params={"per_page": 100},
            key="installations",
        )

    def list_org_fine_grained_pats(self, org: str) -> list[dict]:
        """List fine-grained personal access tokens approved for the org."""
        return self._paginate(
            f"{GITHUB_API}/orgs/{org}/personal-access-tokens",
            params={"per_page": 100},
        )

    # -----------------------------------------------------------------
    # Branch listing
    # -----------------------------------------------------------------

    def list_branches(self, owner: str, repo: str) -> list[dict]:
        """List all branches in a repository."""
        return self._paginate(
            f"{GITHUB_API}/repos/{owner}/{repo}/branches",
            params={"per_page": 100},
        )

    def get_commit(self, owner: str, repo: str, sha: str) -> dict | None:
        """Fetch a single commit by SHA. Returns None on 404/403."""
        resp = self._session.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}",
            timeout=30,
        )
        if resp.status_code in (403, 404):
            return None
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    def _paginate(self, url: str, params: dict | None = None, key: str | None = None) -> list[dict]:
        """Generic paginated GET that returns all items.

        Args:
            key: If set, unwrap envelope-style responses by extracting
                 ``data[key]`` from each page (e.g. ``"installations"``).
        """
        items = []
        while url:
            resp = self._session.get(url, params=params, timeout=30)
            if resp.status_code in (403, 404):
                # Permission denied or not found -- return what we have
                logger.debug("Got %d for %s, stopping pagination", resp.status_code, url)
                break
            resp.raise_for_status()
            data = resp.json()
            if key and isinstance(data, dict):
                data = data.get(key, [])
            if isinstance(data, list):
                items.extend(data)
            url = resp.links.get("next", {}).get("url")
            params = None
        return items

    @property
    def rate_limit(self) -> dict:
        resp = self._session.get(f"{GITHUB_API}/rate_limit", timeout=10)
        resp.raise_for_status()
        return resp.json()["rate"]
