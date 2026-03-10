"""Validate that the GitHub token is a fine-grained PAT with read-only access."""

import logging

import requests

GITHUB_API = "https://api.github.com"

logger = logging.getLogger(__name__)

# Required fine-grained PAT permissions (all read-only):
#   Repository:  Administration (Read), Contents (Read), Metadata (Read, auto-granted)
#   Organization: Members (Read)
# Maps each required permission to its section in the GitHub fine-grained PAT UI.
# Format: "Section heading → Permission name" : "Access level"
REQUIRED_PERMISSIONS = {
    "Repository permissions → Administration": "Read-only",
    "Repository permissions → Contents": "Read-only",
    "Repository permissions → Metadata": "Read-only (auto-granted)",
    "Organization permissions → Members": "Read-only",
}


class TokenPermissionError(Exception):
    """Raised when the token has write or admin access that violates read-only policy."""


def validate_token(token: str, org: str) -> dict:
    """Validate that the token is a fine-grained PAT with the correct permissions.

    Checks:
    1. Token is valid and can authenticate.
    2. Classic PATs are rejected (they cannot provide read-only private repo access).
    3. Fine-grained PATs are probed for:
       a. Minimum required read permissions (org members, repo contents).
       b. No write/admin permissions (repo creation, org settings update).

    Returns the authenticated user info dict on success.
    Raises TokenPermissionError if validation fails.
    """
    headers = _auth_headers(token)

    # Step 1: Check token validity
    resp = requests.get(f"{GITHUB_API}/user", headers=headers, timeout=30)
    if resp.status_code == 401:
        raise TokenPermissionError(
            "Token authentication failed. Ensure the token is valid and not expired."
        )
    resp.raise_for_status()
    user_info = resp.json()

    # Step 2: Detect and reject classic PATs
    scopes_header = resp.headers.get("X-OAuth-Scopes", "")
    if scopes_header:
        # Classic PATs always return X-OAuth-Scopes (even if empty string with scopes)
        _reject_classic_pat(scopes_header)

    # Also detect classic PATs that return an empty X-OAuth-Scopes header
    # (classic PATs with no scopes). Fine-grained PATs omit the header entirely.
    if "X-OAuth-Scopes" in resp.headers:
        _reject_classic_pat(resp.headers["X-OAuth-Scopes"])

    # Step 3: Fine-grained PAT — verify minimum read permissions
    _check_required_read_permissions(token, org)

    # Step 4: Fine-grained PAT — verify no write permissions
    _check_no_write_permissions(token, org)

    return user_info


# ---- Classic PAT rejection ----

WRITE_SCOPES = {
    "repo",             # full repo access (read+write)
    "public_repo",      # write to public repos
    "delete_repo",      # delete repos
    "admin:org",        # full org admin
    "write:org",        # write org membership
    "admin:repo_hook",  # full repo hook access
    "write:repo_hook",  # write repo hooks
}


def _reject_classic_pat(scopes_header: str):
    """Reject all classic PATs — they cannot provide read-only private repo access."""
    scopes = {s.strip() for s in scopes_header.split(",") if s.strip()}
    dangerous = scopes & WRITE_SCOPES

    if dangerous:
        raise TokenPermissionError(
            f"Classic PAT detected with write/admin scopes: "
            f"{', '.join(sorted(dangerous))}. "
            f"Classic PATs are not supported. Please create a fine-grained PAT "
            f"with read-only permissions. See 'gh-auditor --help' for setup instructions."
        )

    # Even read-only classic PATs can't access private repos without 'repo' scope
    raise TokenPermissionError(
        "Classic PAT detected. Classic PATs cannot access private repositories "
        "without the 'repo' scope, which grants write access. "
        "Please create a fine-grained PAT with read-only permissions instead. "
        "See 'gh-auditor --help' for setup instructions."
    )


# ---- Fine-grained PAT: minimum permission checks ----

def _check_required_read_permissions(token: str, org: str):
    """Verify the fine-grained PAT has the minimum required read permissions.

    Probes specific API endpoints that require each permission. A 403 response
    means the permission is missing.
    """
    headers = _auth_headers(token)
    missing = []

    # Check: Organization permissions → Members → Read-only
    # Required for: list org members, teams, outside collaborators, invitations
    resp = requests.get(
        f"{GITHUB_API}/orgs/{org}/members",
        headers=headers,
        params={"per_page": 1, "role": "all"},
        timeout=30,
    )
    if resp.status_code == 403:
        missing.append(
            "Organization permissions → Members → Read-only\n"
            "      (needed to list org owners, teams, and invitations)"
        )
    logger.debug("Members read check: %d", resp.status_code)

    # Check: Repository permissions → Metadata → Read-only (list org repos)
    resp = requests.get(
        f"{GITHUB_API}/orgs/{org}/repos",
        headers=headers,
        params={"per_page": 1, "type": "all"},
        timeout=30,
    )
    if resp.status_code == 403:
        missing.append(
            "Repository permissions → Metadata → Read-only\n"
            "      (needed to list repositories)"
        )
    else:
        repos = resp.json() if resp.status_code == 200 else []
        if isinstance(repos, list) and repos:
            repo_full_name = repos[0]["full_name"]
            owner, repo_name = repo_full_name.split("/", 1)

            # Check: Repository permissions → Contents → Read-only
            resp = requests.get(
                f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/.github",
                headers=headers,
                timeout=30,
            )
            # 404 is OK (directory may not exist), 403 means no permission
            if resp.status_code == 403:
                missing.append(
                    "Repository permissions → Contents → Read-only\n"
                    "      (needed to read workflow YAML files)"
                )
            logger.debug("Contents read check on %s: %d", repo_full_name, resp.status_code)

            # Check: Repository permissions → Administration → Read-only
            resp = requests.get(
                f"{GITHUB_API}/repos/{owner}/{repo_name}/collaborators",
                headers=headers,
                params={"per_page": 1},
                timeout=30,
            )
            if resp.status_code == 403:
                missing.append(
                    "Repository permissions → Administration → Read-only\n"
                    "      (needed to list repo collaborators)"
                )
            logger.debug("Admin read check on %s: %d", repo_full_name, resp.status_code)

    if missing:
        perms_list = "\n    ".join(missing)
        raise TokenPermissionError(
            f"Token is missing required permissions. In your fine-grained PAT settings, "
            f"enable these:\n\n    {perms_list}\n\n"
            f"See 'gh-auditor --help' for full setup instructions."
        )


# ---- Fine-grained PAT: write permission rejection ----

def _check_no_write_permissions(token: str, org: str):
    """Verify the fine-grained PAT does NOT have any write permissions.

    Probes write-only API endpoints with invalid payloads. If the API returns
    422 (payload rejected but auth accepted), the token has write access.
    403/404 means no write access (expected).
    """
    headers = _auth_headers(token)

    # Probe 1: Repository write — attempt to create a repo with invalid name
    resp = requests.post(
        f"{GITHUB_API}/orgs/{org}/repos",
        headers=headers,
        json={"name": ""},  # empty name always fails validation
        timeout=30,
    )
    logger.debug("Repo write probe: %d", resp.status_code)
    if resp.status_code == 422:
        raise TokenPermissionError(
            "Token has WRITE access to organization repositories (can create repos). "
            "This tool requires a read-only token. Please create a new fine-grained PAT "
            "with only 'Read' permissions. See 'gh-auditor --help' for setup instructions."
        )

    # Probe 2: Org admin write — attempt to update org settings with no-op
    resp = requests.patch(
        f"{GITHUB_API}/orgs/{org}",
        headers=headers,
        json={"company": ""},
        timeout=30,
    )
    logger.debug("Org admin write probe: %d", resp.status_code)
    if resp.status_code in (200, 422):
        raise TokenPermissionError(
            "Token has ADMIN/WRITE access to organization settings. "
            "This tool requires a read-only token. Please create a new fine-grained PAT "
            "with only 'Read' permissions. See 'gh-auditor --help' for setup instructions."
        )


def _auth_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
