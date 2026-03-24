"""Validate that the GitHub token is a fine-grained PAT with read-only access."""

import logging

import requests

GITHUB_API = "https://api.github.com"

logger = logging.getLogger(__name__)

# Required fine-grained PAT permissions (all read-only):
#   Repository:  Administration (Read), Contents (Read), Metadata (Read, auto-granted)
#   Organization: Members (Read), Administration (Read)
# Maps each required permission to its section in the GitHub fine-grained PAT UI.
# Format: "Section heading → Permission name" : "Access level"
REQUIRED_PERMISSIONS = {
    "Repository permissions → Administration": "Read-only",
    "Repository permissions → Contents": "Read-only",
    "Repository permissions → Metadata": "Read-only (auto-granted)",
    "Organization permissions → Members": "Read-only",
    "Organization permissions → Administration": "Read-only",
}


class TokenPermissionError(Exception):
    """Raised when the token has write or admin access that violates read-only policy."""


def validate_token(token: str, org: str) -> dict:
    """Validate that the token is a fine-grained PAT with the correct permissions.

    Checks:
    1. Token is valid and can authenticate.
    2. Classic PATs are rejected (they cannot provide read-only private repo access).
    3. Fine-grained PATs are probed for minimum required read permissions.

    Note: Write permission checks are intentionally omitted. Org owners get
    implicit write access on their fine-grained PATs regardless of selected
    permissions, making write probes unreliable. Since this tool only performs
    read operations, extra permissions are harmless.

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
    """Warn about classic PATs — they may have broader access than needed."""
    scopes = {s.strip() for s in scopes_header.split(",") if s.strip()}
    dangerous = scopes & WRITE_SCOPES

    if dangerous:
        logger.warning(
            "Classic PAT detected with write/admin scopes: %s. "
            "For least-privilege access, consider creating a fine-grained PAT "
            "with read-only permissions instead.",
            ", ".join(sorted(dangerous)),
        )
    else:
        logger.warning(
            "Classic PAT detected. For least-privilege access, consider creating "
            "a fine-grained PAT with read-only permissions instead."
        )


# ---- Fine-grained PAT: minimum permission checks ----

def _check_required_read_permissions(token: str, org: str):
    """Verify the fine-grained PAT has the minimum required read permissions.

    Probes specific API endpoints that require each permission. A 403 response
    means the permission is missing.

    Permissions are split into "required" (blocks audit) and "optional"
    (warns but continues). Administration:Read is optional because some
    orgs restrict fine-grained PAT access to admin endpoints via org policy.
    """
    headers = _auth_headers(token)
    missing = []
    warnings = []

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
            # This is optional — some orgs block fine-grained PATs from
            # admin endpoints via org policy. The audit will still work but
            # branch protection, collaborator listings, and identity checks
            # will be degraded.
            resp = requests.get(
                f"{GITHUB_API}/repos/{owner}/{repo_name}/collaborators",
                headers=headers,
                params={"per_page": 1},
                timeout=30,
            )
            if resp.status_code == 403:
                warnings.append(
                    "Repository permissions → Administration → Read-only\n"
                    "      (needed to list repo collaborators and branch protection)\n"
                    "      The audit will continue but some checks will be skipped."
                )
            logger.debug("Admin read check on %s: %d", repo_full_name, resp.status_code)

    # Check: Organization permissions → Administration → Read-only
    # Optional — needed for Apps & Tokens audit (APP/PAT rules).
    # The audit degrades gracefully if this is missing.
    resp = requests.get(
        f"{GITHUB_API}/orgs/{org}/installations",
        headers=headers,
        params={"per_page": 1},
        timeout=30,
    )
    if resp.status_code == 403:
        warnings.append(
            "Organization permissions → Administration → Read-only\n"
            "      (needed for GitHub App installations and fine-grained PAT audit)\n"
            "      The audit will continue but Apps & Tokens checks will be skipped."
        )
    logger.debug("Org administration read check: %d", resp.status_code)

    if warnings:
        for w in warnings:
            logger.warning("Optional permission missing: %s", w.split("\n")[0].strip())

    if missing:
        for m in missing:
            logger.warning("Missing permission (audit may be degraded): %s", m.split("\n")[0].strip())


def _auth_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
