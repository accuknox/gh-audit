"""Org-level settings audit (ORG001-ORG005)."""

from __future__ import annotations

import logging

from .github_client import GitHubClient

logger = logging.getLogger(__name__)


def audit_org_settings(client: GitHubClient, org: str) -> dict:
    """Audit org-level security settings.

    Returns {"settings": {...}, "findings": [...]}.
    """
    findings: list[dict] = []
    settings: dict = {}

    # Fetch org metadata
    try:
        org_data = client.get_org(org)
    except Exception as e:
        logger.warning("Could not fetch org data for %s: %s", org, e)
        return {"settings": {}, "findings": [], "error": str(e)}

    settings["two_factor_requirement_enabled"] = org_data.get("two_factor_requirement_enabled")
    settings["default_repository_permission"] = org_data.get("default_repository_permission")

    # ORG001: 2FA not required
    if not org_data.get("two_factor_requirement_enabled", False):
        findings.append({
            "rule_id": "ORG001",
            "severity": "critical",
            "title": f"2FA not required for org '{org}'",
            "description": (
                f"Organization '{org}' does not require two-factor authentication "
                f"for its members. Enable 2FA requirement to prevent account "
                f"compromise from leading to org-wide access."
            ),
        })

    # ORG002: Default repo permission too broad
    default_perm = org_data.get("default_repository_permission", "read")
    if default_perm not in ("read", "none"):
        findings.append({
            "rule_id": "ORG002",
            "severity": "high",
            "title": f"Default repo permission is '{default_perm}' in org '{org}'",
            "description": (
                f"Organization '{org}' grants '{default_perm}' permission to all "
                f"members on new repositories by default. Set the default to 'read' "
                f"or 'none' and grant elevated access through teams."
            ),
        })

    # ORG006: Repository creation not restricted
    if org_data.get("members_can_create_repositories", True):
        # Also check specific types
        can_create_public = org_data.get("members_can_create_public_repositories", True)
        can_create_private = org_data.get("members_can_create_private_repositories", True)
        if can_create_public or can_create_private:
            repo_types = []
            if can_create_public:
                repo_types.append("public")
            if can_create_private:
                repo_types.append("private")
            findings.append({
                "rule_id": "ORG006",
                "severity": "medium",
                "title": f"Repository creation not restricted in org '{org}'",
                "description": (
                    f"Organization '{org}' allows all members to create "
                    f"{' and '.join(repo_types)} repositories. Restrict repository "
                    f"creation to admins or specific teams to maintain governance."
                ),
            })

    # ORG007: Organization not verified
    if not org_data.get("is_verified", False):
        findings.append({
            "rule_id": "ORG007",
            "severity": "low",
            "title": f"Organization '{org}' is not verified",
            "description": (
                f"Organization '{org}' does not have a verified badge. Verify "
                f"your organization's domain to confirm identity and restrict "
                f"email notifications to verified domains."
            ),
        })

    settings["members_can_create_repositories"] = org_data.get("members_can_create_repositories")
    settings["is_verified"] = org_data.get("is_verified")

    # ORG003-ORG005: Actions permissions
    actions_perms = client.get_org_actions_permissions(org)
    if actions_perms:
        settings["actions_permissions"] = actions_perms

        # ORG003: All actions allowed
        if actions_perms.get("allowed_actions") == "all":
            findings.append({
                "rule_id": "ORG003",
                "severity": "high",
                "title": f"All GitHub Actions allowed in org '{org}'",
                "description": (
                    f"Organization '{org}' allows all GitHub Actions to run, including "
                    f"actions from any third-party repository. Restrict to 'selected' "
                    f"or 'local_only' to reduce supply chain risk."
                ),
            })

        # ORG004: Default GITHUB_TOKEN has write permissions
        if actions_perms.get("default_workflow_permissions") == "write":
            findings.append({
                "rule_id": "ORG004",
                "severity": "high",
                "title": f"Default GITHUB_TOKEN has write permissions in org '{org}'",
                "description": (
                    f"Organization '{org}' sets the default GITHUB_TOKEN permission to "
                    f"'write'. Set it to 'read' and grant write permissions explicitly "
                    f"in individual workflows."
                ),
            })

        # ORG005: Fork PR workflows run without approval
        if not actions_perms.get("can_approve_pull_request_reviews", True) is False:
            # Check if fork PRs require approval
            fork_approval = actions_perms.get(
                "fork_pull_request_workflows_approval_policy"
            )
            if fork_approval and fork_approval not in (
                "require_approval_for_all_external_pull_requests",
                "require_approval_for_all",
            ):
                findings.append({
                    "rule_id": "ORG005",
                    "severity": "medium",
                    "title": f"Fork PR workflows may run without approval in org '{org}'",
                    "description": (
                        f"Organization '{org}' does not require approval for all fork "
                        f"pull request workflows. Set the policy to require approval "
                        f"for all external contributors to prevent malicious workflow "
                        f"execution."
                    ),
                })

    return {"settings": settings, "findings": findings}
