"""Branch protection and MR approval rules for GitLab (GLB001-GLB007)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def audit_branch_policies(
    client,
    project_id: int,
    project_path: str,
    default_branch: str,
) -> list[dict]:
    """Run branch policy rules GLB001-GLB007 for a project's default branch.

    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    # Fetch protected branches
    try:
        protected_branches = client.list_protected_branches(project_id)
    except Exception as e:
        logger.warning("Failed to list protected branches for %s: %s", project_path, e)
        protected_branches = []

    # Find protection for default branch
    default_protection = None
    for pb in protected_branches:
        if pb.get("name") == default_branch:
            default_protection = pb
            break

    # GLB001: Default branch not protected
    if default_protection is None:
        findings.append({
            "rule_id": "GLB001",
            "severity": "high",
            "title": f"Default branch '{default_branch}' is not protected",
            "description": (
                f"Repository {project_path} does not have branch protection "
                f"configured on '{default_branch}'. Direct pushes, force pushes, "
                f"and deletions are possible. Configure branch protection rules."
            ),
            "workflow_file": "",
        })
        # Without protection, many other checks aren't applicable
        return findings

    # GLB004: Force push allowed on default branch
    if default_protection.get("allow_force_push", False):
        findings.append({
            "rule_id": "GLB004",
            "severity": "high",
            "title": f"Force push allowed on '{default_branch}'",
            "description": (
                f"Repository {project_path} allows force pushes to "
                f"'{default_branch}'. This can rewrite history and destroy "
                f"commits. Disable allow_force_push on the protected branch."
            ),
            "workflow_file": "",
        })

    # GLB005: No deletion protection (implicit when branch is protected,
    # but check if any wildcard protection might leave gaps)
    # Protected branches in GitLab cannot be deleted by default, so this
    # is only relevant if the branch is NOT in the protected list (handled by GLB001)

    # GLB003: Code owner approval not required (Premium)
    if not default_protection.get("code_owner_approval_required", False):
        findings.append({
            "rule_id": "GLB003",
            "severity": "medium",
            "title": f"Code owner approval not required on '{default_branch}'",
            "description": (
                f"Repository {project_path} does not require code owner approval "
                f"on '{default_branch}'. Enable code_owner_approval_required to "
                f"ensure designated code owners review changes to their areas."
            ),
            "workflow_file": "",
        })

    # Fetch approval configuration
    approval_config = None
    try:
        approval_config = client.get_project_approval_config(project_id)
    except Exception:
        pass

    # Fetch approval rules
    approval_rules = []
    try:
        approval_rules = client.list_approval_rules(project_id)
    except Exception:
        pass

    # GLB002: No required approvals
    approvals_required = 0
    if approval_config:
        approvals_required = approval_config.get("approvals_before_merge", 0)

    # Also check individual rules
    if approval_rules:
        for rule in approval_rules:
            rule_approvals = rule.get("approvals_required", 0)
            if rule_approvals > approvals_required:
                approvals_required = rule_approvals

    if approvals_required == 0:
        findings.append({
            "rule_id": "GLB002",
            "severity": "high",
            "title": f"No required approvals on '{default_branch}'",
            "description": (
                f"Repository {project_path} does not require any MR approvals "
                f"before merging to '{default_branch}'. Set approvals_before_merge "
                f"to at least 1 to ensure code review."
            ),
            "workflow_file": "",
        })

    # GLB006: Author can approve their own MR
    if approval_config and approval_config.get("merge_requests_author_approval", False):
        findings.append({
            "rule_id": "GLB006",
            "severity": "high",
            "title": "MR author can approve their own merge request",
            "description": (
                f"Repository {project_path} allows MR authors to approve their "
                f"own merge requests (merge_requests_author_approval is enabled). "
                f"Disable this to require independent review."
            ),
            "workflow_file": "",
        })

    # GLB007: Committers can approve
    if approval_config and not approval_config.get("merge_requests_disable_committers_approval", False):
        findings.append({
            "rule_id": "GLB007",
            "severity": "medium",
            "title": "MR committers can approve merge requests",
            "description": (
                f"Repository {project_path} allows users who have committed to "
                f"an MR to also approve it (merge_requests_disable_committers_approval "
                f"is false). Enable this setting to require independent review."
            ),
            "workflow_file": "",
        })

    return findings
