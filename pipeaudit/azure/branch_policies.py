"""Branch policy rules for Azure DevOps (ABP001-ABP007)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Well-known policy type GUIDs in Azure DevOps
POLICY_MINIMUM_REVIEWERS = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
POLICY_REQUIRED_REVIEWERS = "fd2167ab-b0d6-4f1a-b764-b67e8e1516c1"
POLICY_BUILD_VALIDATION = "0609b952-1397-4640-95ec-e00a01b2c241"
POLICY_COMMENT_RESOLUTION = "c6a1889d-b943-4856-b76f-9e46bb6b0df2"
POLICY_MERGE_STRATEGY = "fa4e907d-c16b-4a4c-9dfa-4916e5d171dd"
POLICY_WORK_ITEM_LINKING = "40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e"


def audit_branch_policies(
    policies: list[dict],
    project: str,
    repo_id: str,
    repo_name: str,
    default_branch: str,
) -> list[dict]:
    """Run branch policy rules ABP001-ABP007 for a repo's default branch.

    Args:
        policies: All policy configurations for the project.
        project: Project name.
        repo_id: Repository ID.
        repo_name: Full repository name for findings.
        default_branch: The default branch name (e.g., "main").

    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    # Normalize default branch ref format
    branch_ref = default_branch
    if not branch_ref.startswith("refs/"):
        branch_ref = f"refs/heads/{branch_ref}"

    # Filter policies for this repo and default branch
    repo_policies = _filter_policies_for_branch(policies, repo_id, branch_ref)

    # Group by policy type
    by_type: dict[str, list[dict]] = {}
    for policy in repo_policies:
        type_id = policy.get("type", {}).get("id", "")
        by_type.setdefault(type_id, []).append(policy)

    # ABP001: No branch policy at all on default branch
    if not repo_policies:
        findings.append({
            "rule_id": "ABP001",
            "severity": "high",
            "title": f"No branch policy on '{default_branch}'",
            "description": (
                f"Repository {repo_name} has no branch policies configured on "
                f"'{default_branch}'. Direct pushes, merges without reviews, and "
                f"bypasses are all possible. Configure branch policies to enforce "
                f"code review and build validation."
            ),
            "workflow_file": "",
        })
        return findings

    # ABP002: Minimum reviewers not configured
    min_reviewer_policies = by_type.get(POLICY_MINIMUM_REVIEWERS, [])
    if not min_reviewer_policies:
        findings.append({
            "rule_id": "ABP002",
            "severity": "high",
            "title": f"No minimum reviewer policy on '{default_branch}'",
            "description": (
                f"Repository {repo_name} does not have a minimum reviewer count "
                f"policy on '{default_branch}'. PRs can be merged without any "
                f"approvals. Add a minimum reviewer policy with at least 1 reviewer."
            ),
            "workflow_file": "",
        })
    else:
        for policy in min_reviewer_policies:
            settings = policy.get("settings", {})
            min_count = settings.get("minimumApproverCount", 0)
            if min_count < 1:
                findings.append({
                    "rule_id": "ABP002",
                    "severity": "high",
                    "title": f"Minimum reviewers set to {min_count} on '{default_branch}'",
                    "description": (
                        f"Repository {repo_name} has a minimum reviewer policy on "
                        f"'{default_branch}' but requires {min_count} approvers. "
                        f"Set minimumApproverCount to at least 1."
                    ),
                    "workflow_file": "",
                })

    # ABP003: No required/code-owner reviewers
    required_reviewer_policies = by_type.get(POLICY_REQUIRED_REVIEWERS, [])
    if not required_reviewer_policies:
        findings.append({
            "rule_id": "ABP003",
            "severity": "medium",
            "title": f"No required reviewers policy on '{default_branch}'",
            "description": (
                f"Repository {repo_name} does not have a required reviewers (code owner) "
                f"policy on '{default_branch}'. Add specific required reviewers to "
                f"ensure designated owners review critical code paths."
            ),
            "workflow_file": "",
        })

    # ABP004: Self-approval allowed (creatorVoteCounts: true)
    for policy in min_reviewer_policies:
        settings = policy.get("settings", {})
        if settings.get("creatorVoteCounts", False):
            findings.append({
                "rule_id": "ABP004",
                "severity": "high",
                "title": f"Self-approval allowed on '{default_branch}'",
                "description": (
                    f"Repository {repo_name} allows the PR creator to approve "
                    f"their own changes on '{default_branch}' (creatorVoteCounts "
                    f"is enabled). Disable this to require independent review."
                ),
                "workflow_file": "",
            })
            break

    # ABP005: No build validation policy
    build_policies = by_type.get(POLICY_BUILD_VALIDATION, [])
    if not build_policies:
        findings.append({
            "rule_id": "ABP005",
            "severity": "high",
            "title": f"No build validation policy on '{default_branch}'",
            "description": (
                f"Repository {repo_name} does not require build validation on "
                f"'{default_branch}'. PRs can be merged without passing CI. "
                f"Add a build validation policy to ensure code compiles and "
                f"tests pass before merging."
            ),
            "workflow_file": "",
        })

    # ABP006: Comment resolution not required
    comment_policies = by_type.get(POLICY_COMMENT_RESOLUTION, [])
    if not comment_policies:
        findings.append({
            "rule_id": "ABP006",
            "severity": "low",
            "title": f"Comment resolution not required on '{default_branch}'",
            "description": (
                f"Repository {repo_name} does not require comment resolution on "
                f"'{default_branch}'. Reviewers' comments may be left unaddressed. "
                f"Add a comment resolution policy to ensure all feedback is resolved."
            ),
            "workflow_file": "",
        })

    # ABP007: No merge strategy restriction
    merge_policies = by_type.get(POLICY_MERGE_STRATEGY, [])
    if not merge_policies:
        findings.append({
            "rule_id": "ABP007",
            "severity": "low",
            "title": f"No merge strategy restriction on '{default_branch}'",
            "description": (
                f"Repository {repo_name} does not enforce a merge strategy on "
                f"'{default_branch}'. All merge types (merge commit, squash, "
                f"rebase) are allowed. Consider restricting to squash or rebase "
                f"for a cleaner history."
            ),
            "workflow_file": "",
        })

    return findings


def _filter_policies_for_branch(
    policies: list[dict], repo_id: str, branch_ref: str
) -> list[dict]:
    """Filter policies that apply to a specific repo and branch."""
    result = []
    for policy in policies:
        if not policy.get("isEnabled", True):
            continue

        settings = policy.get("settings", {})
        scopes = settings.get("scope", [])

        for scope in scopes:
            if not isinstance(scope, dict):
                continue
            scope_repo_id = scope.get("repositoryId")
            scope_ref = scope.get("refName", "")

            # Policy applies if: repo matches (or is null = all repos)
            # AND branch matches (or is null = all branches)
            repo_matches = scope_repo_id is None or scope_repo_id == repo_id
            branch_matches = not scope_ref or scope_ref == branch_ref

            if repo_matches and branch_matches:
                result.append(policy)
                break

    return result
