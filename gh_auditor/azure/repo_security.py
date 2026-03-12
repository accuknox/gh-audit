"""Repository security rules for Azure DevOps (ASC001-ASC004)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def audit_repo_security(
    client,
    project: str,
    repo_id: str,
    repo_name: str,
    repo_meta: dict,
    default_branch: str,
) -> list[dict]:
    """Run repository security rules ASC001-ASC004.

    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    # ASC001: No credential scanning (Advanced Security)
    adv_security = repo_meta.get("advancedSecurity", {})
    if not isinstance(adv_security, dict):
        adv_security = {}

    secret_scanning = adv_security.get("secretScanning", {})
    if not isinstance(secret_scanning, dict) or secret_scanning.get("status") != "enabled":
        findings.append({
            "rule_id": "ASC001",
            "severity": "high",
            "title": f"No credential scanning on {repo_name}",
            "description": (
                f"Repository {repo_name} does not have credential/secret scanning "
                f"enabled via Azure DevOps Advanced Security. Enable Advanced "
                f"Security secret scanning to detect accidentally committed "
                f"credentials and tokens."
            ),
            "workflow_file": "",
        })

    # ASC002: No dependency scanning
    dependency_scanning = adv_security.get("dependencyScanning", {})
    if not isinstance(dependency_scanning, dict) or dependency_scanning.get("status") != "enabled":
        findings.append({
            "rule_id": "ASC002",
            "severity": "medium",
            "title": f"No dependency scanning on {repo_name}",
            "description": (
                f"Repository {repo_name} does not have dependency scanning "
                f"enabled via Azure DevOps Advanced Security. Enable dependency "
                f"scanning to identify known vulnerabilities in third-party packages."
            ),
            "workflow_file": "",
        })

    # ASC003: Forks allowed without restrictions
    fork_policy = repo_meta.get("isForkingAllowed", False)
    # In ADO, fork policy is project-level, but repos can be individually configured
    project_info = repo_meta.get("project", {})
    is_public = project_info.get("visibility", "private") == "public"

    if fork_policy and is_public:
        findings.append({
            "rule_id": "ASC003",
            "severity": "medium",
            "title": f"Forking allowed on public repo {repo_name}",
            "description": (
                f"Repository {repo_name} allows forking in a public project. "
                f"This can lead to uncontrolled code copies and potential "
                f"pipeline abuse via fork PRs. Consider restricting fork policy "
                f"or adding approval gates for fork PR pipelines."
            ),
            "workflow_file": "",
        })

    # ASC004: No SECURITY.md
    security_paths = ["SECURITY.md", ".github/SECURITY.md"]
    has_security_md = False
    for path in security_paths:
        content = client.get_file_content(project, repo_id, path, default_branch)
        if content is not None:
            has_security_md = True
            break

    if not has_security_md:
        findings.append({
            "rule_id": "ASC004",
            "severity": "low",
            "title": f"No SECURITY.md in {repo_name}",
            "description": (
                f"Repository {repo_name} has no SECURITY.md file. Add a security "
                f"policy to tell users how to responsibly report vulnerabilities."
            ),
            "workflow_file": "",
        })

    return findings
