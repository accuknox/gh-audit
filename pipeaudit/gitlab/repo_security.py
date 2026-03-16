"""Repository security rules for GitLab (GLS001-GLS004)."""

from __future__ import annotations

import logging
import re

import yaml

logger = logging.getLogger(__name__)

SECRET_DETECTION_RE = re.compile(
    r"(Secret-Detection|secret_detection|SAST\.gitlab-ci\.yml)", re.IGNORECASE
)
DEPENDENCY_SCANNING_RE = re.compile(
    r"(Dependency-Scanning|dependency_scanning)", re.IGNORECASE
)
CONTAINER_SCANNING_RE = re.compile(
    r"(Container-Scanning|container_scanning)", re.IGNORECASE
)


def audit_repo_security(
    client,
    project_id: int,
    project_path: str,
    default_branch: str,
) -> list[dict]:
    """Run repository security rules GLS001-GLS004.

    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    # Fetch .gitlab-ci.yml for template/job checks
    ci_content = client.get_file_content(project_id, ".gitlab-ci.yml", default_branch)
    ci_text = ci_content or ""

    # GLS001: No secret detection
    if not SECRET_DETECTION_RE.search(ci_text):
        findings.append({
            "rule_id": "GLS001",
            "severity": "high",
            "title": f"No secret detection in {project_path}",
            "description": (
                f"Repository {project_path} does not include the Secret-Detection "
                f"template or define a secret_detection job in .gitlab-ci.yml. "
                f"Enable secret detection to catch accidentally committed secrets."
            ),
            "workflow_file": ".gitlab-ci.yml",
        })

    # GLS002: No dependency scanning
    if not DEPENDENCY_SCANNING_RE.search(ci_text):
        findings.append({
            "rule_id": "GLS002",
            "severity": "medium",
            "title": f"No dependency scanning in {project_path}",
            "description": (
                f"Repository {project_path} does not include the Dependency-Scanning "
                f"template or define a dependency_scanning job in .gitlab-ci.yml. "
                f"Enable dependency scanning to identify known vulnerabilities."
            ),
            "workflow_file": ".gitlab-ci.yml",
        })

    # GLS003: No SECURITY.md
    security_paths = ["SECURITY.md", ".gitlab/SECURITY.md"]
    has_security_md = False
    for path in security_paths:
        content = client.get_file_content(project_id, path, default_branch)
        if content is not None:
            has_security_md = True
            break

    if not has_security_md:
        findings.append({
            "rule_id": "GLS003",
            "severity": "low",
            "title": f"No SECURITY.md in {project_path}",
            "description": (
                f"Repository {project_path} has no SECURITY.md file. Add a "
                f"security policy to tell users how to responsibly report "
                f"vulnerabilities."
            ),
            "workflow_file": "",
        })

    # GLS004: Dockerfile present but no container scanning
    has_dockerfile = client.get_file_content(
        project_id, "Dockerfile", default_branch
    ) is not None

    if has_dockerfile and not CONTAINER_SCANNING_RE.search(ci_text):
        findings.append({
            "rule_id": "GLS004",
            "severity": "medium",
            "title": f"Dockerfile without container scanning in {project_path}",
            "description": (
                f"Repository {project_path} has a Dockerfile but does not include "
                f"the Container-Scanning template or define a container_scanning "
                f"job. Enable container scanning to detect image vulnerabilities."
            ),
            "workflow_file": ".gitlab-ci.yml",
        })

    return findings
