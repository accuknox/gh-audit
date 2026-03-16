"""GitLab audit orchestrator — mirrors run_ado_audit() for Azure DevOps."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .gitlab_client import GitLabClient
from .branch_policies import audit_branch_policies
from .identity import audit_identity
from .pipeline_rules import audit_pipeline_security
from .group_settings import audit_group_settings
from .repo_security import audit_repo_security
from ..scoring import enrich_report

logger = logging.getLogger(__name__)


@dataclass
class GitLabAuditConfig:
    """Configuration for a GitLab audit run."""
    platform: str = "gitlab"
    org: str = ""              # top-level group path
    token: str = ""
    base_url: str = "https://gitlab.com/api/v4"
    groups: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    include_archived: bool = False
    include_forks: bool = False
    skip_identity: bool = False
    skip_group_settings: bool = False
    skip_pipeline_security: bool = False
    updated_within_months: int | None = None


def run_gitlab_audit(config: GitLabAuditConfig, progress=None) -> dict:
    """Run the full GitLab audit and return the report dict.

    Follows the same structure as run_ado_audit():
    - audit_metadata, repos[], org_settings, identity
    """
    from ..auditor import NullProgress
    if progress is None:
        progress = NullProgress()

    client = GitLabClient(config.org, config.token, config.base_url)

    # Discovery phase
    progress.on_discovery_start()

    projects = _discover_projects(client, config)

    report = {
        "audit_metadata": {
            "platform": "gitlab",
            "organization": config.org,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_repos_scanned": 0,
            "total_workflows_scanned": 0,
            "total_findings": 0,
            "findings_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        },
        "repos": [],
    }

    progress.on_discovery_done(len(projects), 0)

    # Per-project audit
    for project in projects:
        project_id = project.get("id")
        project_path = project.get("path_with_namespace", "")
        default_branch = project.get("default_branch", "main") or "main"
        visibility = project.get("visibility", "private")

        progress.on_repo_start(project_path, default_branch)

        repo_report = {
            "repo": project_path,
            "branch": default_branch,
            "visibility": visibility,
            "archived": project.get("archived", False),
            "fork": bool(project.get("forked_from_project")),
            "default_branch": default_branch,
            "workflows_scanned": 0,
            "findings": [],
        }

        # Pipeline security rules
        if not config.skip_pipeline_security:
            try:
                pipeline_findings = audit_pipeline_security(
                    client, project_id, project_path,
                    default_branch, visibility,
                )
                repo_report["findings"].extend(pipeline_findings)
                if pipeline_findings:
                    repo_report["workflows_scanned"] += 1
            except Exception as e:
                logger.warning("Pipeline audit failed for %s: %s", project_path, e)

        # Branch policies
        try:
            bp_findings = audit_branch_policies(
                client, project_id, project_path, default_branch,
            )
            repo_report["findings"].extend(bp_findings)
        except Exception as e:
            logger.warning("Branch policy audit failed for %s: %s", project_path, e)

        # Repository security
        try:
            rs_findings = audit_repo_security(
                client, project_id, project_path, default_branch,
            )
            repo_report["findings"].extend(rs_findings)
        except Exception as e:
            logger.warning("Repo security audit failed for %s: %s", project_path, e)

        # Tally findings
        report["repos"].append(repo_report)
        report["audit_metadata"]["total_repos_scanned"] += 1
        report["audit_metadata"]["total_workflows_scanned"] += repo_report["workflows_scanned"]

        for finding in repo_report["findings"]:
            sev = finding.get("severity", "info")
            report["audit_metadata"]["total_findings"] += 1
            report["audit_metadata"]["findings_by_severity"][sev] = (
                report["audit_metadata"]["findings_by_severity"].get(sev, 0) + 1
            )

        progress.on_repo_done(project_path, len(repo_report["findings"]))

    # Group settings audit
    if not config.skip_group_settings:
        all_settings_findings: list[dict] = []
        try:
            gs_findings = audit_group_settings(client, config.org)
            all_settings_findings.extend(gs_findings)
        except Exception as e:
            logger.warning("Group settings audit failed: %s", e)

        report["org_settings"] = {"findings": all_settings_findings}

        for finding in all_settings_findings:
            sev = finding.get("severity", "info")
            report["audit_metadata"]["total_findings"] += 1
            report["audit_metadata"]["findings_by_severity"][sev] = (
                report["audit_metadata"]["findings_by_severity"].get(sev, 0) + 1
            )

    # Identity / access audit
    if not config.skip_identity:
        progress.on_identity_start()
        try:
            identity_report = audit_identity(
                client,
                config.org,
                on_status=lambda msg: progress.on_identity_status(msg),
            )
            report["identity"] = identity_report

            identity_severity_counts: dict[str, int] = {}
            for finding in identity_report.get("findings", []):
                sev = finding.get("severity", "info")
                report["audit_metadata"]["total_findings"] += 1
                report["audit_metadata"]["findings_by_severity"][sev] = (
                    report["audit_metadata"]["findings_by_severity"].get(sev, 0) + 1
                )
                identity_severity_counts[sev] = identity_severity_counts.get(sev, 0) + 1

            progress.on_identity_done(
                len(identity_report.get("findings", [])),
                identity_severity_counts,
            )
        except Exception as e:
            logger.warning("Identity audit failed: %s", e)
            report["identity"] = {"error": str(e), "findings": []}
            progress.on_identity_done(0)

    # Compute risk scores
    enrich_report(report)

    return report


def _discover_projects(
    client: GitLabClient, config: GitLabAuditConfig
) -> list[dict]:
    """Discover projects to audit."""
    try:
        all_projects = client.list_projects()
    except Exception as e:
        logger.warning("Failed to list projects: %s", e)
        return []

    result = []
    for project in all_projects:
        # Filter archived
        if project.get("archived", False) and not config.include_archived:
            continue

        # Filter by repo name if specified
        if config.repos:
            project_path = project.get("path_with_namespace", "")
            project_name = project.get("name", "")
            if (project_path not in config.repos
                    and project_name not in config.repos):
                continue

        result.append(project)

    return result
