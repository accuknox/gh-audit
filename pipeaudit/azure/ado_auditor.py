"""Azure DevOps audit orchestrator — mirrors run_audit() for GitHub."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .ado_client import AzureDevOpsClient
from .branch_policies import audit_branch_policies
from .identity import audit_identity
from .pipeline_rules import audit_pipeline_security
from .project_settings import audit_project_settings
from .repo_security import audit_repo_security
from ..scoring import enrich_report

logger = logging.getLogger(__name__)


@dataclass
class AdoAuditConfig:
    """Configuration for an Azure DevOps audit run."""
    platform: str = "azure"
    org: str = ""
    token: str = ""
    projects: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    output: str = ""
    html_output: str = ""
    sarif_output: str = ""
    include_disabled_repos: bool = False
    skip_identity: bool = False
    skip_project_settings: bool = False
    skip_pipeline_security: bool = False
    updated_within_months: int | None = None


def run_ado_audit(config: AdoAuditConfig, progress=None) -> dict:
    """Run the full Azure DevOps audit and return the report dict.

    Follows the same structure as the GitHub run_audit():
    - audit_metadata, repos[], org_settings, identity
    """
    from ..auditor import NullProgress
    if progress is None:
        progress = NullProgress()

    client = AzureDevOpsClient(config.org, config.token)

    # Discovery phase
    progress.on_discovery_start()

    projects_to_audit = _discover_projects(client, config)

    report = {
        "audit_metadata": {
            "platform": "azure",
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

    total_repos = 0
    for project_meta in projects_to_audit:
        project_name = project_meta.get("name", "")
        repos = _list_project_repos(client, project_name, config)
        total_repos += len(repos)

    progress.on_discovery_done(total_repos, 0)

    # Per-project, per-repo audit
    for project_meta in projects_to_audit:
        project_name = project_meta.get("name", "")
        logger.info("Auditing project: %s", project_name)

        repos = _list_project_repos(client, project_name, config)

        # Pre-fetch project-level data needed by rules
        try:
            policies = client.list_policy_configurations(project_name)
        except Exception as e:
            logger.warning("Failed to list policies for %s: %s", project_name, e)
            policies = []

        try:
            environments = client.list_environments(project_name)
        except Exception as e:
            logger.warning("Failed to list environments for %s: %s", project_name, e)
            environments = []

        # Pre-fetch environment checks
        env_checks_map: dict[int, list[dict]] = {}
        for env in environments:
            env_id = env.get("id")
            if env_id is not None:
                try:
                    env_checks_map[env_id] = client.get_environment_checks(project_name, env_id)
                except Exception:
                    env_checks_map[env_id] = []

        try:
            variable_groups = client.list_variable_groups(project_name)
        except Exception as e:
            logger.warning("Failed to list variable groups for %s: %s", project_name, e)
            variable_groups = []

        is_public = project_meta.get("visibility", "private") == "public"

        for repo_meta in repos:
            repo_name = f"{project_name}/{repo_meta.get('name', '')}"
            repo_id = repo_meta.get("id", "")
            default_branch = repo_meta.get("defaultBranch", "refs/heads/main")
            # Strip refs/heads/ prefix for display
            branch_display = default_branch
            if branch_display.startswith("refs/heads/"):
                branch_display = branch_display[len("refs/heads/"):]

            progress.on_repo_start(repo_name, branch_display)

            repo_report = {
                "repo": repo_name,
                "branch": branch_display,
                "visibility": "public" if is_public else "private",
                "archived": repo_meta.get("isDisabled", False),
                "fork": False,
                "default_branch": branch_display,
                "workflows_scanned": 0,
                "findings": [],
            }

            # Pipeline security rules
            if not config.skip_pipeline_security:
                try:
                    pipeline_findings = audit_pipeline_security(
                        client, project_name, repo_id, repo_name,
                        branch_display, is_public,
                        environments, env_checks_map, variable_groups,
                    )
                    repo_report["findings"].extend(pipeline_findings)
                    if pipeline_findings:
                        repo_report["workflows_scanned"] += 1
                except Exception as e:
                    logger.warning("Pipeline audit failed for %s: %s", repo_name, e)

            # Branch policies
            try:
                bp_findings = audit_branch_policies(
                    policies, project_name, repo_id, repo_name, branch_display,
                )
                repo_report["findings"].extend(bp_findings)
            except Exception as e:
                logger.warning("Branch policy audit failed for %s: %s", repo_name, e)

            # Repository security
            try:
                rs_findings = audit_repo_security(
                    client, project_name, repo_id, repo_name,
                    repo_meta, branch_display,
                )
                repo_report["findings"].extend(rs_findings)
            except Exception as e:
                logger.warning("Repo security audit failed for %s: %s", repo_name, e)

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

            progress.on_repo_done(repo_name, len(repo_report["findings"]))

    # Project settings audit (serves as org_settings equivalent)
    if not config.skip_project_settings:
        all_settings_findings: list[dict] = []
        for project_meta in projects_to_audit:
            project_name = project_meta.get("name", "")
            try:
                ps_findings = audit_project_settings(client, project_name, project_meta)
                all_settings_findings.extend(ps_findings)
            except Exception as e:
                logger.warning("Project settings audit failed for %s: %s", project_name, e)

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
                projects_to_audit,
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
    client: AzureDevOpsClient, config: AdoAuditConfig
) -> list[dict]:
    """Discover projects to audit."""
    if config.projects:
        projects = []
        for name in config.projects:
            try:
                projects.append(client.get_project(name))
            except Exception as e:
                logger.warning("Could not fetch project '%s': %s", name, e)
        return projects

    return client.list_projects()


def _list_project_repos(
    client: AzureDevOpsClient,
    project: str,
    config: AdoAuditConfig,
) -> list[dict]:
    """List repos in a project, applying filters."""
    try:
        repos = client.list_repositories(project)
    except Exception as e:
        logger.warning("Failed to list repos for %s: %s", project, e)
        return []

    result = []
    for repo in repos:
        if repo.get("isDisabled", False) and not config.include_disabled_repos:
            continue

        # Filter by repo name if specified
        if config.repos:
            repo_name = repo.get("name", "")
            full_name = f"{project}/{repo_name}"
            if repo_name not in config.repos and full_name not in config.repos:
                continue

        result.append(repo)

    return result
