"""Core auditor that orchestrates scanning repos and running rules."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

import yaml

from .github_client import GitHubClient
from .identity import audit_identity
from .rules import ALL_RULES, Finding

logger = logging.getLogger(__name__)


@dataclass
class RepoSpec:
    """A specific repo + branch to audit.

    When is_regex is True, `repo` is a regex pattern matched against
    repo names in the org, and `branch` (if set) is a regex matched
    against branch names (default branch is used for non-matching repos).
    """
    owner: str
    repo: str
    branch: str | None = None  # None means use default branch
    is_regex: bool = False


@dataclass
class AuditConfig:
    """Configuration for an audit run."""
    org: str
    token: str
    repo_specs: list[RepoSpec] = field(default_factory=list)
    include_archived: bool = False
    include_forks: bool = False
    skip_identity: bool = False
    updated_within_months: int | None = None  # Only scan repos updated within N months


class ProgressCallback(Protocol):
    """Protocol for progress reporting during audit."""

    def on_discovery_start(self) -> None: ...
    def on_discovery_done(self, total_repos: int, skipped: int) -> None: ...
    def on_repo_start(self, repo_name: str, branch: str) -> None: ...
    def on_repo_workflows_found(self, repo_name: str, count: int) -> None: ...
    def on_workflow_scanned(self, repo_name: str, workflow: str, findings_count: int, severity_counts: dict[str, int] | None = None) -> None: ...
    def on_repo_done(self, repo_name: str, findings_count: int) -> None: ...
    def on_repo_error(self, repo_name: str, error: str) -> None: ...
    def on_identity_start(self) -> None: ...
    def on_identity_status(self, message: str) -> None: ...
    def on_identity_done(self, findings_count: int, severity_counts: dict[str, int] | None = None) -> None: ...


class NullProgress:
    """No-op progress callback."""
    def on_discovery_start(self) -> None: pass
    def on_discovery_done(self, total_repos: int, skipped: int) -> None: pass
    def on_repo_start(self, repo_name: str, branch: str) -> None: pass
    def on_repo_workflows_found(self, repo_name: str, count: int) -> None: pass
    def on_workflow_scanned(self, repo_name: str, workflow: str, findings_count: int, severity_counts: dict[str, int] | None = None) -> None: pass
    def on_repo_done(self, repo_name: str, findings_count: int) -> None: pass
    def on_repo_error(self, repo_name: str, error: str) -> None: pass
    def on_identity_start(self) -> None: pass
    def on_identity_status(self, message: str) -> None: pass
    def on_identity_done(self, findings_count: int, severity_counts: dict[str, int] | None = None) -> None: pass


def run_audit(
    config: AuditConfig,
    progress: ProgressCallback | None = None,
) -> dict:
    """Run the full audit and return the JSON-serializable report."""
    if progress is None:
        progress = NullProgress()

    client = GitHubClient(config.token)

    progress.on_discovery_start()

    if config.repo_specs:
        repos_to_audit = _resolve_repo_specs(client, config)
        skipped = 0
    else:
        repos_to_audit, skipped = _collect_org_repos(client, config)

    progress.on_discovery_done(len(repos_to_audit), skipped)

    report = {
        "audit_metadata": {
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

    for repo_meta, branch in repos_to_audit:
        repo_report = _audit_repo(client, repo_meta, branch, progress)
        report["repos"].append(repo_report)

        report["audit_metadata"]["total_repos_scanned"] += 1
        report["audit_metadata"]["total_workflows_scanned"] += repo_report[
            "workflows_scanned"
        ]
        for finding in repo_report["findings"]:
            sev = finding["severity"]
            report["audit_metadata"]["total_findings"] += 1
            report["audit_metadata"]["findings_by_severity"][sev] = (
                report["audit_metadata"]["findings_by_severity"].get(sev, 0) + 1
            )

    # Identity / access audit
    if not config.skip_identity:
        progress.on_identity_start()
        try:
            all_repo_metas = [meta for meta, _ in repos_to_audit]
            identity_report = audit_identity(
                client,
                config.org,
                all_repo_metas,
                on_status=lambda msg: progress.on_identity_status(msg),
            )
            report["identity"] = identity_report

            # Count identity findings toward totals
            identity_severity_counts: dict[str, int] = {}
            for finding in identity_report["findings"]:
                sev = finding.get("severity", "info")
                report["audit_metadata"]["total_findings"] += 1
                report["audit_metadata"]["findings_by_severity"][sev] = (
                    report["audit_metadata"]["findings_by_severity"].get(sev, 0) + 1
                )
                identity_severity_counts[sev] = identity_severity_counts.get(sev, 0) + 1

            progress.on_identity_done(len(identity_report["findings"]), identity_severity_counts)
        except Exception as e:
            logger.warning("Identity audit failed: %s", e)
            report["identity"] = {"error": str(e), "findings": []}
            progress.on_identity_done(0)

    return report


def _updated_cutoff(months: int) -> datetime:
    """Return a UTC datetime N months in the past."""
    return datetime.now(timezone.utc) - timedelta(days=months * 30)


def _is_recently_updated(repo: dict, cutoff: datetime | None) -> bool:
    """Check if repo was pushed to after the cutoff date."""
    if cutoff is None:
        return True
    pushed_at = repo.get("pushed_at")
    if not pushed_at:
        return True  # no info, include by default
    try:
        pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        return pushed >= cutoff
    except (ValueError, TypeError):
        return True


def _collect_org_repos(
    client: GitHubClient, config: AuditConfig
) -> tuple[list[tuple[dict, str]], int]:
    """Fetch all org repos and pair each with its default branch."""
    logger.info("Fetching repositories for org '%s'...", config.org)
    repos = client.list_org_repos(config.org)
    logger.info("Found %d repositories", len(repos))

    cutoff = _updated_cutoff(config.updated_within_months) if config.updated_within_months else None
    if cutoff:
        logger.info("Filtering repos updated within %d month(s) (since %s)", config.updated_within_months, cutoff.isoformat())

    result = []
    skipped = 0
    for repo in repos:
        if repo.get("archived") and not config.include_archived:
            logger.info("SKIP (archived): %s", repo["full_name"])
            skipped += 1
            continue
        if repo.get("fork") and not config.include_forks:
            logger.info("SKIP (fork): %s", repo["full_name"])
            skipped += 1
            continue
        if not _is_recently_updated(repo, cutoff):
            logger.info("SKIP (stale, last pushed %s): %s", repo.get("pushed_at", "unknown"), repo["full_name"])
            skipped += 1
            continue

        branch = repo.get("default_branch", "main")
        logger.info("SCAN: %s @ %s", repo["full_name"], branch)
        result.append((repo, branch))

    logger.info(
        "Repo discovery complete: %d to scan, %d skipped, %d total in org",
        len(result), skipped, len(repos),
    )
    return result, skipped


def _resolve_repo_specs(
    client: GitHubClient, config: AuditConfig
) -> list[tuple[dict, str]]:
    """Resolve user-provided repo/branch specs to metadata + branch pairs.

    Supports both exact repo names and regex patterns. When a spec has
    is_regex=True, all org repos are fetched and matched against the pattern.
    """
    has_regex = any(s.is_regex for s in config.repo_specs)

    # Pre-fetch all org repos if any spec uses regex
    org_repos: list[dict] | None = None
    if has_regex:
        logger.info("Regex repo specs detected, fetching all org repos for matching...")
        org_repos = client.list_org_repos(config.org)

    result = []
    seen = set()  # avoid duplicates when multiple patterns match the same repo

    for spec in config.repo_specs:
        owner = spec.owner or config.org

        if spec.is_regex:
            matches = _match_regex_spec(spec, owner, org_repos or [], config)
            for repo_meta, branch in matches:
                if repo_meta["full_name"] not in seen:
                    seen.add(repo_meta["full_name"])
                    logger.info("SCAN (regex '%s'): %s @ %s", spec.repo, repo_meta["full_name"], branch)
                    result.append((repo_meta, branch))
        else:
            try:
                repo_meta = client.get_repo(owner, spec.repo)
            except Exception as e:
                logger.warning("Could not fetch repo %s/%s: %s", owner, spec.repo, e)
                continue

            if repo_meta["full_name"] not in seen:
                seen.add(repo_meta["full_name"])
                branch = spec.branch or repo_meta.get("default_branch", "main")
                logger.info("SCAN (exact): %s @ %s", repo_meta["full_name"], branch)
                result.append((repo_meta, branch))

    return result


def _match_regex_spec(
    spec: RepoSpec,
    owner: str,
    org_repos: list[dict],
    config: AuditConfig,
) -> list[tuple[dict, str]]:
    """Match a regex RepoSpec against the list of org repos."""
    try:
        repo_pattern = re.compile(spec.repo)
    except re.error as e:
        logger.warning("Invalid regex pattern '%s': %s", spec.repo, e)
        return []

    branch_pattern = None
    if spec.branch:
        try:
            branch_pattern = re.compile(spec.branch)
        except re.error as e:
            logger.warning("Invalid branch regex '%s': %s", spec.branch, e)
            return []

    cutoff = _updated_cutoff(config.updated_within_months) if config.updated_within_months else None

    matches = []
    for repo_meta in org_repos:
        full_name = repo_meta["full_name"]
        repo_owner, repo_name = full_name.split("/", 1)

        # Owner must match exactly (regex only applies to repo name)
        if repo_owner != owner:
            continue

        # Skip archived/forks/stale per config
        if repo_meta.get("archived") and not config.include_archived:
            continue
        if repo_meta.get("fork") and not config.include_forks:
            continue
        if not _is_recently_updated(repo_meta, cutoff):
            continue

        if repo_pattern.fullmatch(repo_name) or repo_pattern.search(repo_name):
            default_branch = repo_meta.get("default_branch", "main")

            if branch_pattern:
                # If a branch regex is given, use it to select the branch.
                # For now, match against the default branch name.
                if branch_pattern.fullmatch(default_branch) or branch_pattern.search(default_branch):
                    matches.append((repo_meta, default_branch))
                else:
                    logger.debug(
                        "Repo %s matched but branch '%s' did not match pattern '%s'",
                        full_name, default_branch, spec.branch,
                    )
            else:
                matches.append((repo_meta, default_branch))

    logger.info(
        "Pattern '%s' matched %d repo(s): %s",
        spec.repo,
        len(matches),
        ", ".join(m[0]["full_name"] for m in matches[:10])
        + ("..." if len(matches) > 10 else ""),
    )
    return matches


def _audit_repo(
    client: GitHubClient,
    repo_meta: dict,
    branch: str,
    progress: ProgressCallback,
) -> dict:
    """Audit a single repository's workflows on the specified branch."""
    full_name = repo_meta["full_name"]
    owner, repo = full_name.split("/", 1)

    visibility = "public" if not repo_meta.get("private", True) else "private"
    logger.info("Auditing %s @ %s (%s)", full_name, branch, visibility)
    progress.on_repo_start(full_name, branch)

    repo_report = {
        "repo": full_name,
        "branch": branch,
        "visibility": visibility,
        "archived": repo_meta.get("archived", False),
        "fork": repo_meta.get("fork", False),
        "default_branch": repo_meta.get("default_branch", "main"),
        "workflows_scanned": 0,
        "findings": [],
    }

    try:
        workflow_files = client.list_workflow_files(owner, repo, branch)
    except Exception as e:
        logger.warning("Failed to list workflows for %s: %s", full_name, e)
        repo_report["error"] = f"Failed to list workflows: {e}"
        progress.on_repo_error(full_name, str(e))
        return repo_report

    logger.info("  Found %d workflow(s) in %s", len(workflow_files), full_name)
    progress.on_repo_workflows_found(full_name, len(workflow_files))

    for wf_name in workflow_files:
        path = f".github/workflows/{wf_name}"
        content = client.get_file_content(owner, repo, path, branch)
        if content is None:
            logger.debug("Could not fetch %s in %s", path, full_name)
            continue

        try:
            workflow = yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.warning("Invalid YAML in %s/%s: %s", full_name, path, e)
            repo_report["findings"].append({
                "rule_id": "GHA000",
                "severity": "info",
                "title": "Invalid workflow YAML",
                "description": f"Could not parse {path}: {e}",
                "workflow_file": wf_name,
            })
            continue

        if not isinstance(workflow, dict):
            continue

        repo_report["workflows_scanned"] += 1

        wf_findings = 0
        wf_severity_counts: dict[str, int] = {}
        for rule_fn in ALL_RULES:
            try:
                rule_findings = rule_fn(wf_name, workflow, repo_meta)
                for f in rule_findings:
                    fd = f.to_dict()
                    repo_report["findings"].append(fd)
                    wf_findings += 1
                    sev = fd.get("severity", "info")
                    wf_severity_counts[sev] = wf_severity_counts.get(sev, 0) + 1
            except Exception as e:
                logger.warning(
                    "Rule %s failed on %s/%s: %s",
                    rule_fn.__name__, full_name, wf_name, e,
                )

        logger.info("  Workflow %s/%s: %d finding(s)", full_name, wf_name, wf_findings)
        progress.on_workflow_scanned(full_name, wf_name, wf_findings, wf_severity_counts)

    logger.info("Done: %s — %d workflow(s), %d finding(s)", full_name, repo_report["workflows_scanned"], len(repo_report["findings"]))
    progress.on_repo_done(full_name, len(repo_report["findings"]))
    return repo_report
