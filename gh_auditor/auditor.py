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
from .scoring import enrich_report

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
    skip_repo_security: bool = False
    skip_org_settings: bool = False
    skip_apps_and_tokens: bool = False
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
    def on_apps_tokens_start(self) -> None: ...
    def on_apps_tokens_status(self, message: str) -> None: ...
    def on_apps_tokens_done(self, findings_count: int, severity_counts: dict[str, int] | None = None) -> None: ...


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
    def on_apps_tokens_start(self) -> None: pass
    def on_apps_tokens_status(self, message: str) -> None: pass
    def on_apps_tokens_done(self, findings_count: int, severity_counts: dict[str, int] | None = None) -> None: pass


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

    # Org settings audit
    if not config.skip_org_settings:
        try:
            from .org_settings import audit_org_settings
            org_settings_report = audit_org_settings(client, config.org)
            report["org_settings"] = org_settings_report

            for finding in org_settings_report.get("findings", []):
                sev = finding.get("severity", "info")
                report["audit_metadata"]["total_findings"] += 1
                report["audit_metadata"]["findings_by_severity"][sev] = (
                    report["audit_metadata"]["findings_by_severity"].get(sev, 0) + 1
                )
        except Exception as e:
            logger.warning("Org settings audit failed: %s", e)
            report["org_settings"] = {"error": str(e), "findings": []}

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

    # Apps & tokens audit
    if not config.skip_apps_and_tokens:
        progress.on_apps_tokens_start()
        try:
            from .apps_and_tokens import audit_apps_and_tokens
            apps_tokens_report = audit_apps_and_tokens(
                client, config.org,
                on_status=lambda msg: progress.on_apps_tokens_status(msg),
            )
            report["apps_and_tokens"] = apps_tokens_report

            apps_tokens_severity_counts: dict[str, int] = {}
            for finding in apps_tokens_report["findings"]:
                sev = finding.get("severity", "info")
                report["audit_metadata"]["total_findings"] += 1
                report["audit_metadata"]["findings_by_severity"][sev] = (
                    report["audit_metadata"]["findings_by_severity"].get(sev, 0) + 1
                )
                apps_tokens_severity_counts[sev] = apps_tokens_severity_counts.get(sev, 0) + 1

            progress.on_apps_tokens_done(len(apps_tokens_report["findings"]), apps_tokens_severity_counts)
        except Exception as e:
            logger.warning("Apps & tokens audit failed: %s", e)
            report["apps_and_tokens"] = {"error": str(e), "findings": []}
            progress.on_apps_tokens_done(0)

    # Compute risk scores
    enrich_report(report)

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

    # Branch protection audit on the scanned branch
    _audit_branch_protection(client, owner, repo, branch, repo_report)

    # Repository security features audit
    _audit_repo_security(client, owner, repo, branch, repo_meta, repo_report)

    logger.info("Done: %s — %d workflow(s), %d finding(s)", full_name, repo_report["workflows_scanned"], len(repo_report["findings"]))
    progress.on_repo_done(full_name, len(repo_report["findings"]))
    return repo_report


def _audit_branch_protection(
    client: GitHubClient,
    owner: str,
    repo: str,
    branch: str,
    repo_report: dict,
) -> None:
    """Check branch protection rules and append findings to repo_report."""
    full_name = f"{owner}/{repo}"
    logger.info("  Checking branch protection for %s @ %s", full_name, branch)

    try:
        protection = client.get_branch_protection(owner, repo, branch)
    except Exception as e:
        logger.warning("Failed to fetch branch protection for %s: %s", full_name, e)
        return

    if protection is None:
        # No branch protection at all — both rules fail
        repo_report["findings"].append({
            "rule_id": "BPR001",
            "severity": "high",
            "title": f"No branch protection rules on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} has no branch protection rules configured. "
                f"This means PRs can be merged without any approvals and direct pushes to "
                f"the branch are allowed. Enable branch protection with required reviews "
                f"and restrict direct pushes."
            ),
            "workflow_file": "",
        })
        return

    # Rule 1: PRs must require at least 1 approver
    pr_reviews = protection.get("required_pull_request_reviews")
    if not pr_reviews:
        repo_report["findings"].append({
            "rule_id": "BPR001",
            "severity": "high",
            "title": f"No required PR reviews on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} does not require pull request reviews "
                f"before merging. Anyone with write access can merge PRs without approval. "
                f"Enable 'Require pull request reviews before merging' with at least 1 "
                f"required approving review."
            ),
            "workflow_file": "",
        })
    else:
        required_count = pr_reviews.get("required_approving_review_count", 0)
        if required_count < 1:
            repo_report["findings"].append({
                "rule_id": "BPR001",
                "severity": "high",
                "title": f"Required approving reviews is 0 on '{branch}'",
                "description": (
                    f"Branch '{branch}' in {full_name} has pull request reviews enabled "
                    f"but required_approving_review_count is {required_count}. Set this "
                    f"to at least 1 to ensure PRs are reviewed before merging."
                ),
                "workflow_file": "",
            })

    # Rule 2: Direct pushes should be restricted (enforce_admins + restrict pushes)
    # Check 'restrictions' (limits who can push) and 'enforce_admins' (applies rules to admins too)
    restrictions = protection.get("restrictions")
    enforce_admins = protection.get("enforce_admins", {})
    enforce_admins_enabled = enforce_admins.get("enabled", False) if isinstance(enforce_admins, dict) else bool(enforce_admins)
    allow_force_pushes = protection.get("allow_force_pushes", {})
    force_pushes_enabled = allow_force_pushes.get("enabled", False) if isinstance(allow_force_pushes, dict) else bool(allow_force_pushes)

    if restrictions is None and not enforce_admins_enabled:
        repo_report["findings"].append({
            "rule_id": "BPR002",
            "severity": "high",
            "title": f"Direct pushes not restricted on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} does not restrict who can push directly. "
                f"There are no push restrictions configured and admin enforcement is disabled, "
                f"meaning admins can bypass all branch protection rules. Enable push restrictions "
                f"and/or 'Include administrators' to prevent direct commits to the branch."
            ),
            "workflow_file": "",
        })
    elif not enforce_admins_enabled:
        repo_report["findings"].append({
            "rule_id": "BPR002",
            "severity": "medium",
            "title": f"Admins can bypass branch protection on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} has push restrictions but "
                f"'Include administrators' (enforce_admins) is disabled. Org/repo admins "
                f"can still push directly to the branch, bypassing all protection rules. "
                f"Enable 'Include administrators' to enforce rules for everyone."
            ),
            "workflow_file": "",
        })

    if force_pushes_enabled:
        repo_report["findings"].append({
            "rule_id": "BPR002",
            "severity": "critical",
            "title": f"Force pushes allowed on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} allows force pushes. This means "
                f"anyone with push access can rewrite branch history, potentially "
                f"removing security fixes or injecting malicious code. Disable force "
                f"pushes on protected branches."
            ),
            "workflow_file": "",
        })

    # Rule 3: Required status checks must be configured
    status_checks = protection.get("required_status_checks")
    if not status_checks:
        repo_report["findings"].append({
            "rule_id": "BPR003",
            "severity": "high",
            "title": f"Required status checks not configured on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} has no required status checks. "
                f"Merging is allowed without any CI/status checks passing. "
                f"Configure required status checks to ensure PRs pass CI before merging."
            ),
            "workflow_file": "",
        })
    else:
        contexts = status_checks.get("contexts", [])
        checks = status_checks.get("checks", [])
        if not contexts and not checks:
            repo_report["findings"].append({
                "rule_id": "BPR003",
                "severity": "high",
                "title": f"Required status checks empty on '{branch}'",
                "description": (
                    f"Branch '{branch}' in {full_name} has required status checks enabled "
                    f"but no specific checks are configured. Merging is allowed without any "
                    f"CI/status checks passing. Add at least one required status check."
                ),
                "workflow_file": "",
            })

    # Rule 4: Stale reviews should be dismissed on new pushes
    if pr_reviews and not pr_reviews.get("dismiss_stale_reviews", False):
        repo_report["findings"].append({
            "rule_id": "BPR004",
            "severity": "medium",
            "title": f"Stale reviews not dismissed on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} does not dismiss stale pull request "
                f"reviews when new commits are pushed. An approved PR can have new, "
                f"unreviewed code added after approval. Enable 'Dismiss stale pull "
                f"request approvals when new commits are pushed'."
            ),
            "workflow_file": "",
        })

    # Rule 5: Branch deletion should not be allowed
    allow_deletions = protection.get("allow_deletions", {})
    deletions_enabled = allow_deletions.get("enabled", False) if isinstance(allow_deletions, dict) else bool(allow_deletions)
    if deletions_enabled:
        repo_report["findings"].append({
            "rule_id": "BPR005",
            "severity": "critical",
            "title": f"Branch deletion allowed on '{branch}'",
            "description": (
                f"Protected branch '{branch}' in {full_name} can be deleted, risking "
                f"loss of history. Disable 'Allow deletions' on this protected branch."
            ),
            "workflow_file": "",
        })

    # Rule 6: Signed commits should be required
    if not protection.get("required_signatures", {}).get("enabled", False):
        repo_report["findings"].append({
            "rule_id": "BPR006",
            "severity": "medium",
            "title": f"Signed commits not required on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} does not require signed commits. "
                f"Enable 'Require signed commits' to verify commit authenticity."
            ),
            "workflow_file": "",
        })

    # Rule 7: Code owner reviews should be required (only if PR reviews exist)
    if pr_reviews and not pr_reviews.get("require_code_owner_reviews", False):
        repo_report["findings"].append({
            "rule_id": "BPR007",
            "severity": "medium",
            "title": f"Code owner reviews not required on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} has PR reviews enabled but does not "
                f"require review from code owners. Enable 'Require review from Code Owners' "
                f"to ensure designated owners approve changes to their areas."
            ),
            "workflow_file": "",
        })

    # Rule 8: Dismissal restrictions should be set (only if PR reviews exist)
    if pr_reviews and not pr_reviews.get("dismissal_restrictions"):
        repo_report["findings"].append({
            "rule_id": "BPR008",
            "severity": "low",
            "title": f"No dismissal restrictions on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} has PR reviews enabled but no "
                f"dismissal restrictions. Anyone who can push can dismiss reviews. "
                f"Configure dismissal restrictions to limit who can dismiss reviews."
            ),
            "workflow_file": "",
        })

    # Rule 9: Linear history should be required
    if not protection.get("required_linear_history", {}).get("enabled", False):
        repo_report["findings"].append({
            "rule_id": "BPR009",
            "severity": "low",
            "title": f"Linear history not required on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} does not require linear history. "
                f"Enable 'Require linear history' to prevent merge commits and keep "
                f"a clean, auditable commit history."
            ),
            "workflow_file": "",
        })

    # Rule 10: Conversation resolution should be required
    if not protection.get("required_conversation_resolution", {}).get("enabled", False):
        repo_report["findings"].append({
            "rule_id": "BPR010",
            "severity": "low",
            "title": f"Conversation resolution not required on '{branch}'",
            "description": (
                f"Branch '{branch}' in {full_name} does not require conversations to be "
                f"resolved before merging. Enable 'Require conversation resolution' to "
                f"ensure all review comments are addressed."
            ),
            "workflow_file": "",
        })


def _audit_repo_security(
    client: GitHubClient,
    owner: str,
    repo: str,
    branch: str,
    repo_meta: dict,
    repo_report: dict,
) -> None:
    """Check repository security features and append findings to repo_report."""
    full_name = f"{owner}/{repo}"

    # SEC001-SEC003: Check security_and_analysis settings
    security_and_analysis = repo_meta.get("security_and_analysis") or {}

    if security_and_analysis:
        # SEC001: Secret scanning
        secret_scanning = security_and_analysis.get("secret_scanning") or {}
        if secret_scanning.get("status") != "enabled":
            repo_report["findings"].append({
                "rule_id": "SEC001",
                "severity": "high",
                "title": f"Secret scanning not enabled on {full_name}",
                "description": (
                    f"Repository {full_name} does not have secret scanning enabled. "
                    f"Enable secret scanning to detect accidentally committed secrets."
                ),
                "workflow_file": "",
            })

        # SEC002: Push protection
        push_protection = security_and_analysis.get("secret_scanning_push_protection") or {}
        if push_protection.get("status") != "enabled":
            repo_report["findings"].append({
                "rule_id": "SEC002",
                "severity": "high",
                "title": f"Push protection not enabled on {full_name}",
                "description": (
                    f"Repository {full_name} does not have secret scanning push protection "
                    f"enabled. Enable push protection to block pushes containing secrets."
                ),
                "workflow_file": "",
            })

        # SEC003: Dependabot security updates
        dependabot = security_and_analysis.get("dependabot_security_updates") or {}
        if dependabot.get("status") != "enabled":
            repo_report["findings"].append({
                "rule_id": "SEC003",
                "severity": "medium",
                "title": f"Dependabot security updates disabled on {full_name}",
                "description": (
                    f"Repository {full_name} does not have Dependabot security updates "
                    f"enabled. Enable Dependabot to automatically receive PRs that fix "
                    f"known vulnerabilities in dependencies."
                ),
                "workflow_file": "",
            })

    # SEC004: CODEOWNERS file
    codeowners_paths = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]
    has_codeowners = False
    for path in codeowners_paths:
        try:
            content = client.get_file_content(owner, repo, path, branch)
            if content is not None:
                has_codeowners = True
                break
        except Exception:
            continue

    if not has_codeowners:
        repo_report["findings"].append({
            "rule_id": "SEC004",
            "severity": "medium",
            "title": f"No CODEOWNERS file in {full_name}",
            "description": (
                f"Repository {full_name} has no CODEOWNERS file. Add a CODEOWNERS file "
                f"to define code ownership and automatically request reviews from the "
                f"right teams."
            ),
            "workflow_file": "",
        })

    # SEC005: SECURITY.md file
    security_paths = ["SECURITY.md", ".github/SECURITY.md"]
    has_security_md = False
    for path in security_paths:
        try:
            content = client.get_file_content(owner, repo, path, branch)
            if content is not None:
                has_security_md = True
                break
        except Exception:
            continue

    if not has_security_md:
        repo_report["findings"].append({
            "rule_id": "SEC005",
            "severity": "low",
            "title": f"No SECURITY.md in {full_name}",
            "description": (
                f"Repository {full_name} has no SECURITY.md file. Add a security policy "
                f"to tell users how to responsibly report vulnerabilities."
            ),
            "workflow_file": "",
        })
