"""Pipeline security rules for GitLab (GLP001-GLP008)."""

from __future__ import annotations

import logging
import re

import yaml

logger = logging.getLogger(__name__)

# CI variables considered attacker-controlled
UNSAFE_VARIABLES = {
    "CI_MERGE_REQUEST_TITLE",
    "CI_COMMIT_MESSAGE",
    "CI_MERGE_REQUEST_DESCRIPTION",
    "CI_COMMIT_TAG_MESSAGE",
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
}

# Pattern matching $VARIABLE or ${VARIABLE} in script blocks
VARIABLE_RE = re.compile(r"\$\{?(" + "|".join(re.escape(v) for v in UNSAFE_VARIABLES) + r")\}?")

# Secret-like variable name patterns
SECRET_NAME_RE = re.compile(
    r"(secret|password|token|key|credential|api_key|private)",
    re.IGNORECASE,
)

# Security job name patterns
SECURITY_JOB_RE = re.compile(
    r"(sast|secret.?detect|dependency.?scan)", re.IGNORECASE
)


def audit_pipeline_security(
    client,
    project_id: int,
    project_path: str,
    default_branch: str,
    visibility: str,
) -> list[dict]:
    """Run pipeline security rules GLP001-GLP008.

    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    # Fetch .gitlab-ci.yml
    ci_content = client.get_file_content(project_id, ".gitlab-ci.yml", default_branch)
    if not ci_content:
        return findings

    try:
        ci_config = yaml.safe_load(ci_content)
    except yaml.YAMLError:
        return findings

    if not isinstance(ci_config, dict):
        return findings

    filename = ".gitlab-ci.yml"

    # GLP001: Unpinned remote includes
    _check_includes(ci_config, filename, project_path, findings)

    # GLP002: Script injection via attacker-controlled variables
    _check_script_injection(ci_config, filename, project_path, findings)

    # GLP003: Shared runners on private/internal projects
    _check_shared_runners(client, project_id, project_path, visibility, findings)

    # GLP004: MR from forks without source project check
    _check_fork_pipeline_rules(ci_config, filename, project_path, findings)

    # GLP005: CI/CD variables with secret-like names not protected/masked
    _check_variables(client, project_id, project_path, findings)

    # GLP006: allow_failure on security jobs
    _check_allow_failure_security(ci_config, filename, project_path, findings)

    # GLP007: Jobs with no rules/only restriction
    _check_unrestricted_jobs(ci_config, filename, project_path, findings)

    # GLP008: Variables with protected=false and environment_scope=*
    _check_variable_scope(client, project_id, project_path, findings)

    return findings


def _get_jobs(ci_config: dict) -> dict[str, dict]:
    """Extract job definitions from CI config (top-level keys that are dicts
    and not reserved keywords)."""
    reserved = {
        "image", "services", "stages", "variables", "cache",
        "before_script", "after_script", "include", "default",
        "workflow", "pages",
    }
    jobs = {}
    for key, value in ci_config.items():
        if key.startswith(".") or key in reserved or not isinstance(value, dict):
            continue
        jobs[key] = value
    return jobs


def _check_includes(
    ci_config: dict, filename: str, project_path: str, findings: list[dict]
) -> None:
    """GLP001: Check for unpinned remote/project includes."""
    includes = ci_config.get("include", [])
    if isinstance(includes, dict):
        includes = [includes]
    if not isinstance(includes, list):
        return

    for inc in includes:
        if isinstance(inc, str):
            # Simple string include (local or remote URL)
            if inc.startswith("http"):
                findings.append({
                    "rule_id": "GLP001",
                    "severity": "high",
                    "title": f"Unpinned remote include in {filename}",
                    "description": (
                        f"Pipeline '{filename}' in {project_path} includes remote "
                        f"template '{inc}' without pinning to a SHA or tag. "
                        f"Pin remote includes to prevent supply chain attacks."
                    ),
                    "workflow_file": filename,
                })
            continue

        if not isinstance(inc, dict):
            continue

        # Remote includes
        remote = inc.get("remote")
        if remote and isinstance(remote, str):
            findings.append({
                "rule_id": "GLP001",
                "severity": "high",
                "title": f"Unpinned remote include in {filename}",
                "description": (
                    f"Pipeline '{filename}' in {project_path} includes remote "
                    f"template '{remote}' without pinning to a SHA or tag."
                ),
                "workflow_file": filename,
            })

        # Project includes without ref pinning
        project = inc.get("project")
        ref = inc.get("ref", "")
        if project and isinstance(project, str):
            is_pinned = False
            if ref:
                # Pinned if full SHA (40 hex) or looks like a tag
                if len(ref) >= 40 and all(c in "0123456789abcdef" for c in ref.lower()):
                    is_pinned = True
                elif ref.startswith("v") and any(c.isdigit() for c in ref):
                    is_pinned = True
            if not is_pinned:
                findings.append({
                    "rule_id": "GLP001",
                    "severity": "high",
                    "title": f"Unpinned project include in {filename}",
                    "description": (
                        f"Pipeline '{filename}' in {project_path} includes template "
                        f"from project '{project}' at ref '{ref or 'default'}' "
                        f"without pinning to a SHA or version tag."
                    ),
                    "workflow_file": filename,
                })


def _check_script_injection(
    ci_config: dict, filename: str, project_path: str, findings: list[dict]
) -> None:
    """GLP002: Check for attacker-controlled variables in script blocks."""
    jobs = _get_jobs(ci_config)

    for job_name, job in jobs.items():
        for script_key in ("script", "before_script", "after_script"):
            scripts = job.get(script_key, [])
            if isinstance(scripts, str):
                scripts = [scripts]
            if not isinstance(scripts, list):
                continue

            for line in scripts:
                if not isinstance(line, str):
                    continue
                for match in VARIABLE_RE.finditer(line):
                    var_name = match.group(1)
                    findings.append({
                        "rule_id": "GLP002",
                        "severity": "high",
                        "title": f"Script injection via ${var_name} in {filename}",
                        "description": (
                            f"Job '{job_name}' in pipeline '{filename}' in {project_path} "
                            f"interpolates attacker-controlled variable '${var_name}' "
                            f"directly into a script block. Use a CI/CD variable with "
                            f"proper escaping instead."
                        ),
                        "workflow_file": filename,
                    })


def _check_shared_runners(
    client, project_id: int, project_path: str, visibility: str,
    findings: list[dict],
) -> None:
    """GLP003: Shared runners on private/internal projects."""
    if visibility == "public":
        return

    try:
        runners = client.list_project_runners(project_id)
    except Exception:
        return

    for runner in runners:
        if runner.get("is_shared", False):
            findings.append({
                "rule_id": "GLP003",
                "severity": "medium",
                "title": f"Shared runner on {visibility} project {project_path}",
                "description": (
                    f"Project {project_path} ({visibility}) uses shared runner "
                    f"'{runner.get('description', 'unknown')}'. Shared runners "
                    f"may execute code from other projects. Consider using "
                    f"group or project-specific runners for sensitive projects."
                ),
                "workflow_file": "",
            })
            break  # One finding per project is enough


def _check_fork_pipeline_rules(
    ci_config: dict, filename: str, project_path: str, findings: list[dict]
) -> None:
    """GLP004: Pipeline rules allowing MR from forks without source check."""
    jobs = _get_jobs(ci_config)

    for job_name, job in jobs.items():
        rules = job.get("rules", [])
        if not isinstance(rules, list):
            continue

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            condition = rule.get("if", "")
            if not isinstance(condition, str):
                continue

            # Check for merge_request_event without fork source check
            if "CI_PIPELINE_SOURCE" in condition and "merge_request_event" in condition:
                if "CI_MERGE_REQUEST_SOURCE_PROJECT_ID" not in condition:
                    # Could run on fork MRs without restriction
                    findings.append({
                        "rule_id": "GLP004",
                        "severity": "high",
                        "title": f"Fork MR pipeline without source check in {filename}",
                        "description": (
                            f"Job '{job_name}' in pipeline '{filename}' in {project_path} "
                            f"runs on merge_request_event without checking "
                            f"CI_MERGE_REQUEST_SOURCE_PROJECT_ID. This allows fork MRs "
                            f"to trigger the pipeline with access to project secrets."
                        ),
                        "workflow_file": filename,
                    })
                    break


def _check_variables(
    client, project_id: int, project_path: str, findings: list[dict]
) -> None:
    """GLP005: CI/CD variables with secret-like names not protected or masked."""
    try:
        variables = client.list_project_variables(project_id)
    except Exception:
        return

    for var in variables:
        key = var.get("key", "")
        if not SECRET_NAME_RE.search(key):
            continue

        is_protected = var.get("protected", False)
        is_masked = var.get("masked", False)

        if not is_protected or not is_masked:
            issues = []
            if not is_protected:
                issues.append("not protected")
            if not is_masked:
                issues.append("not masked")

            findings.append({
                "rule_id": "GLP005",
                "severity": "medium",
                "title": f"Secret-like variable '{key}' {' and '.join(issues)}",
                "description": (
                    f"CI/CD variable '{key}' in project {project_path} has a "
                    f"secret-like name but is {' and '.join(issues)}. Mark it "
                    f"as protected and masked to limit exposure."
                ),
                "workflow_file": "",
            })


def _check_allow_failure_security(
    ci_config: dict, filename: str, project_path: str, findings: list[dict]
) -> None:
    """GLP006: allow_failure on security scanning jobs."""
    jobs = _get_jobs(ci_config)

    for job_name, job in jobs.items():
        if not SECURITY_JOB_RE.search(job_name):
            continue

        if job.get("allow_failure") is True:
            findings.append({
                "rule_id": "GLP006",
                "severity": "medium",
                "title": f"Security job '{job_name}' allows failure in {filename}",
                "description": (
                    f"Security scanning job '{job_name}' in pipeline '{filename}' "
                    f"in {project_path} has allow_failure: true. Security scan "
                    f"failures will not block the pipeline, potentially allowing "
                    f"vulnerabilities to reach production."
                ),
                "workflow_file": filename,
            })


def _check_unrestricted_jobs(
    ci_config: dict, filename: str, project_path: str, findings: list[dict]
) -> None:
    """GLP007: Jobs with no rules/only restriction."""
    jobs = _get_jobs(ci_config)

    for job_name, job in jobs.items():
        has_rules = "rules" in job
        has_only = "only" in job
        has_except = "except" in job

        if not has_rules and not has_only and not has_except:
            findings.append({
                "rule_id": "GLP007",
                "severity": "low",
                "title": f"Unrestricted job '{job_name}' in {filename}",
                "description": (
                    f"Job '{job_name}' in pipeline '{filename}' in {project_path} "
                    f"has no rules:, only:, or except: restrictions. It will run "
                    f"on every pipeline trigger. Add rules to control when it runs."
                ),
                "workflow_file": filename,
            })


def _check_variable_scope(
    client, project_id: int, project_path: str, findings: list[dict]
) -> None:
    """GLP008: Variables with protected=false and environment_scope=*."""
    try:
        variables = client.list_project_variables(project_id)
    except Exception:
        return

    for var in variables:
        key = var.get("key", "")
        is_protected = var.get("protected", False)
        env_scope = var.get("environment_scope", "*")

        if not is_protected and env_scope == "*":
            if SECRET_NAME_RE.search(key):
                findings.append({
                    "rule_id": "GLP008",
                    "severity": "high",
                    "title": f"Unprotected variable '{key}' with wildcard scope",
                    "description": (
                        f"CI/CD variable '{key}' in project {project_path} has "
                        f"protected: false and environment_scope: '*'. This "
                        f"exposes the variable to all branches and environments. "
                        f"Set protected: true or restrict the environment scope."
                    ),
                    "workflow_file": "",
                })
