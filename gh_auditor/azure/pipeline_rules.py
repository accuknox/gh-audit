"""Pipeline security rules for Azure DevOps (AZP001-AZP008)."""

from __future__ import annotations

import logging
import re

import yaml

logger = logging.getLogger(__name__)

# Variables considered attacker-controlled in ADO pipelines
UNSAFE_VARIABLES = {
    "Build.SourceVersionMessage",
    "Build.RequestedFor",
    "Build.RequestedForEmail",
    "System.PullRequest.SourceBranch",
    "System.PullRequest.TargetBranch",
    "Build.SourceBranchName",
}

# Pattern matching $(<variable>) interpolation in scripts
INTERPOLATION_RE = re.compile(r"\$\(([^)]+)\)")


def audit_pipeline_security(
    client,
    project: str,
    repo_id: str,
    repo_name: str,
    default_branch: str,
    is_public: bool,
    environments: list[dict],
    env_checks_map: dict[int, list[dict]],
    variable_groups: list[dict],
) -> list[dict]:
    """Run pipeline security rules AZP001-AZP008 on all pipelines in a repo.

    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    # Fetch pipeline YAML content from the repo
    yaml_content = client.get_file_content(
        project, repo_id, "azure-pipelines.yml", default_branch
    )
    if yaml_content:
        findings.extend(
            _check_pipeline_yaml(
                yaml_content, "azure-pipelines.yml", repo_name,
                is_public, environments, env_checks_map, variable_groups,
            )
        )

    # Also check build definitions for YAML pipeline paths
    try:
        definitions = client.list_build_definitions(project)
    except Exception as e:
        logger.warning("Failed to list build definitions for %s: %s", project, e)
        definitions = []

    for defn in definitions:
        repo_info = defn.get("repository", {})
        if repo_info.get("id") != repo_id:
            continue

        yaml_filename = defn.get("process", {}).get("yamlFilename")
        if not yaml_filename or yaml_filename == "azure-pipelines.yml":
            continue

        content = client.get_file_content(project, repo_id, yaml_filename, default_branch)
        if content:
            findings.extend(
                _check_pipeline_yaml(
                    content, yaml_filename, repo_name,
                    is_public, environments, env_checks_map, variable_groups,
                )
            )

    return findings


def _check_pipeline_yaml(
    content: str,
    filename: str,
    repo_name: str,
    is_public: bool,
    environments: list[dict],
    env_checks_map: dict[int, list[dict]],
    variable_groups: list[dict],
) -> list[dict]:
    """Analyze a single pipeline YAML for security issues."""
    findings: list[dict] = []

    try:
        pipeline = yaml.safe_load(content)
    except yaml.YAMLError:
        return findings

    if not isinstance(pipeline, dict):
        return findings

    # Collect all steps from stages/jobs/steps
    steps = _collect_steps(pipeline)
    jobs = _collect_jobs(pipeline)

    # AZP001: checkout with persistCredentials: true
    for step in steps:
        if isinstance(step, dict) and step.get("checkout"):
            if step.get("persistCredentials") is True:
                findings.append({
                    "rule_id": "AZP001",
                    "severity": "high",
                    "title": f"Checkout with persistCredentials in {filename}",
                    "description": (
                        f"Pipeline '{filename}' in {repo_name} uses checkout with "
                        f"persistCredentials: true. This leaves the Git credential "
                        f"available to subsequent steps, which could be exploited "
                        f"to push code or access other repos."
                    ),
                    "workflow_file": filename,
                })

    # AZP002: Unpinned template references
    _check_templates(pipeline, filename, repo_name, findings)

    # AZP004: Script with elevated permissions (target: host)
    for step in steps:
        if not isinstance(step, dict):
            continue
        target = step.get("target")
        if isinstance(target, str) and target.lower() == "host":
            findings.append({
                "rule_id": "AZP004",
                "severity": "medium",
                "title": f"Script targets host in {filename}",
                "description": (
                    f"A step in pipeline '{filename}' in {repo_name} uses "
                    f"'target: host', running directly on the agent machine "
                    f"with elevated access outside the container sandbox."
                ),
                "workflow_file": filename,
            })
        elif isinstance(target, dict) and target.get("container", "").lower() == "host":
            findings.append({
                "rule_id": "AZP004",
                "severity": "medium",
                "title": f"Script targets host in {filename}",
                "description": (
                    f"A step in pipeline '{filename}' in {repo_name} uses "
                    f"'target.container: host', running directly on the agent "
                    f"machine outside the container sandbox."
                ),
                "workflow_file": filename,
            })

    # AZP005: Self-hosted agent in public project
    if is_public:
        pool = pipeline.get("pool")
        if isinstance(pool, dict) and pool.get("name") and not pool.get("vmImage"):
            demands = pool.get("demands", [])
            if not demands:
                findings.append({
                    "rule_id": "AZP005",
                    "severity": "critical",
                    "title": f"Self-hosted agent in public project ({filename})",
                    "description": (
                        f"Pipeline '{filename}' in {repo_name} uses a self-hosted "
                        f"agent pool '{pool['name']}' in a public project without "
                        f"demands or gates. Any fork PR can execute code on the "
                        f"self-hosted agent, risking persistent compromise."
                    ),
                    "workflow_file": filename,
                })

        for job in jobs:
            job_pool = job.get("pool")
            if isinstance(job_pool, dict) and job_pool.get("name") and not job_pool.get("vmImage"):
                demands = job_pool.get("demands", [])
                if not demands:
                    findings.append({
                        "rule_id": "AZP005",
                        "severity": "critical",
                        "title": f"Self-hosted agent in public project ({filename})",
                        "description": (
                            f"Job in pipeline '{filename}' in {repo_name} uses a "
                            f"self-hosted agent pool '{job_pool['name']}' in a public "
                            f"project without demands. Fork PRs can execute code on it."
                        ),
                        "workflow_file": filename,
                    })

    # AZP006: Script injection via variable interpolation
    for step in steps:
        if not isinstance(step, dict):
            continue
        for key in ("script", "bash", "powershell", "pwsh"):
            script_content = step.get(key)
            if not isinstance(script_content, str):
                continue
            for match in INTERPOLATION_RE.finditer(script_content):
                var_name = match.group(1).strip()
                if var_name in UNSAFE_VARIABLES:
                    findings.append({
                        "rule_id": "AZP006",
                        "severity": "high",
                        "title": f"Script injection via $({var_name}) in {filename}",
                        "description": (
                            f"Pipeline '{filename}' in {repo_name} interpolates "
                            f"attacker-controlled variable '$({var_name})' directly "
                            f"into a script block. Use an environment variable mapping "
                            f"instead to prevent command injection."
                        ),
                        "workflow_file": filename,
                    })

    # AZP007: Environment without approval checks
    _check_environment_approvals(
        pipeline, filename, repo_name, environments, env_checks_map, findings
    )

    # AZP008: Secret variable group accessible to all pipelines
    _check_variable_groups(pipeline, filename, repo_name, variable_groups, findings)

    # AZP003: Service connection without approvals
    _check_service_connections(
        pipeline, filename, repo_name, environments, env_checks_map, findings
    )

    return findings


def _collect_steps(pipeline: dict) -> list[dict]:
    """Extract all steps from a pipeline definition."""
    steps = list(pipeline.get("steps", []) or [])

    for stage in pipeline.get("stages", []) or []:
        if not isinstance(stage, dict):
            continue
        for job in stage.get("jobs", []) or []:
            if not isinstance(job, dict):
                continue
            steps.extend(job.get("steps", []) or [])

    for job in pipeline.get("jobs", []) or []:
        if not isinstance(job, dict):
            continue
        steps.extend(job.get("steps", []) or [])

    return steps


def _collect_jobs(pipeline: dict) -> list[dict]:
    """Extract all jobs from a pipeline definition."""
    jobs = list(pipeline.get("jobs", []) or [])

    for stage in pipeline.get("stages", []) or []:
        if not isinstance(stage, dict):
            continue
        jobs.extend(stage.get("jobs", []) or [])

    return jobs


def _check_templates(
    pipeline: dict, filename: str, repo_name: str, findings: list[dict]
) -> None:
    """AZP002: Check for unpinned template references."""

    def _check_ref(ref: str) -> bool:
        """Return True if the template reference is pinned."""
        if "@" not in ref:
            return True  # local template, no remote ref
        _, version_part = ref.rsplit("@", 1)
        # Pinned if it references a tag or a full SHA (40+ hex chars)
        if version_part.startswith("refs/tags/"):
            return True
        if len(version_part) >= 40 and all(c in "0123456789abcdef" for c in version_part.lower()):
            return True
        return False

    def _scan_value(value):
        if isinstance(value, str) and "@" in value:
            if not _check_ref(value):
                findings.append({
                    "rule_id": "AZP002",
                    "severity": "high",
                    "title": f"Unpinned template reference in {filename}",
                    "description": (
                        f"Pipeline '{filename}' in {repo_name} references template "
                        f"'{value}' without pinning to a tag or SHA. Use "
                        f"'@refs/tags/<tag>' or a full commit SHA to prevent "
                        f"supply chain attacks via mutable branch references."
                    ),
                    "workflow_file": filename,
                })

    # Check extends templates
    extends = pipeline.get("extends")
    if isinstance(extends, dict):
        template = extends.get("template", "")
        _scan_value(template)

    # Check resource repositories used as templates
    resources = pipeline.get("resources", {})
    if isinstance(resources, dict):
        for repo in resources.get("repositories", []) or []:
            if isinstance(repo, dict):
                ref = repo.get("ref", "")
                name = repo.get("repository", repo.get("name", ""))
                if ref and not ref.startswith("refs/tags/"):
                    if not (len(ref) >= 40 and all(c in "0123456789abcdef" for c in ref.lower())):
                        findings.append({
                            "rule_id": "AZP002",
                            "severity": "high",
                            "title": f"Unpinned template repo ref in {filename}",
                            "description": (
                                f"Pipeline '{filename}' in {repo_name} references "
                                f"repository '{name}' at ref '{ref}' without pinning "
                                f"to a tag or SHA."
                            ),
                            "workflow_file": filename,
                        })

    # Check stage/job templates
    for stage in pipeline.get("stages", []) or []:
        if isinstance(stage, dict) and "template" in stage:
            _scan_value(stage["template"])
    for job in _collect_jobs(pipeline):
        if isinstance(job, dict) and "template" in job:
            _scan_value(job["template"])


def _check_environment_approvals(
    pipeline: dict,
    filename: str,
    repo_name: str,
    environments: list[dict],
    env_checks_map: dict[int, list[dict]],
    findings: list[dict],
) -> None:
    """AZP007: Check if environments used in pipeline have approval gates."""
    env_names_in_pipeline: set[str] = set()

    # Deployment jobs reference environments
    for job in _collect_jobs(pipeline):
        if not isinstance(job, dict):
            continue
        env = job.get("environment")
        if isinstance(env, str):
            env_names_in_pipeline.add(env)
        elif isinstance(env, dict):
            name = env.get("name", "")
            if name:
                env_names_in_pipeline.add(name)

    if not env_names_in_pipeline:
        return

    env_by_name = {e.get("name", ""): e for e in environments}

    for env_name in env_names_in_pipeline:
        env_info = env_by_name.get(env_name)
        if not env_info:
            continue
        env_id = env_info.get("id")
        if env_id is None:
            continue
        checks = env_checks_map.get(env_id, [])
        has_approval = any(
            c.get("type", {}).get("name") in ("Approval", "ExclusiveLock", "TaskCheck")
            for c in checks
        )
        if not has_approval:
            findings.append({
                "rule_id": "AZP007",
                "severity": "high",
                "title": f"No approval gate on environment '{env_name}' ({filename})",
                "description": (
                    f"Pipeline '{filename}' in {repo_name} deploys to environment "
                    f"'{env_name}' which has no approval checks configured. Add "
                    f"approval gates to prevent unauthorized deployments."
                ),
                "workflow_file": filename,
            })


def _check_variable_groups(
    pipeline: dict,
    filename: str,
    repo_name: str,
    variable_groups: list[dict],
    findings: list[dict],
) -> None:
    """AZP008: Check if referenced variable groups contain secrets and are broadly shared."""
    vg_refs: list[str] = []

    variables = pipeline.get("variables")
    if isinstance(variables, list):
        for var in variables:
            if isinstance(var, dict) and "group" in var:
                vg_refs.append(var["group"])

    if not vg_refs:
        return

    vg_by_name = {vg.get("name", ""): vg for vg in variable_groups}

    for vg_name in vg_refs:
        vg = vg_by_name.get(vg_name)
        if not vg:
            continue
        # Check if group has secret variables
        has_secrets = False
        for var_data in (vg.get("variables", {}) or {}).values():
            if isinstance(var_data, dict) and var_data.get("isSecret"):
                has_secrets = True
                break

        is_shared = vg.get("isShared", False)

        if has_secrets and is_shared:
            findings.append({
                "rule_id": "AZP008",
                "severity": "high",
                "title": f"Secret variable group '{vg_name}' shared broadly ({filename})",
                "description": (
                    f"Pipeline '{filename}' in {repo_name} references variable "
                    f"group '{vg_name}' which contains secret variables and is "
                    f"shared across projects. Restrict variable group access to "
                    f"specific pipelines only."
                ),
                "workflow_file": filename,
            })


def _check_service_connections(
    pipeline: dict,
    filename: str,
    repo_name: str,
    environments: list[dict],
    env_checks_map: dict[int, list[dict]],
    findings: list[dict],
) -> None:
    """AZP003: Check for service connection usage without environment approval gates."""
    steps = _collect_steps(pipeline)
    uses_service_connection = False

    for step in steps:
        if not isinstance(step, dict):
            continue
        inputs = step.get("inputs", {})
        if isinstance(inputs, dict):
            for val in inputs.values():
                if isinstance(val, str) and "serviceconnection" in val.lower():
                    uses_service_connection = True
                    break
        # Check task inputs that commonly reference service connections
        if step.get("task") and isinstance(step.get("inputs"), dict):
            for key in ("azureSubscription", "connectedServiceName",
                        "dockerRegistryServiceConnection", "kubernetesServiceConnection"):
                if step["inputs"].get(key):
                    uses_service_connection = True
                    break

    if not uses_service_connection:
        return

    # Check if any environment in the pipeline has approval gates
    jobs = _collect_jobs(pipeline)
    has_env_with_checks = False
    env_by_name = {e.get("name", ""): e for e in environments}

    for job in jobs:
        env = job.get("environment")
        env_name = env if isinstance(env, str) else (env.get("name", "") if isinstance(env, dict) else "")
        if env_name:
            env_info = env_by_name.get(env_name)
            if env_info:
                checks = env_checks_map.get(env_info.get("id", -1), [])
                if checks:
                    has_env_with_checks = True
                    break

    if not has_env_with_checks:
        findings.append({
            "rule_id": "AZP003",
            "severity": "high",
            "title": f"Service connection used without approval gates ({filename})",
            "description": (
                f"Pipeline '{filename}' in {repo_name} uses service connections "
                f"but has no environment with approval checks. Add approval gates "
                f"on environments or service connections to prevent unauthorized "
                f"access to external resources."
            ),
            "workflow_file": filename,
        })
