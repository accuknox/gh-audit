"""Load audit configuration from a YAML config file."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from .auditor import AuditConfig, RepoSpec

CONFIG_TOKEN_ENV = "GH_AUDIT_TOKEN"
ADO_TOKEN_ENV = "ADO_AUDIT_TOKEN"
GL_TOKEN_ENV = "GL_AUDIT_TOKEN"


def load_config(config_path: str):
    """Load and validate config from a YAML file.

    Returns either an AuditConfig (GitHub) or AdoAuditConfig (Azure)
    plus output settings.

    The token is always read from environment variables, never from the
    config file, to avoid accidental secret leakage.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Config file must be a YAML mapping, got {type(raw).__name__}")

    platform = raw.get("platform", "github")

    # Org (required)
    org = raw.get("org")
    if not org or not isinstance(org, str):
        raise ValueError("Config file must specify 'org' as a non-empty string.")

    updated_within = raw.get("updated_within_months")
    if updated_within is not None:
        updated_within = int(updated_within)

    extras = (
        raw.get("output", "-"),
        raw.get("verbosity", 0),
        raw.get("html_output", None),
        raw.get("sarif_output", None),
        raw.get("log_file", None),
    )

    if platform == "azure":
        return _load_ado_config(raw, org, updated_within), *extras

    if platform == "gitlab":
        return _load_gitlab_config(raw, org, updated_within), *extras

    return _load_github_config(raw, org, updated_within), *extras


def _load_github_config(raw: dict, org: str, updated_within) -> AuditConfig:
    """Load GitHub-specific config."""
    # Token from environment
    token = os.environ.get(CONFIG_TOKEN_ENV, "").strip()
    if not token:
        raise ValueError(
            f"Environment variable {CONFIG_TOKEN_ENV} is not set. "
            f"Export your read-only GitHub token:\n"
            f"  export {CONFIG_TOKEN_ENV}=ghp_..."
        )

    # Repo specs (supports exact names and regex patterns)
    repo_specs = []
    for entry in raw.get("repos") or []:
        if isinstance(entry, str):
            repo_specs.append(_parse_repo_entry(entry, org))
        elif isinstance(entry, dict):
            repo_str = entry.get("repo", "")
            branch = entry.get("branch")
            is_regex = bool(entry.get("regex", False))
            if not repo_str:
                continue
            spec = _parse_repo_entry(repo_str, org)
            if branch:
                spec.branch = branch
            spec.is_regex = is_regex
            repo_specs.append(spec)

    return AuditConfig(
        org=org,
        token=token,
        repo_specs=repo_specs,
        include_archived=bool(raw.get("include_archived", False)),
        include_forks=bool(raw.get("include_forks", False)),
        skip_identity=bool(raw.get("skip_identity", False)),
        skip_repo_security=bool(raw.get("skip_repo_security", False)),
        skip_org_settings=bool(raw.get("skip_org_settings", False)),
        skip_apps_and_tokens=bool(raw.get("skip_apps_and_tokens", False)),
        updated_within_months=updated_within,
    )


def _load_ado_config(raw: dict, org: str, updated_within):
    """Load Azure DevOps-specific config."""
    from .azure.ado_auditor import AdoAuditConfig

    # Token from environment
    token = os.environ.get(ADO_TOKEN_ENV, "").strip()
    if not token:
        token = os.environ.get(CONFIG_TOKEN_ENV, "").strip()
    if not token:
        raise ValueError(
            f"Environment variable {ADO_TOKEN_ENV} is not set. "
            f"Export your Azure DevOps PAT:\n"
            f"  export {ADO_TOKEN_ENV}=..."
        )

    return AdoAuditConfig(
        org=org,
        token=token,
        projects=raw.get("projects", []) or [],
        repos=raw.get("repos", []) or [],
        skip_identity=bool(raw.get("skip_identity", False)),
        skip_project_settings=bool(raw.get("skip_project_settings", False)),
        skip_pipeline_security=bool(raw.get("skip_pipeline_security", False)),
        include_disabled_repos=bool(raw.get("include_disabled_repos", False)),
        updated_within_months=updated_within,
    )


def _load_gitlab_config(raw: dict, org: str, updated_within) -> "GitLabAuditConfig":
    """Load GitLab-specific config."""
    from .gitlab.gitlab_auditor import GitLabAuditConfig

    # Token from environment
    token = os.environ.get(GL_TOKEN_ENV, "").strip()
    if not token:
        token = os.environ.get("GITLAB_TOKEN", "").strip()
    if not token:
        token = os.environ.get(CONFIG_TOKEN_ENV, "").strip()
    if not token:
        raise ValueError(
            f"Environment variable {GL_TOKEN_ENV} is not set. "
            f"Export your GitLab PAT:\n"
            f"  export {GL_TOKEN_ENV}=glpat-..."
        )

    return GitLabAuditConfig(
        org=org,
        token=token,
        base_url=raw.get("base_url", "https://gitlab.com/api/v4"),
        groups=raw.get("groups", []) or [],
        repos=raw.get("repos", []) or [],
        include_archived=bool(raw.get("include_archived", False)),
        include_forks=bool(raw.get("include_forks", False)),
        skip_identity=bool(raw.get("skip_identity", False)),
        skip_group_settings=bool(raw.get("skip_group_settings", False)),
        skip_pipeline_security=bool(raw.get("skip_pipeline_security", False)),
        updated_within_months=updated_within,
    )


def _parse_repo_entry(repo_str: str, default_org: str) -> RepoSpec:
    """Parse 'owner/repo' or just 'repo' into a RepoSpec."""
    if "/" in repo_str:
        owner, repo = repo_str.split("/", 1)
    else:
        owner = default_org
        repo = repo_str

    return RepoSpec(owner=owner, repo=repo, branch=None)
