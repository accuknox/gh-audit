"""Load audit configuration from a YAML config file."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from .auditor import AuditConfig, RepoSpec

CONFIG_TOKEN_ENV = "GH_AUDIT_TOKEN"


def load_config(config_path: str) -> AuditConfig:
    """Load and validate an AuditConfig from a YAML file.

    The GitHub token is always read from the GH_AUDIT_TOKEN environment
    variable, never from the config file, to avoid accidental secret leakage.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Config file must be a YAML mapping, got {type(raw).__name__}")

    # Token from environment
    token = os.environ.get(CONFIG_TOKEN_ENV, "").strip()
    if not token:
        raise ValueError(
            f"Environment variable {CONFIG_TOKEN_ENV} is not set. "
            f"Export your read-only GitHub token:\n"
            f"  export {CONFIG_TOKEN_ENV}=ghp_..."
        )

    # Org (required)
    org = raw.get("org")
    if not org or not isinstance(org, str):
        raise ValueError("Config file must specify 'org' as a non-empty string.")

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

    updated_within = raw.get("updated_within_months")
    if updated_within is not None:
        updated_within = int(updated_within)

    return AuditConfig(
        org=org,
        token=token,
        repo_specs=repo_specs,
        include_archived=bool(raw.get("include_archived", False)),
        include_forks=bool(raw.get("include_forks", False)),
        skip_identity=bool(raw.get("skip_identity", False)),
        updated_within_months=updated_within,
    ), raw.get("output", "-"), raw.get("verbosity", 0), raw.get("html_output", None), raw.get("sarif_output", None), raw.get("log_file", None)


def _parse_repo_entry(repo_str: str, default_org: str) -> RepoSpec:
    """Parse 'owner/repo' or just 'repo' into a RepoSpec."""
    if "/" in repo_str:
        owner, repo = repo_str.split("/", 1)
    else:
        owner = default_org
        repo = repo_str

    return RepoSpec(owner=owner, repo=repo, branch=None)
