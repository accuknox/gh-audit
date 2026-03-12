"""Audit GitHub App installations and fine-grained PATs for an organization.

Checks for inactive apps, overly permissive tokens, broad repo access,
and similar credential/integration hygiene issues.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from .github_client import GitHubClient

logger = logging.getLogger(__name__)

SENSITIVE_PERMISSIONS = {
    "administration",
    "contents",
    "actions",
    "members",
    "workflows",
    "organization_administration",
    "organization_secrets",
}

SENSITIVE_EVENTS = {
    "push",
    "workflow_run",
    "member",
    "organization",
    "repository",
    "deployment",
}

INACTIVITY_DAYS = 90


def audit_apps_and_tokens(
    client: GitHubClient,
    org: str,
    on_status: callable = None,
) -> dict:
    """Audit GitHub App installations and fine-grained PATs.

    Returns {"app_installations": [...], "fine_grained_pats": [...], "findings": [...]}.
    """
    findings: list[dict] = []
    app_installations: list[dict] = []
    fine_grained_pats: list[dict] = []

    # --- App installations ---
    if on_status:
        on_status("Fetching GitHub App installations...")
    try:
        app_installations = client.list_org_installations(org)
    except Exception as e:
        logger.warning("Could not fetch app installations for %s: %s", org, e)

    if app_installations:
        if on_status:
            on_status(f"Checking {len(app_installations)} app installation(s)...")
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=INACTIVITY_DAYS)

        for app in app_installations:
            app_name = app.get("app_slug") or app.get("app_id") or "unknown"
            _check_app(app, app_name, cutoff, findings)
    else:
        logger.info("No app installations found (or no permission) for %s", org)

    # --- Fine-grained PATs ---
    if on_status:
        on_status("Fetching fine-grained PATs...")
    try:
        fine_grained_pats = client.list_org_fine_grained_pats(org)
    except Exception as e:
        logger.warning("Could not fetch fine-grained PATs for %s: %s", org, e)

    if fine_grained_pats:
        if on_status:
            on_status(f"Checking {len(fine_grained_pats)} fine-grained PAT(s)...")
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=INACTIVITY_DAYS)

        for pat in fine_grained_pats:
            owner = pat.get("owner", {}).get("login", "unknown")
            pat_name = pat.get("name") or f"token-{pat.get('id', 'unknown')}"
            _check_pat(pat, owner, pat_name, cutoff, findings)
    else:
        logger.info("No fine-grained PATs found (or no permission) for %s", org)

    return {
        "app_installations": app_installations,
        "fine_grained_pats": fine_grained_pats,
        "findings": findings,
    }


def _check_app(
    app: dict,
    app_name: str,
    cutoff: datetime,
    findings: list[dict],
) -> None:
    """Run APP001-APP005 checks on a single app installation."""
    # APP001: Inactive app (not updated in >90 days)
    updated_at = _parse_dt(app.get("updated_at"))
    if updated_at and updated_at < cutoff:
        days_ago = (datetime.now(timezone.utc) - updated_at).days
        findings.append({
            "rule_id": "APP001",
            "severity": "medium",
            "title": f"App '{app_name}' inactive for {days_ago} days",
            "description": (
                f"GitHub App '{app_name}' was last updated {days_ago} days ago "
                f"(updated_at: {app.get('updated_at')}). Review whether this "
                f"installation is still needed."
            ),
            "workflow_file": "",
        })

    # APP002: Overly permissive scopes
    permissions = app.get("permissions", {})
    sensitive_writes = {
        k: v for k, v in permissions.items()
        if k in SENSITIVE_PERMISSIONS and v in ("write", "admin")
    }
    if sensitive_writes:
        scopes_str = ", ".join(f"{k}={v}" for k, v in sorted(sensitive_writes.items()))
        findings.append({
            "rule_id": "APP002",
            "severity": "high",
            "title": f"App '{app_name}' has write/admin on sensitive scopes",
            "description": (
                f"GitHub App '{app_name}' has elevated permissions on sensitive "
                f"scopes: {scopes_str}. Verify these are required and follow "
                f"least-privilege principles."
            ),
            "workflow_file": "",
        })

    # APP003: Access to all repos
    if app.get("repository_selection") == "all":
        findings.append({
            "rule_id": "APP003",
            "severity": "high",
            "title": f"App '{app_name}' has access to all repositories",
            "description": (
                f"GitHub App '{app_name}' has repository_selection='all', granting "
                f"access to every repository in the organization. Restrict to "
                f"specific repositories where possible."
            ),
            "workflow_file": "",
        })

    # APP004: Suspended but still installed
    if app.get("suspended_at") is not None:
        findings.append({
            "rule_id": "APP004",
            "severity": "low",
            "title": f"App '{app_name}' is suspended but still installed",
            "description": (
                f"GitHub App '{app_name}' is suspended (suspended_at: "
                f"{app.get('suspended_at')}) but remains installed. Consider "
                f"uninstalling if no longer needed."
            ),
            "workflow_file": "",
        })

    # APP005: Sensitive webhook events
    events = set(app.get("events", []))
    sensitive_subscribed = events & SENSITIVE_EVENTS
    if sensitive_subscribed:
        events_str = ", ".join(sorted(sensitive_subscribed))
        findings.append({
            "rule_id": "APP005",
            "severity": "medium",
            "title": f"App '{app_name}' subscribes to sensitive events",
            "description": (
                f"GitHub App '{app_name}' subscribes to sensitive webhook events: "
                f"{events_str}. Ensure the app needs these events and the webhook "
                f"endpoint is secure."
            ),
            "workflow_file": "",
        })


def _check_pat(
    pat: dict,
    owner: str,
    pat_name: str,
    cutoff: datetime,
    findings: list[dict],
) -> None:
    """Run PAT001-PAT005 checks on a single fine-grained PAT."""
    label = f"PAT '{pat_name}' (owner: {owner})"

    # PAT001: No expiration
    if pat.get("token_expires_at") is None:
        findings.append({
            "rule_id": "PAT001",
            "severity": "high",
            "title": f"{label} has no expiration",
            "description": (
                f"Fine-grained PAT '{pat_name}' owned by {owner} has no expiration "
                f"date. Non-expiring tokens are a risk if compromised. Set an "
                f"expiration and rotate regularly."
            ),
            "workflow_file": "",
        })

    # PAT002: Not used in >90 days
    last_used = _parse_dt(pat.get("token_last_used_at"))
    if last_used is None or last_used < cutoff:
        if last_used:
            days_ago = (datetime.now(timezone.utc) - last_used).days
            detail = f"last used {days_ago} days ago"
        else:
            detail = "never used"
        findings.append({
            "rule_id": "PAT002",
            "severity": "medium",
            "title": f"{label} inactive ({detail})",
            "description": (
                f"Fine-grained PAT '{pat_name}' owned by {owner} is {detail}. "
                f"Revoke unused tokens to reduce attack surface."
            ),
            "workflow_file": "",
        })

    # PAT003: Write/admin on sensitive scopes
    permissions = pat.get("permissions", {})
    # PATs may nest permissions under "repository" and "organization" keys
    all_perms = {}
    if isinstance(permissions, dict):
        for section in ("repository", "organization"):
            if isinstance(permissions.get(section), dict):
                all_perms.update(permissions[section])
        # Also handle flat permissions dict
        if not all_perms:
            all_perms = permissions

    sensitive_writes = {
        k: v for k, v in all_perms.items()
        if k in SENSITIVE_PERMISSIONS and v in ("write", "admin")
    }
    if sensitive_writes:
        scopes_str = ", ".join(f"{k}={v}" for k, v in sorted(sensitive_writes.items()))
        findings.append({
            "rule_id": "PAT003",
            "severity": "high",
            "title": f"{label} has write/admin on sensitive scopes",
            "description": (
                f"Fine-grained PAT '{pat_name}' owned by {owner} has elevated "
                f"permissions: {scopes_str}. Verify these are required."
            ),
            "workflow_file": "",
        })

    # PAT004: Access to all repos
    if pat.get("repository_selection") == "all":
        findings.append({
            "rule_id": "PAT004",
            "severity": "medium",
            "title": f"{label} has access to all repositories",
            "description": (
                f"Fine-grained PAT '{pat_name}' owned by {owner} has "
                f"repository_selection='all'. Restrict to specific repositories."
            ),
            "workflow_file": "",
        })

    # PAT005: Expired but still listed
    if pat.get("token_expired") is True:
        findings.append({
            "rule_id": "PAT005",
            "severity": "low",
            "title": f"{label} is expired but still listed",
            "description": (
                f"Fine-grained PAT '{pat_name}' owned by {owner} has expired but "
                f"is still listed in the organization. Remove expired tokens."
            ),
            "workflow_file": "",
        })


def _parse_dt(value: str | None) -> datetime | None:
    """Parse an ISO 8601 datetime string, returning None on failure."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return None
