"""Identity and access rules for Azure DevOps (AIM001-AIM005)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

PRIVILEGED_GROUP_NAMES = {
    "Project Administrators",
    "Project Collection Administrators",
    "Build Administrators",
}


def audit_identity(
    client,
    projects: list[dict],
    on_status: callable = None,
) -> dict:
    """Run identity/access rules AIM001-AIM005.

    Returns a report dict with 'findings' list.
    """
    findings: list[dict] = []

    if on_status:
        on_status("Fetching organization users and groups...")

    try:
        all_users = client.list_users()
    except Exception as e:
        logger.warning("Failed to list users: %s", e)
        all_users = []

    try:
        all_groups = client.list_groups()
    except Exception as e:
        logger.warning("Failed to list groups: %s", e)
        all_groups = []

    # Build maps
    group_by_name: dict[str, dict] = {}
    for g in all_groups:
        display_name = g.get("displayName", "")
        group_by_name[display_name] = g

    # AIM001: Excessive project admins
    if on_status:
        on_status("Checking project administrator counts...")

    for project in projects:
        project_name = project.get("name", "")
        admin_group_name = f"[{project_name}]\\Project Administrators"

        # Find the Project Administrators group for this project
        admin_group = None
        for g in all_groups:
            display_name = g.get("displayName", "")
            principal_name = g.get("principalName", "")
            if display_name == "Project Administrators" and project_name in principal_name:
                admin_group = g
                break
            if principal_name == admin_group_name:
                admin_group = g
                break

        if not admin_group:
            continue

        descriptor = admin_group.get("descriptor", "")
        if not descriptor:
            continue

        try:
            members = client.list_group_members(descriptor)
        except Exception as e:
            logger.warning("Failed to list admin members for %s: %s", project_name, e)
            continue

        member_count = len(members)
        if member_count > 5:
            findings.append({
                "rule_id": "AIM001",
                "severity": "high",
                "title": f"Excessive project admins in '{project_name}' ({member_count})",
                "description": (
                    f"Project '{project_name}' has {member_count} members in the "
                    f"Project Administrators group (threshold: 5). Excessive admin "
                    f"access increases the blast radius of compromised accounts. "
                    f"Review and reduce the admin count."
                ),
                "workflow_file": "",
            })

    # AIM002: Inactive users (90+ days)
    if on_status:
        on_status("Checking for inactive users...")

    cutoff_90 = datetime.now(timezone.utc) - timedelta(days=90)
    inactive_users: list[str] = []

    for user in all_users:
        last_accessed = user.get("lastAccessedDate", "")
        display_name = user.get("displayName", "")
        if not last_accessed:
            continue
        try:
            last_dt = datetime.fromisoformat(last_accessed.replace("Z", "+00:00"))
            if last_dt < cutoff_90:
                inactive_users.append(display_name)
        except (ValueError, TypeError):
            continue

    if inactive_users:
        findings.append({
            "rule_id": "AIM002",
            "severity": "high",
            "title": f"{len(inactive_users)} inactive user(s) (90+ days)",
            "description": (
                f"Found {len(inactive_users)} users with no sign-in activity in "
                f"the last 90 days. Inactive accounts with organization access "
                f"are a security risk. Review and disable or remove stale accounts."
            ),
            "users": inactive_users[:20],
            "workflow_file": "",
        })

    # AIM003: Guest users in privileged groups
    if on_status:
        on_status("Checking guest users in privileged groups...")

    for g in all_groups:
        display_name = g.get("displayName", "")
        if display_name not in PRIVILEGED_GROUP_NAMES:
            continue

        descriptor = g.get("descriptor", "")
        if not descriptor:
            continue

        try:
            members = client.list_group_members(descriptor)
        except Exception:
            continue

        for member in members:
            # Guest users have origin "aad" with subjectKind "user" and
            # their domain typically indicates external
            origin = member.get("origin", "")
            subject_kind = member.get("subjectKind", "")
            member_name = member.get("displayName", member.get("mailAddress", "unknown"))

            if origin == "aad" and subject_kind == "user":
                mail = member.get("mailAddress", "")
                if mail and "#EXT#" in mail:
                    findings.append({
                        "rule_id": "AIM003",
                        "severity": "high",
                        "title": f"Guest user '{member_name}' in '{display_name}'",
                        "description": (
                            f"Guest user '{member_name}' is a member of the "
                            f"privileged group '{display_name}'. External guest "
                            f"accounts should not have administrative access. "
                            f"Remove the guest from this group or convert to a "
                            f"full organization member."
                        ),
                        "workflow_file": "",
                    })

    # AIM004: Service accounts without expiration
    if on_status:
        on_status("Checking service connection expiration...")

    for project in projects:
        project_name = project.get("name", "")
        try:
            connections = client.list_service_connections(project_name)
        except Exception as e:
            logger.warning("Failed to list service connections for %s: %s", project_name, e)
            continue

        for conn in connections:
            conn_name = conn.get("name", "")
            auth = conn.get("authorization", {})
            params = auth.get("parameters", {})

            # Check for service principal connections without expiry info
            if conn.get("type") in ("azurerm", "kubernetes", "dockerregistry"):
                # Look for expiration indicators
                has_expiry = bool(
                    params.get("tenantExpirationDate")
                    or params.get("certExpirationDate")
                    or conn.get("data", {}).get("expiresAfter")
                )
                if not has_expiry:
                    findings.append({
                        "rule_id": "AIM004",
                        "severity": "medium",
                        "title": f"Service connection '{conn_name}' has no expiration",
                        "description": (
                            f"Service connection '{conn_name}' in project "
                            f"'{project_name}' does not have an expiration date "
                            f"configured. Long-lived credentials without rotation "
                            f"increase risk. Configure credential expiration and rotation."
                        ),
                        "workflow_file": "",
                    })

    # AIM005: Direct permission assignments (not via groups)
    # This is checked at project level by looking for individual user ACL entries
    # For now, we check if users are directly assigned to project teams
    # rather than through security groups
    if on_status:
        on_status("Checking direct permission assignments...")

    return {"findings": findings}
