"""Identity and access rules for GitLab (GLI001-GLI005)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# GitLab access levels
ACCESS_LEVEL_DEVELOPER = 30
ACCESS_LEVEL_OWNER = 50


def audit_identity(
    client,
    group_path: str,
    on_status: callable = None,
) -> dict:
    """Run identity/access rules GLI001-GLI005.

    Returns a report dict with 'findings' list.
    """
    findings: list[dict] = []

    if on_status:
        on_status("Fetching group members...")

    try:
        members = client.list_group_members(include_inherited=True)
    except Exception as e:
        logger.warning("Failed to list group members: %s", e)
        members = []

    logger.info("Fetched %d group members", len(members))
    if members:
        levels = {}
        for m in members:
            lvl = m.get("access_level", "unknown")
            levels[lvl] = levels.get(lvl, 0) + 1
        logger.info("Member access levels: %s", levels)

    # GLI001: Too many owners
    if on_status:
        on_status("Checking owner count...")

    owners = [
        m for m in members
        if m.get("access_level", 0) == ACCESS_LEVEL_OWNER
    ]
    owner_names = [m.get("username", m.get("name", "unknown")) for m in owners]

    if len(owners) > 5:
        findings.append({
            "rule_id": "GLI001",
            "severity": "high",
            "title": f"Excessive group owners ({len(owners)})",
            "description": (
                f"Group '{group_path}' has {len(owners)} members with Owner "
                f"access (threshold: 5). Excessive owner access increases the "
                f"blast radius of compromised accounts. Review and reduce the "
                f"owner count."
            ),
            "users": owner_names[:20],
            "workflow_file": "",
        })

    # GLI002: Inactive members (90+ days)
    if on_status:
        on_status("Checking for inactive members...")

    cutoff_90 = datetime.now(timezone.utc) - timedelta(days=90)
    inactive_members: list[str] = []

    for member in members:
        last_activity = member.get("last_activity_on", "")
        username = member.get("username", member.get("name", "unknown"))
        if not last_activity:
            continue
        try:
            last_dt = datetime.strptime(last_activity, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            if last_dt < cutoff_90:
                inactive_members.append(username)
        except (ValueError, TypeError):
            continue

    if inactive_members:
        findings.append({
            "rule_id": "GLI002",
            "severity": "high",
            "title": f"{len(inactive_members)} inactive member(s) (90+ days)",
            "description": (
                f"Found {len(inactive_members)} members in group '{group_path}' "
                f"with no activity in the last 90 days. Inactive accounts with "
                f"group access are a security risk. Review and remove stale "
                f"accounts."
            ),
            "users": inactive_members[:20],
            "workflow_file": "",
        })

    # GLI003: External users with Developer+ access
    if on_status:
        on_status("Checking external users...")

    for member in members:
        is_external = member.get("extern_uid") is not None or member.get("external", False)
        access_level = member.get("access_level", 0)
        username = member.get("username", member.get("name", "unknown"))

        if is_external and access_level >= ACCESS_LEVEL_DEVELOPER:
            findings.append({
                "rule_id": "GLI003",
                "severity": "medium",
                "title": f"External user '{username}' with elevated access",
                "description": (
                    f"External user '{username}' has access level {access_level} "
                    f"(Developer or higher) in group '{group_path}'. Review "
                    f"whether external users need this level of access."
                ),
                "workflow_file": "",
            })

    # GLI004: Pending access requests
    if on_status:
        on_status("Checking access requests...")

    try:
        access_requests = client.list_group_access_requests()
    except Exception:
        access_requests = []

    if access_requests:
        requesters = [
            r.get("username", r.get("name", "unknown"))
            for r in access_requests
        ]
        findings.append({
            "rule_id": "GLI004",
            "severity": "low",
            "title": f"{len(access_requests)} pending access request(s)",
            "description": (
                f"Group '{group_path}' has {len(access_requests)} pending "
                f"access requests. Review and approve or deny pending requests "
                f"promptly."
            ),
            "users": requesters[:20],
            "workflow_file": "",
        })

    # GLI005: Bot/service accounts
    if on_status:
        on_status("Checking bot and service accounts...")

    bot_types = {"project_bot", "service_account"}
    for member in members:
        user_type = member.get("user_type", "")
        username = member.get("username", member.get("name", "unknown"))

        if user_type in bot_types:
            findings.append({
                "rule_id": "GLI005",
                "severity": "medium",
                "title": f"Bot/service account '{username}' in group",
                "description": (
                    f"User '{username}' is a {user_type} account in group "
                    f"'{group_path}'. Bot and service accounts should be "
                    f"regularly reviewed for necessity and access scope."
                ),
                "workflow_file": "",
            })

    return {
        "findings": findings,
        "org_owners": sorted(owner_names),
        "org_member_count": len(members),
    }
