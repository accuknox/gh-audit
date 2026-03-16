"""Group settings rules for GitLab (GLG001-GLG005)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def audit_group_settings(client, group_path: str) -> list[dict]:
    """Run group settings rules GLG001-GLG005.

    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    try:
        group = client.get_group()
    except Exception as e:
        logger.warning("Failed to get group '%s': %s", group_path, e)
        return findings

    # GLG001: Public group visibility
    visibility = group.get("visibility", "private")
    if visibility == "public":
        findings.append({
            "rule_id": "GLG001",
            "severity": "high",
            "title": f"Group '{group_path}' is public",
            "description": (
                f"Group '{group_path}' has public visibility. Anyone on the "
                f"internet can view projects, issues, and merge requests. "
                f"Consider making the group private or internal unless public "
                f"access is intentional."
            ),
            "workflow_file": "",
        })

    # GLG002: 2FA not required
    if not group.get("require_two_factor_authentication", False):
        findings.append({
            "rule_id": "GLG002",
            "severity": "high",
            "title": f"2FA not required for group '{group_path}'",
            "description": (
                f"Group '{group_path}' does not require two-factor authentication "
                f"for its members. Enable require_two_factor_authentication to "
                f"prevent account compromise."
            ),
            "workflow_file": "",
        })

    # GLG003: Project creation not restricted to maintainer+
    creation_level = group.get("project_creation_level", "developer")
    if creation_level not in ("maintainer", "noone"):
        findings.append({
            "rule_id": "GLG003",
            "severity": "medium",
            "title": f"Project creation not restricted in '{group_path}'",
            "description": (
                f"Group '{group_path}' allows project creation at level "
                f"'{creation_level}'. Restrict project_creation_level to "
                f"'maintainer' or 'noone' to control repository proliferation."
            ),
            "workflow_file": "",
        })

    # GLG004: Forking outside group not prevented
    if not group.get("prevent_forking_outside_group", False):
        findings.append({
            "rule_id": "GLG004",
            "severity": "medium",
            "title": f"Forking outside group allowed in '{group_path}'",
            "description": (
                f"Group '{group_path}' does not prevent forking projects "
                f"outside the group. Enable prevent_forking_outside_group to "
                f"keep code within organizational boundaries."
            ),
            "workflow_file": "",
        })

    # GLG005: Shared runners enabled
    shared_runners = group.get("shared_runners_setting", "enabled")
    if shared_runners == "enabled":
        findings.append({
            "rule_id": "GLG005",
            "severity": "low",
            "title": f"Shared runners enabled for group '{group_path}'",
            "description": (
                f"Group '{group_path}' has shared_runners_setting set to "
                f"'enabled'. Shared runners execute CI jobs from multiple "
                f"projects. Consider using group runners for better isolation."
            ),
            "workflow_file": "",
        })

    return findings
