"""Project/organization settings rules for Azure DevOps (AOG001-AOG005)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def audit_project_settings(
    client,
    project: str,
    project_meta: dict,
) -> list[dict]:
    """Run organization/project settings rules AOG001-AOG005.

    Returns a list of finding dicts.
    """
    findings: list[dict] = []

    # AOG001: Guest access enabled
    # Check project properties for guest access policy
    project_id = project_meta.get("id", "")
    properties = []
    try:
        properties = client.get_project_properties(project_id)
    except Exception as e:
        logger.warning("Failed to get project properties for %s: %s", project, e)

    prop_map = {p.get("name", ""): p.get("value", "") for p in properties}

    # Guest access is indicated by AAD guest policy
    if prop_map.get("System.GuestAccessEnabled", "").lower() == "true":
        findings.append({
            "rule_id": "AOG001",
            "severity": "high",
            "title": f"Guest access enabled in project '{project}'",
            "description": (
                f"Project '{project}' has guest access enabled, allowing "
                f"external (non-organization) users to be invited. Restrict "
                f"guest access to reduce the attack surface from external accounts."
            ),
            "workflow_file": "",
        })

    # AOG002: Public projects allowed
    visibility = project_meta.get("visibility", "private")
    if visibility == "public":
        findings.append({
            "rule_id": "AOG002",
            "severity": "high",
            "title": f"Project '{project}' is public",
            "description": (
                f"Project '{project}' has public visibility. Anyone on the "
                f"internet can view code, pipelines, and work items. Consider "
                f"making the project private unless public access is intentional."
            ),
            "workflow_file": "",
        })

    # AOG003: Third-party OAuth app access
    if prop_map.get("System.ThirdPartyOAuthEnabled", "").lower() == "true":
        findings.append({
            "rule_id": "AOG003",
            "severity": "medium",
            "title": f"Third-party OAuth access enabled in project '{project}'",
            "description": (
                f"Project '{project}' allows third-party OAuth applications to "
                f"access project data. Review and restrict third-party app access "
                f"to prevent data exposure through external integrations."
            ),
            "workflow_file": "",
        })

    # AOG004: SSH authentication unrestricted
    if prop_map.get("System.SSHAuthenticationDisabled", "").lower() != "true":
        findings.append({
            "rule_id": "AOG004",
            "severity": "low",
            "title": f"SSH authentication unrestricted in project '{project}'",
            "description": (
                f"Project '{project}' does not restrict SSH authentication. "
                f"While SSH is generally secure, unrestricted SSH access may "
                f"bypass conditional access policies. Consider enforcing "
                f"HTTPS-only access if your organization uses conditional access."
            ),
            "workflow_file": "",
        })

    # AOG005: Overly permissive project-level permissions
    try:
        teams = client.list_project_teams(project)
    except Exception as e:
        logger.warning("Failed to list teams for %s: %s", project, e)
        teams = []

    for team in teams:
        team_name = team.get("name", "")
        # Check if the Contributors team or similar broad groups have admin-like access
        if "contributors" in team_name.lower():
            # In ADO, Contributors having broad permissions is a default concern
            identity = team.get("identity", {})
            if identity.get("isTeamAdmin", False):
                findings.append({
                    "rule_id": "AOG005",
                    "severity": "medium",
                    "title": f"Contributors group has elevated permissions in '{project}'",
                    "description": (
                        f"The Contributors group in project '{project}' has elevated "
                        f"permissions. Review and restrict the Contributors group to "
                        f"minimum necessary permissions. Use more specific groups for "
                        f"administrative tasks."
                    ),
                    "workflow_file": "",
                })
                break

    return findings
