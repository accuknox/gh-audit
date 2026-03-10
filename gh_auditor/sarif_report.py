"""Generate SARIF v2.1.0 formatted report from audit results.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard
supported by GitHub Advanced Security, Azure DevOps, and many CI systems.
"""

from __future__ import annotations

import json

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "gh-auditor"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/gh-auditor"

# Map our severity levels to SARIF levels
SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Map our severity to SARIF security-severity score (CVSS-like 0-10)
SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}

# Rule metadata for SARIF rule descriptors
_RULE_HELP = {
    "GHA000": {
        "name": "InvalidWorkflowYaml",
        "short": "Workflow YAML could not be parsed.",
        "help": "Ensure the workflow file is valid YAML.",
    },
    "GHA001": {
        "name": "PullRequestTargetTrigger",
        "short": "pull_request_target trigger runs with base branch secrets.",
        "help": (
            "The pull_request_target trigger runs in the context of the base branch "
            "and has access to secrets, even for PRs from forks. Avoid checking out "
            "PR code or using PR-controlled inputs in run: blocks."
        ),
    },
    "GHA001a": {
        "name": "PullRequestTargetCheckoutHead",
        "short": "pull_request_target checks out PR head -- critical injection vector.",
        "help": (
            "Checking out the PR head ref in a pull_request_target workflow allows "
            "an attacker to execute arbitrary code with access to base branch secrets. "
            "This is the most dangerous GitHub Actions vulnerability pattern."
        ),
    },
    "GHA002": {
        "name": "ScriptInjection",
        "short": "Untrusted input interpolated into shell command.",
        "help": (
            "Using ${{ }} to inject untrusted input (issue titles, PR bodies, etc.) "
            "into run: blocks enables command injection. Use an environment variable instead."
        ),
    },
    "GHA003": {
        "name": "UnpinnedAction",
        "short": "Action not pinned to a full commit SHA.",
        "help": (
            "Pin third-party actions to a full 40-character commit SHA instead of "
            "mutable tags or branches to prevent supply chain attacks."
        ),
    },
    "GHA004": {
        "name": "OverlyPermissivePermissions",
        "short": "Workflow permissions are missing or overly broad.",
        "help": (
            "Declare explicit least-privilege permissions at the top level of each "
            "workflow. Avoid write-all and prefer per-scope read/write declarations."
        ),
    },
    "GHA004a": {
        "name": "SensitiveWritePermission",
        "short": "Write permission on a sensitive scope.",
        "help": "Verify that write access to this scope is necessary.",
    },
    "GHA005": {
        "name": "SelfHostedRunnerPublicRepo",
        "short": "Self-hosted runner used in a public repository.",
        "help": (
            "Public repos allow any fork PR to run code on self-hosted runners. "
            "Attackers can gain persistent access. Use GitHub-hosted runners for public repos."
        ),
    },
    "GHA006": {
        "name": "WorkflowRunTrigger",
        "short": "workflow_run trigger has access to secrets from fork PRs.",
        "help": (
            "The workflow_run trigger runs on the default branch with secret access. "
            "Treat data from the triggering workflow (artifacts, inputs) as untrusted."
        ),
    },
    "GHA007": {
        "name": "SecretsInPullRequestTarget",
        "short": "Secrets used in a pull_request_target workflow.",
        "help": "Secrets are available in pull_request_target context. Ensure no PR-controlled data can exfiltrate them.",
    },
    "GHA008": {
        "name": "UnsafeArtifactDownload",
        "short": "Artifact downloaded in workflow_run context may be attacker-controlled.",
        "help": "Treat downloaded artifacts as untrusted input. Never execute or eval their contents directly.",
    },
    "GHA009": {
        "name": "PersistCredentials",
        "short": "actions/checkout persists credentials by default.",
        "help": "Set persist-credentials: false to limit token exposure to subsequent steps.",
    },
    "GHA010": {
        "name": "VulnerableAction",
        "short": "Known vulnerable or deprecated action version.",
        "help": "Upgrade to the latest version of this action.",
    },
    "GHA011": {
        "name": "UnsecureCommands",
        "short": "ACTIONS_ALLOW_UNSECURE_COMMANDS enables deprecated injection-vulnerable commands.",
        "help": "Use $GITHUB_ENV and $GITHUB_PATH files instead of the deprecated set-env and add-path commands.",
    },
    "GHA012": {
        "name": "UnfilteredPushTrigger",
        "short": "Push trigger with no branch filter runs on all branches.",
        "help": "Add a branches filter to restrict which branch pushes trigger the workflow.",
    },
    "GHA013": {
        "name": "ThirdPartyAction",
        "short": "Action from a non-well-known publisher.",
        "help": "Review this action for trustworthiness and pin to a full commit SHA.",
    },
    "IAM001": {
        "name": "TooManyOrgAdmins",
        "short": "Organization has too many admin users.",
        "help": "Limit org-level admin access to a small number of trusted individuals.",
    },
    "IAM002": {
        "name": "SingleOrgAdmin",
        "short": "Organization has only one admin (single point of failure).",
        "help": "Add at least one additional trusted admin for redundancy.",
    },
    "IAM003": {
        "name": "OutsideCollaborators",
        "short": "Outside collaborators have direct repo access.",
        "help": "Review whether external users still need access and consider using teams instead.",
    },
    "IAM004": {
        "name": "PendingInvitations",
        "short": "Stale pending org invitations.",
        "help": "Revoke pending invitations that are no longer needed.",
    },
    "IAM005": {
        "name": "TeamAdminAccess",
        "short": "Team has admin access to a repository.",
        "help": "Reduce to maintain or write permission if full admin is not required.",
    },
    "IAM006": {
        "name": "OutsideCollaboratorWriteAccess",
        "short": "Outside collaborator has write/admin access to a repository.",
        "help": "Verify that external user access is intentional, time-bounded, and still needed.",
    },
    "IAM007": {
        "name": "TooManyRepoAdmins",
        "short": "Repository has too many admin users.",
        "help": "Reduce admin access and use maintain or write roles where possible.",
    },
    "IAM008": {
        "name": "OrgOwnersEnumeration",
        "short": "Lists all organization owners for audit trail.",
        "help": "Ensure each owner account has 2FA enabled and access is reviewed regularly.",
    },
    "IAM009": {
        "name": "InactiveMember6Months",
        "short": "Member has no contributions in the last 6 months.",
        "help": "Stale accounts with org access are a security risk. Review and remove inactive members.",
    },
    "IAM010": {
        "name": "InactiveMember3Months",
        "short": "Member has no contributions in the last 3 months.",
        "help": "Verify whether these users are still actively working on projects in the organization.",
    },
    "IAM011": {
        "name": "InactiveMember1Month",
        "short": "Member has no contributions in the last month.",
        "help": "May be normal (PTO, non-coding roles) but noted for awareness during access reviews.",
    },
}


def _descriptive_rule_id(rule_id: str) -> str:
    """Build a descriptive ruleId like 'GHA001/PullRequestTargetTrigger'.

    Combines the short code with the rule name from _RULE_HELP for readability
    in SARIF viewers. Falls back to just the code if no name is registered.
    """
    meta = _RULE_HELP.get(rule_id)
    if meta and meta.get("name"):
        return f"{rule_id}/{meta['name']}"
    return rule_id


def generate_sarif_report(report: dict) -> dict:
    """Convert the audit report to SARIF v2.1.0 format."""
    results = []
    rules_seen: dict[str, dict] = {}

    # Workflow findings (per-repo)
    for repo in report.get("repos", []):
        repo_name = repo["repo"]
        branch = repo.get("branch", "main")

        for finding in repo.get("findings", []):
            rule_id = finding.get("rule_id", "UNKNOWN")
            _ensure_rule(rules_seen, rule_id, finding)

            artifact_uri = f"{repo_name}/.github/workflows/{finding.get('workflow_file', 'unknown')}"

            result = {
                "ruleId": _descriptive_rule_id(rule_id),
                "level": SEVERITY_TO_SARIF_LEVEL.get(finding.get("severity", "info"), "note"),
                "message": {
                    "text": finding.get("description", finding.get("title", "")),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": artifact_uri,
                                "uriBaseId": "ROOTDIR",
                            },
                        },
                        "logicalLocations": _build_logical_locations(
                            repo_name, branch, finding
                        ),
                    }
                ],
                "properties": {
                    "repository": repo_name,
                    "branch": branch,
                    "visibility": repo.get("visibility", "unknown"),
                    "severity": finding.get("severity", "info"),
                },
            }

            if finding.get("line_hint"):
                result["codeFlows"] = []
                result["properties"]["expressionHint"] = finding["line_hint"]

            results.append(result)

    # Identity findings
    for finding in report.get("identity", {}).get("findings", []):
        rule_id = finding.get("rule_id", "UNKNOWN")
        _ensure_rule(rules_seen, rule_id, finding)

        result = {
            "ruleId": _descriptive_rule_id(rule_id),
            "level": SEVERITY_TO_SARIF_LEVEL.get(finding.get("severity", "info"), "note"),
            "message": {
                "text": finding.get("description", finding.get("title", "")),
            },
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": finding.get("repo") or finding.get("team") or report.get("audit_metadata", {}).get("organization", "org"),
                            "kind": "namespace",
                        }
                    ],
                }
            ],
            "properties": {
                "severity": finding.get("severity", "info"),
                "category": "identity",
            },
        }

        if finding.get("users"):
            result["properties"]["users"] = finding["users"]
        if finding.get("user"):
            result["properties"]["user"] = finding["user"]
        if finding.get("repo"):
            result["properties"]["repository"] = finding["repo"]
        if finding.get("team"):
            result["properties"]["team"] = finding["team"]

        results.append(result)

    # Build rule descriptors
    rules = []
    for rule_id in sorted(rules_seen.keys()):
        meta = _RULE_HELP.get(rule_id, {})
        severity = rules_seen[rule_id].get("severity", "info")

        rule_desc = {
            "id": _descriptive_rule_id(rule_id),
            "name": meta.get("name", rule_id),
            "shortDescription": {
                "text": meta.get("short", rules_seen[rule_id].get("title", rule_id)),
            },
            "fullDescription": {
                "text": meta.get("help", rules_seen[rule_id].get("description", "")),
            },
            "defaultConfiguration": {
                "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
            },
            "properties": {
                "security-severity": SEVERITY_TO_SCORE.get(severity, "1.0"),
                "tags": ["security"],
            },
        }

        if rule_id.startswith("IAM"):
            rule_desc["properties"]["tags"].append("identity")
        else:
            rule_desc["properties"]["tags"].append("github-actions")

        rules.append(rule_desc)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": rules,
                    },
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "organization": report.get("audit_metadata", {}).get("organization", ""),
                            "timestamp": report.get("audit_metadata", {}).get("timestamp", ""),
                            "totalReposScanned": report.get("audit_metadata", {}).get("total_repos_scanned", 0),
                            "totalWorkflowsScanned": report.get("audit_metadata", {}).get("total_workflows_scanned", 0),
                        },
                    }
                ],
            }
        ],
    }

    return sarif


def write_sarif_report(report: dict, path: str) -> None:
    """Generate and write the SARIF report to a file."""
    sarif = generate_sarif_report(report)
    with open(path, "w") as f:
        json.dump(sarif, f, indent=2)


def _ensure_rule(rules_seen: dict, rule_id: str, finding: dict) -> None:
    """Track a rule the first time it's seen."""
    if rule_id not in rules_seen:
        rules_seen[rule_id] = {
            "title": finding.get("title", ""),
            "description": finding.get("description", ""),
            "severity": finding.get("severity", "info"),
        }


def _build_logical_locations(
    repo_name: str, branch: str, finding: dict
) -> list[dict]:
    """Build logical location entries for a workflow finding."""
    locations = [
        {"name": repo_name, "kind": "namespace"},
    ]
    if finding.get("workflow_file"):
        locations.append({
            "name": finding["workflow_file"],
            "kind": "module",
            "fullyQualifiedName": f"{repo_name}/{finding['workflow_file']}",
        })
    if finding.get("job"):
        locations.append({
            "name": finding["job"],
            "kind": "function",
        })
    if finding.get("step"):
        locations.append({
            "name": finding["step"],
            "kind": "member",
        })
    return locations
