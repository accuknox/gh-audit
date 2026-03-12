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
    "BPR001": {
        "name": "RequiredPullRequestReviews",
        "short": "No required pull request reviews before merging.",
        "help": "Enable 'Require pull request reviews before merging' with at least 1 required approving review.",
    },
    "BPR002": {
        "name": "PushRestrictions",
        "short": "Direct pushes or force pushes not restricted on protected branch.",
        "help": "Enable push restrictions and 'Include administrators' to prevent direct or force pushes to the branch.",
    },
    "BPR003": {
        "name": "RequiredStatusChecks",
        "short": "Required status checks not configured on protected branch.",
        "help": "Configure required status checks to ensure PRs pass CI before merging.",
    },
    "BPR004": {
        "name": "DismissStaleReviews",
        "short": "Stale reviews not dismissed when new commits are pushed.",
        "help": "Enable 'Dismiss stale pull request approvals when new commits are pushed' to prevent unreviewed code from being merged.",
    },
    "BPR005": {
        "name": "AllowDeletions",
        "short": "Protected branch can be deleted.",
        "help": "Disable 'Allow deletions' on the protected branch to prevent accidental or malicious branch removal.",
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
    "BPR006": {
        "name": "RequiredSignedCommits",
        "short": "Signed commits not required on protected branch.",
        "help": "Enable 'Require signed commits' to verify commit authenticity and prevent impersonation.",
    },
    "BPR007": {
        "name": "RequireCodeOwnerReviews",
        "short": "Code owner reviews not required on protected branch.",
        "help": "Enable 'Require review from Code Owners' to ensure designated owners approve changes.",
    },
    "BPR008": {
        "name": "DismissalRestrictions",
        "short": "No dismissal restrictions on pull request reviews.",
        "help": "Configure dismissal restrictions to limit who can dismiss pull request reviews.",
    },
    "BPR009": {
        "name": "RequiredLinearHistory",
        "short": "Linear history not required on protected branch.",
        "help": "Enable 'Require linear history' to keep a clean, auditable commit history.",
    },
    "BPR010": {
        "name": "RequiredConversationResolution",
        "short": "Conversation resolution not required before merging.",
        "help": "Enable 'Require conversation resolution' to ensure all review comments are addressed.",
    },
    "SEC001": {
        "name": "SecretScanningDisabled",
        "short": "Secret scanning not enabled on repository.",
        "help": "Enable secret scanning to detect accidentally committed secrets like API keys and tokens.",
    },
    "SEC002": {
        "name": "PushProtectionDisabled",
        "short": "Secret scanning push protection not enabled.",
        "help": "Enable push protection to block pushes that contain secrets before they reach the repository.",
    },
    "SEC003": {
        "name": "DependabotSecurityUpdatesDisabled",
        "short": "Dependabot security updates not enabled.",
        "help": "Enable Dependabot security updates to automatically receive PRs fixing known vulnerabilities.",
    },
    "SEC004": {
        "name": "NoCodeowners",
        "short": "No CODEOWNERS file in repository.",
        "help": "Add a CODEOWNERS file to define code ownership and automatically request reviews.",
    },
    "SEC005": {
        "name": "NoSecurityPolicy",
        "short": "No SECURITY.md file in repository.",
        "help": "Add a SECURITY.md to tell users how to responsibly report vulnerabilities.",
    },
    "ORG001": {
        "name": "TwoFactorNotRequired",
        "short": "Organization does not require two-factor authentication.",
        "help": "Enable 2FA requirement for all org members to prevent account compromise.",
    },
    "ORG002": {
        "name": "DefaultRepoPermissionTooBroad",
        "short": "Default repository permission is too broad.",
        "help": "Set the default member permission to 'read' or 'none' and grant access through teams.",
    },
    "ORG003": {
        "name": "AllActionsAllowed",
        "short": "All GitHub Actions are allowed to run.",
        "help": "Restrict allowed actions to 'selected' or 'local_only' to reduce supply chain risk.",
    },
    "ORG004": {
        "name": "DefaultTokenWrite",
        "short": "Default GITHUB_TOKEN has write permissions.",
        "help": "Set the default GITHUB_TOKEN permission to 'read' and grant write explicitly per workflow.",
    },
    "ORG005": {
        "name": "ForkPRWorkflowsNoApproval",
        "short": "Fork PR workflows may run without approval.",
        "help": "Require approval for all fork pull request workflows to prevent malicious execution.",
    },
    # GitHub Apps & Tokens (APP001-APP005, PAT001-PAT005)
    "APP001": {
        "name": "InactiveAppInstallation",
        "short": "GitHub App installation inactive for over 90 days.",
        "help": "Review whether this app installation is still needed and uninstall if not.",
    },
    "APP002": {
        "name": "OverlyPermissiveApp",
        "short": "GitHub App has write/admin on sensitive scopes.",
        "help": "Verify the app needs elevated permissions and follow least-privilege principles.",
    },
    "APP003": {
        "name": "AppAllRepoAccess",
        "short": "GitHub App has access to all repositories.",
        "help": "Restrict the app to specific repositories rather than granting org-wide access.",
    },
    "APP004": {
        "name": "SuspendedAppInstalled",
        "short": "GitHub App is suspended but still installed.",
        "help": "Uninstall suspended apps that are no longer needed.",
    },
    "APP005": {
        "name": "AppSensitiveEvents",
        "short": "GitHub App subscribes to sensitive webhook events.",
        "help": "Ensure the app needs these events and the webhook endpoint is secure.",
    },
    "PAT001": {
        "name": "PatNoExpiration",
        "short": "Fine-grained PAT has no expiration date.",
        "help": "Set an expiration on all tokens and rotate regularly.",
    },
    "PAT002": {
        "name": "InactivePat",
        "short": "Fine-grained PAT not used in over 90 days.",
        "help": "Revoke unused tokens to reduce attack surface.",
    },
    "PAT003": {
        "name": "OverlyPermissivePat",
        "short": "Fine-grained PAT has write/admin on sensitive scopes.",
        "help": "Verify the token needs elevated permissions and follow least-privilege principles.",
    },
    "PAT004": {
        "name": "PatAllRepoAccess",
        "short": "Fine-grained PAT has access to all repositories.",
        "help": "Restrict the token to specific repositories.",
    },
    "PAT005": {
        "name": "ExpiredPatListed",
        "short": "Expired fine-grained PAT still listed in organization.",
        "help": "Remove expired tokens from the organization.",
    },
    # Azure DevOps: Pipeline Security (AZP001-AZP008)
    "AZP001": {
        "name": "PersistCredentialsCheckout",
        "short": "Checkout with persistCredentials: true leaves Git credentials for subsequent steps.",
        "help": "Set persistCredentials: false in checkout steps to limit credential exposure.",
    },
    "AZP002": {
        "name": "UnpinnedTemplateReference",
        "short": "Template reference not pinned to a tag or commit SHA.",
        "help": "Pin template references to @refs/tags/<tag> or a full commit SHA to prevent supply chain attacks.",
    },
    "AZP003": {
        "name": "ServiceConnectionNoApproval",
        "short": "Service connection used without environment approval gates.",
        "help": "Add approval checks on environments or service connections to prevent unauthorized access.",
    },
    "AZP004": {
        "name": "ScriptTargetsHost",
        "short": "Script runs with target: host, bypassing container sandbox.",
        "help": "Avoid target: host unless necessary. Use container isolation for build steps.",
    },
    "AZP005": {
        "name": "SelfHostedAgentPublicProject",
        "short": "Self-hosted agent used in a public project without demands or gates.",
        "help": "Use Microsoft-hosted agents for public projects, or add demands and approval gates.",
    },
    "AZP006": {
        "name": "ScriptInjection",
        "short": "Attacker-controlled variable interpolated into script block.",
        "help": "Use environment variable mappings instead of $() interpolation for untrusted variables.",
    },
    "AZP007": {
        "name": "EnvironmentNoApprovalGate",
        "short": "Environment has no approval checks configured.",
        "help": "Add approval gates on environments to control deployments.",
    },
    "AZP008": {
        "name": "SharedSecretVariableGroup",
        "short": "Secret variable group shared broadly across projects.",
        "help": "Restrict secret variable group access to specific pipelines only.",
    },
    # Azure DevOps: Branch Policies (ABP001-ABP007)
    "ABP001": {
        "name": "NoBranchPolicy",
        "short": "No branch policy on default branch.",
        "help": "Configure branch policies to enforce code review and build validation.",
    },
    "ABP002": {
        "name": "MinimumReviewersNotConfigured",
        "short": "Minimum reviewers not configured or set to zero.",
        "help": "Add a minimum reviewer policy with at least 1 required reviewer.",
    },
    "ABP003": {
        "name": "NoRequiredReviewers",
        "short": "No required/code-owner reviewers policy.",
        "help": "Add required reviewers to ensure designated owners approve changes.",
    },
    "ABP004": {
        "name": "SelfApprovalAllowed",
        "short": "PR creator can approve their own changes.",
        "help": "Disable creatorVoteCounts to require independent review.",
    },
    "ABP005": {
        "name": "NoBuildValidation",
        "short": "No build validation policy on default branch.",
        "help": "Add a build validation policy to ensure CI passes before merging.",
    },
    "ABP006": {
        "name": "CommentResolutionNotRequired",
        "short": "Comment resolution not required before merging.",
        "help": "Add a comment resolution policy to ensure review feedback is addressed.",
    },
    "ABP007": {
        "name": "NoMergeStrategyRestriction",
        "short": "No merge strategy restriction on default branch.",
        "help": "Restrict merge strategies to maintain a clean commit history.",
    },
    # Azure DevOps: Repository Security (ASC001-ASC004)
    "ASC001": {
        "name": "NoCredentialScanning",
        "short": "No credential/secret scanning enabled.",
        "help": "Enable Azure DevOps Advanced Security secret scanning to detect committed credentials.",
    },
    "ASC002": {
        "name": "NoDependencyScanning",
        "short": "No dependency scanning enabled.",
        "help": "Enable dependency scanning to identify known vulnerabilities in packages.",
    },
    "ASC003": {
        "name": "ForkingAllowedPublic",
        "short": "Forking allowed on public repository.",
        "help": "Restrict forking or add approval gates for fork PR pipelines.",
    },
    "ASC004": {
        "name": "NoSecurityPolicy",
        "short": "No SECURITY.md file in repository.",
        "help": "Add a SECURITY.md to tell users how to responsibly report vulnerabilities.",
    },
    # Azure DevOps: Project Settings (AOG001-AOG005)
    "AOG001": {
        "name": "GuestAccessEnabled",
        "short": "Guest access enabled in project.",
        "help": "Restrict guest access to reduce attack surface from external accounts.",
    },
    "AOG002": {
        "name": "PublicProject",
        "short": "Project has public visibility.",
        "help": "Make the project private unless public access is intentional.",
    },
    "AOG003": {
        "name": "ThirdPartyOAuthEnabled",
        "short": "Third-party OAuth app access enabled.",
        "help": "Review and restrict third-party app access to prevent data exposure.",
    },
    "AOG004": {
        "name": "SSHUnrestricted",
        "short": "SSH authentication unrestricted.",
        "help": "Consider enforcing HTTPS-only access if your org uses conditional access.",
    },
    "AOG005": {
        "name": "OverlyPermissiveProjectPermissions",
        "short": "Overly permissive project-level permissions.",
        "help": "Restrict the Contributors group to minimum necessary permissions.",
    },
    # Azure DevOps: Identity & Access (AIM001-AIM005)
    "AIM001": {
        "name": "ExcessiveProjectAdmins",
        "short": "Project has too many administrators.",
        "help": "Limit Project Administrators to a small number of trusted individuals.",
    },
    "AIM002": {
        "name": "InactiveUsers",
        "short": "Users with no sign-in activity in 90+ days.",
        "help": "Review and disable or remove stale accounts.",
    },
    "AIM003": {
        "name": "GuestInPrivilegedGroup",
        "short": "Guest user in a privileged security group.",
        "help": "Remove guest users from privileged groups or convert to full members.",
    },
    "AIM004": {
        "name": "ServiceAccountNoExpiration",
        "short": "Service connection credentials have no expiration.",
        "help": "Configure credential expiration and rotation for service connections.",
    },
    "AIM005": {
        "name": "DirectPermissionAssignment",
        "short": "Direct permission assignments instead of group-based access.",
        "help": "Use security groups for permission assignments instead of individual users.",
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
    platform = report.get("audit_metadata", {}).get("platform", "github")
    tool_name = "ado-auditor" if platform == "azure" else TOOL_NAME
    tool_info_uri = TOOL_INFO_URI

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

    # Org settings findings
    for finding in report.get("org_settings", {}).get("findings", []):
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
                            "name": report.get("audit_metadata", {}).get("organization", "org"),
                            "kind": "namespace",
                        }
                    ],
                }
            ],
            "properties": {
                "severity": finding.get("severity", "info"),
                "category": "org-settings",
            },
        }

        results.append(result)

    # Apps & tokens findings
    for finding in report.get("apps_and_tokens", {}).get("findings", []):
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
                            "name": report.get("audit_metadata", {}).get("organization", "org"),
                            "kind": "namespace",
                        }
                    ],
                }
            ],
            "properties": {
                "severity": finding.get("severity", "info"),
                "category": "apps-and-tokens",
            },
        }

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

        if rule_id.startswith("APP") or rule_id.startswith("PAT"):
            rule_desc["properties"]["tags"].append("apps-and-tokens")
        elif rule_id.startswith("IAM"):
            rule_desc["properties"]["tags"].append("identity")
        elif rule_id.startswith("BPR"):
            rule_desc["properties"]["tags"].append("branch-protection")
        elif rule_id.startswith("SEC"):
            rule_desc["properties"]["tags"].append("repo-security")
        elif rule_id.startswith("ORG"):
            rule_desc["properties"]["tags"].append("org-settings")
        elif rule_id.startswith("AZP"):
            rule_desc["properties"]["tags"].append("azure-pipelines")
        elif rule_id.startswith("ABP"):
            rule_desc["properties"]["tags"].append("branch-policies")
        elif rule_id.startswith("ASC"):
            rule_desc["properties"]["tags"].append("repo-security")
        elif rule_id.startswith("AOG"):
            rule_desc["properties"]["tags"].append("project-settings")
        elif rule_id.startswith("AIM"):
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
                        "name": tool_name,
                        "version": TOOL_VERSION,
                        "informationUri": tool_info_uri,
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
                            "riskScore": report.get("audit_metadata", {}).get("org_score", {}),
                        },
                        "workingDirectory": {
                            "uri": report.get("audit_metadata", {}).get("organization", ""),
                            "organization": report.get("audit_metadata", {}).get("organization", ""),
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
