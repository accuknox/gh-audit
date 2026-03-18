"""Generate CIS GitHub Benchmark report in kube-bench JSON format.

This module maps pipeaudit findings to CIS GitHub Benchmark v1.2.0
controls and outputs a JSON report compatible with Aqua Security's
kube-bench format.

Enable CIS benchmark reporting by setting ``cis_benchmark: true`` in
the audit config YAML or passing ``--cis`` on the CLI.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .version import __version__

# ---------------------------------------------------------------------------
# CIS GitHub Benchmark v1.2.0 — full catalog (120 controls)
# ---------------------------------------------------------------------------

_SECTION_NAMES = {
    "1": "Source Code",
    "1.1": "Code Changes",
    "1.2": "Repository Management",
    "1.3": "Contribution Access",
    "1.4": "Third-Party",
    "1.5": "Code Risks",
    "2": "Build Pipelines",
    "2.1": "Build Environment",
    "2.2": "Build Worker",
    "2.3": "Pipeline Instructions",
    "2.4": "Pipeline Integrity",
    "3": "Dependencies",
    "3.1": "Third-Party Packages",
    "3.2": "Validate Packages",
    "4": "Artifacts",
    "4.1": "Verification",
    "4.2": "Access to Artifacts",
    "4.3": "Package Registries",
    "4.4": "Origin Traceability",
    "5": "Deployment",
    "5.1": "Deployment Configuration",
    "5.2": "Deployment Environment",
}

# Each CIS control: (id, title, type, scored)
# type: "automated" or "manual"
# scored: True for controls that contribute to the benchmark score
_CIS_CONTROLS: list[dict] = [
    # 1.1 Code Changes
    {"id": "1.1.1", "title": "Ensure any changes to code are tracked in a version control platform", "type": "manual", "scored": True},
    {"id": "1.1.2", "title": "Ensure any change to code can be traced back to its associated task", "type": "manual", "scored": True},
    {"id": "1.1.3", "title": "Ensure any change to code receives approval of two strongly authenticated users", "type": "automated", "scored": True},
    {"id": "1.1.4", "title": "Ensure previous approvals are dismissed when updates are introduced to a code change proposal", "type": "manual", "scored": True},
    {"id": "1.1.5", "title": "Ensure there are restrictions on who can dismiss code change reviews", "type": "manual", "scored": True},
    {"id": "1.1.6", "title": "Ensure code owners are set for extra sensitive code or configuration", "type": "manual", "scored": True},
    {"id": "1.1.7", "title": "Ensure code owner's review is required when a change affects owned code", "type": "manual", "scored": True},
    {"id": "1.1.8", "title": "Ensure inactive branches are periodically reviewed and removed", "type": "manual", "scored": True},
    {"id": "1.1.9", "title": "Ensure all checks have passed before merging new code", "type": "manual", "scored": True},
    {"id": "1.1.10", "title": "Ensure open Git branches are up to date before they can be merged into code base", "type": "manual", "scored": True},
    {"id": "1.1.11", "title": "Ensure all open comments are resolved before allowing code change merging", "type": "manual", "scored": True},
    {"id": "1.1.12", "title": "Ensure verification of signed commits for new changes before merging", "type": "manual", "scored": True},
    {"id": "1.1.13", "title": "Ensure linear history is required", "type": "manual", "scored": True},
    {"id": "1.1.14", "title": "Ensure branch protection rules are enforced for administrators", "type": "manual", "scored": True},
    {"id": "1.1.15", "title": "Ensure pushing or merging of new code is restricted to specific individuals or teams", "type": "manual", "scored": True},
    {"id": "1.1.16", "title": "Ensure force push code to branches is denied", "type": "manual", "scored": True},
    {"id": "1.1.17", "title": "Ensure branch deletions are denied", "type": "manual", "scored": True},
    {"id": "1.1.18", "title": "Ensure any merging of code is automatically scanned for risks", "type": "manual", "scored": True},
    {"id": "1.1.19", "title": "Ensure any changes to branch protection rules are audited", "type": "manual", "scored": True},
    {"id": "1.1.20", "title": "Ensure branch protection is enforced on the default branch", "type": "manual", "scored": True},
    # 1.2 Repository Management
    {"id": "1.2.1", "title": "Ensure all public repositories contain a SECURITY.md file", "type": "manual", "scored": True},
    {"id": "1.2.2", "title": "Ensure repository creation is limited to specific members", "type": "manual", "scored": True},
    {"id": "1.2.3", "title": "Ensure repository deletion is limited to specific users", "type": "manual", "scored": True},
    {"id": "1.2.4", "title": "Ensure issue deletion is limited to specific users", "type": "manual", "scored": True},
    {"id": "1.2.5", "title": "Ensure all copies (forks) of code are tracked and accounted for", "type": "manual", "scored": True},
    {"id": "1.2.6", "title": "Ensure all code projects are tracked for changes in visibility status", "type": "manual", "scored": True},
    {"id": "1.2.7", "title": "Ensure inactive repositories are reviewed and archived periodically", "type": "manual", "scored": True},
    # 1.3 Contribution Access
    {"id": "1.3.1", "title": "Ensure inactive users are reviewed and removed periodically", "type": "manual", "scored": True},
    {"id": "1.3.2", "title": "Ensure team creation is limited to specific members", "type": "manual", "scored": True},
    {"id": "1.3.3", "title": "Ensure minimum number of administrators are set for the organization", "type": "manual", "scored": True},
    {"id": "1.3.4", "title": "Ensure Multi-Factor Authentication (MFA) is required for contributors of new code", "type": "manual", "scored": True},
    {"id": "1.3.5", "title": "Ensure the organization is requiring members to use Multi-Factor Authentication (MFA)", "type": "manual", "scored": True},
    {"id": "1.3.6", "title": "Ensure new members are required to be invited using company-approved email", "type": "manual", "scored": True},
    {"id": "1.3.7", "title": "Ensure two administrators are set for each repository", "type": "manual", "scored": True},
    {"id": "1.3.8", "title": "Ensure strict base permissions are set for repositories", "type": "manual", "scored": True},
    {"id": "1.3.9", "title": 'Ensure an organization\'s identity is confirmed with a "Verified" badge', "type": "manual", "scored": True},
    {"id": "1.3.10", "title": "Ensure Source Code Management (SCM) email notifications are restricted to verified domains", "type": "manual", "scored": True},
    {"id": "1.3.11", "title": "Ensure an organization provides SSH certificates", "type": "manual", "scored": True},
    {"id": "1.3.12", "title": "Ensure Git access is limited based on IP addresses", "type": "manual", "scored": True},
    {"id": "1.3.13", "title": "Ensure anomalous code behavior is tracked", "type": "manual", "scored": True},
    # 1.4 Third-Party
    {"id": "1.4.1", "title": "Ensure administrator approval is required for every installed application", "type": "manual", "scored": True},
    {"id": "1.4.2", "title": "Ensure stale applications are reviewed and inactive ones are removed", "type": "manual", "scored": True},
    {"id": "1.4.3", "title": "Ensure the access granted to each installed application is limited to the least privilege needed", "type": "manual", "scored": True},
    {"id": "1.4.4", "title": "Ensure only secured webhooks are used", "type": "manual", "scored": True},
    # 1.5 Code Risks
    {"id": "1.5.1", "title": "Ensure scanners are in place to identify and prevent sensitive data in code", "type": "manual", "scored": True},
    {"id": "1.5.2", "title": "Ensure scanners are in place to secure Continuous Integration (CI) pipeline instructions", "type": "manual", "scored": True},
    {"id": "1.5.3", "title": "Ensure scanners are in place to secure Infrastructure as Code (IaC) instructions", "type": "manual", "scored": True},
    {"id": "1.5.4", "title": "Ensure scanners are in place for code vulnerabilities", "type": "manual", "scored": True},
    {"id": "1.5.5", "title": "Ensure scanners are in place for open-source vulnerabilities in used packages", "type": "manual", "scored": True},
    {"id": "1.5.6", "title": "Ensure scanners are in place for open-source license issues in used packages", "type": "manual", "scored": True},
    # 2.1 Build Environment
    {"id": "2.1.1", "title": "Ensure each pipeline has a single responsibility", "type": "manual", "scored": True},
    {"id": "2.1.2", "title": "Ensure all aspects of the pipeline infrastructure and configuration are immutable", "type": "manual", "scored": True},
    {"id": "2.1.3", "title": "Ensure the build environment is logged", "type": "manual", "scored": True},
    {"id": "2.1.4", "title": "Ensure the creation of the build environment is automated", "type": "manual", "scored": True},
    {"id": "2.1.5", "title": "Ensure access to build environments is limited", "type": "manual", "scored": True},
    {"id": "2.1.6", "title": "Ensure users must authenticate to access the build environment", "type": "manual", "scored": True},
    {"id": "2.1.7", "title": "Ensure build secrets are limited to the minimal necessary scope", "type": "manual", "scored": True},
    {"id": "2.1.8", "title": "Ensure the build infrastructure is automatically scanned for vulnerabilities", "type": "manual", "scored": True},
    {"id": "2.1.9", "title": "Ensure default passwords are not used", "type": "manual", "scored": True},
    {"id": "2.1.10", "title": "Ensure webhooks of the build environment are secured", "type": "manual", "scored": True},
    {"id": "2.1.11", "title": "Ensure minimum number of administrators are set for the build environment", "type": "manual", "scored": True},
    # 2.2 Build Worker
    {"id": "2.2.1", "title": "Ensure build workers are single-used", "type": "manual", "scored": True},
    {"id": "2.2.2", "title": "Ensure build worker environments and commands are passed and not pulled", "type": "manual", "scored": True},
    {"id": "2.2.3", "title": "Ensure the duties of each build worker are segregated", "type": "manual", "scored": True},
    {"id": "2.2.4", "title": "Ensure build workers have minimal network connectivity", "type": "manual", "scored": True},
    {"id": "2.2.5", "title": "Ensure run-time security is enforced for build workers", "type": "manual", "scored": True},
    {"id": "2.2.6", "title": "Ensure build workers are automatically scanned for vulnerabilities", "type": "manual", "scored": True},
    {"id": "2.2.7", "title": "Ensure build workers' deployment configuration is stored in a version control platform", "type": "manual", "scored": True},
    {"id": "2.2.8", "title": "Ensure resource consumption of build workers is monitored", "type": "manual", "scored": True},
    # 2.3 Pipeline Instructions
    {"id": "2.3.1", "title": "Ensure all build steps are defined as code", "type": "manual", "scored": True},
    {"id": "2.3.2", "title": "Ensure steps have clearly defined build stage input and output", "type": "manual", "scored": True},
    {"id": "2.3.3", "title": "Ensure output is written to a separate, secured storage repository", "type": "manual", "scored": True},
    {"id": "2.3.4", "title": "Ensure changes to pipeline files are tracked and reviewed", "type": "manual", "scored": True},
    {"id": "2.3.5", "title": "Ensure access to build process triggering is minimized", "type": "manual", "scored": True},
    {"id": "2.3.6", "title": "Ensure pipelines are automatically scanned for misconfigurations", "type": "manual", "scored": True},
    {"id": "2.3.7", "title": "Ensure pipelines are automatically scanned for vulnerabilities", "type": "manual", "scored": True},
    {"id": "2.3.8", "title": "Ensure scanners are in place to identify and prevent sensitive data in pipeline files", "type": "automated", "scored": True},
    # 2.4 Pipeline Integrity
    {"id": "2.4.1", "title": "Ensure all artifacts on all releases are signed", "type": "manual", "scored": True},
    {"id": "2.4.2", "title": "Ensure all external dependencies used in the build process are locked", "type": "manual", "scored": True},
    {"id": "2.4.3", "title": "Ensure dependencies are validated before being used", "type": "manual", "scored": True},
    {"id": "2.4.4", "title": "Ensure the build pipeline creates reproducible artifacts", "type": "manual", "scored": True},
    {"id": "2.4.5", "title": "Ensure pipeline steps produce a Software Bill of Materials (SBOM)", "type": "manual", "scored": True},
    {"id": "2.4.6", "title": "Ensure pipeline steps sign the Software Bill of Materials (SBOM) produced", "type": "manual", "scored": True},
    # 3.1 Third-Party Packages
    {"id": "3.1.1", "title": "Ensure third-party artifacts and open-source libraries are verified", "type": "manual", "scored": True},
    {"id": "3.1.2", "title": "Ensure Software Bill of Materials (SBOM) is required from all third-party suppliers", "type": "manual", "scored": True},
    {"id": "3.1.3", "title": "Ensure signed metadata of the build process is required and verified", "type": "manual", "scored": True},
    {"id": "3.1.4", "title": "Ensure dependencies are monitored between open-source components", "type": "manual", "scored": True},
    {"id": "3.1.5", "title": "Ensure trusted package managers and repositories are defined and prioritized", "type": "manual", "scored": True},
    {"id": "3.1.6", "title": "Ensure a signed Software Bill of Materials (SBOM) of the code is supplied", "type": "manual", "scored": True},
    {"id": "3.1.7", "title": "Ensure dependencies are pinned to a specific, verified version", "type": "manual", "scored": True},
    {"id": "3.1.8", "title": "Ensure all packages used are more than 60 days old", "type": "manual", "scored": True},
    # 3.2 Validate Packages
    {"id": "3.2.1", "title": "Ensure an organization-wide dependency usage policy is enforced", "type": "manual", "scored": True},
    {"id": "3.2.2", "title": "Ensure packages are automatically scanned for known vulnerabilities", "type": "manual", "scored": True},
    {"id": "3.2.3", "title": "Ensure packages are automatically scanned for license implications", "type": "manual", "scored": True},
    {"id": "3.2.4", "title": "Ensure packages are automatically scanned for ownership change", "type": "manual", "scored": True},
    # 4.1 Verification
    {"id": "4.1.1", "title": "Ensure all artifacts are signed by the build pipeline itself", "type": "manual", "scored": True},
    {"id": "4.1.2", "title": "Ensure artifacts are encrypted before distribution", "type": "manual", "scored": True},
    {"id": "4.1.3", "title": "Ensure only authorized platforms have decryption capabilities of artifacts", "type": "manual", "scored": True},
    # 4.2 Access to Artifacts
    {"id": "4.2.1", "title": "Ensure the authority to certify artifacts is limited", "type": "manual", "scored": True},
    {"id": "4.2.2", "title": "Ensure number of permitted users who may upload new artifacts is minimized", "type": "manual", "scored": True},
    {"id": "4.2.3", "title": "Ensure user access to the package registry utilizes Multi-Factor Authentication (MFA)", "type": "manual", "scored": True},
    {"id": "4.2.4", "title": "Ensure user management of the package registry is not local", "type": "manual", "scored": True},
    {"id": "4.2.5", "title": "Ensure anonymous access to artifacts is revoked", "type": "manual", "scored": True},
    {"id": "4.2.6", "title": "Ensure minimum number of administrators are set for the package registry", "type": "manual", "scored": True},
    # 4.3 Package Registries
    {"id": "4.3.1", "title": "Ensure all signed artifacts are validated upon uploading the package registry", "type": "manual", "scored": True},
    {"id": "4.3.2", "title": "Ensure all versions of an existing artifact have their signatures validated", "type": "manual", "scored": True},
    {"id": "4.3.3", "title": "Ensure changes in package registry configuration are audited", "type": "manual", "scored": True},
    {"id": "4.3.4", "title": "Ensure webhooks of the repository are secured", "type": "manual", "scored": True},
    # 4.4 Origin Traceability
    {"id": "4.4.1", "title": "Ensure artifacts contain information about their origin", "type": "manual", "scored": True},
    # 5.1 Deployment Configuration
    {"id": "5.1.1", "title": "Ensure deployment configuration files are separated from source code", "type": "manual", "scored": True},
    {"id": "5.1.2", "title": "Ensure changes in deployment configuration are audited", "type": "manual", "scored": True},
    {"id": "5.1.3", "title": "Ensure scanners are in place to identify and prevent sensitive data in deployment configuration", "type": "manual", "scored": True},
    {"id": "5.1.4", "title": "Limit access to deployment configurations", "type": "manual", "scored": True},
    {"id": "5.1.5", "title": "Scan Infrastructure as Code (IaC)", "type": "manual", "scored": True},
    {"id": "5.1.6", "title": "Ensure deployment configuration manifests are verified", "type": "manual", "scored": True},
    {"id": "5.1.7", "title": "Ensure deployment configuration manifests are pinned to a specific, verified version", "type": "manual", "scored": True},
    # 5.2 Deployment Environment
    {"id": "5.2.1", "title": "Ensure deployments are automated", "type": "manual", "scored": True},
    {"id": "5.2.2", "title": "Ensure the deployment environment is reproducible", "type": "manual", "scored": True},
    {"id": "5.2.3", "title": "Ensure access to production environment is limited", "type": "manual", "scored": True},
    {"id": "5.2.4", "title": "Ensure default passwords are not used", "type": "manual", "scored": True},
]

# Build lookup by ID
_CIS_BY_ID = {c["id"]: c for c in _CIS_CONTROLS}

# ---------------------------------------------------------------------------
# Mapping: pipeaudit rule_id -> list of CIS control IDs
# ---------------------------------------------------------------------------
# Only GitHub rules are mapped here. Azure/GitLab rules would need separate
# CIS benchmarks (not yet available as CIS standards).

_RULE_TO_CIS: dict[str, list[str]] = {
    # Branch protection rules
    "BPR001": ["1.1.3", "1.1.20"],   # Required PR reviews / branch protection enforced
    "BPR002": ["1.1.15", "1.1.16"],  # Push restrictions / force push denied
    "BPR003": ["1.1.9"],             # Required status checks
    "BPR004": ["1.1.4"],             # Dismiss stale reviews
    "BPR005": ["1.1.17"],            # Allow deletions
    "BPR006": ["1.1.12"],            # Signed commits
    "BPR007": ["1.1.7"],             # Code owner reviews
    "BPR008": ["1.1.5"],             # Dismissal restrictions
    "BPR009": ["1.1.13"],            # Linear history
    "BPR010": ["1.1.11"],            # Conversation resolution
    "BPR011": ["1.1.10"],            # Branches up to date before merge
    "BPR012": ["1.1.14"],            # Branch protection enforced for admins
    # GitHub Actions
    "GHA001": ["2.3.4"],             # pull_request_target trigger
    "GHA001a": ["2.3.4"],            # pull_request_target checkout head
    "GHA002": ["2.3.8"],             # Script injection
    "GHA003": ["3.1.7", "2.4.2"],    # Unpinned action / dependencies locked
    "GHA004": ["2.1.7"],             # Overly permissive permissions / secrets scope
    "GHA004a": ["2.1.7"],            # Sensitive write permission
    "GHA005": ["2.2.1"],             # Self-hosted runner public repo
    "GHA006": ["2.3.4"],             # workflow_run trigger
    "GHA007": ["2.1.7"],             # Secrets in pull_request_target
    "GHA008": ["2.3.4"],             # Unsafe artifact download
    "GHA009": ["2.1.7"],             # Persist credentials
    "GHA011": ["2.3.8"],             # Unsecure commands
    "GHA012": ["2.3.5"],             # Unfiltered push trigger
    "GHA013": ["3.1.1"],             # Third-party action
    # Repository security
    "SEC001": ["1.5.1"],             # Secret scanning
    "SEC002": ["1.5.1"],             # Push protection
    "SEC003": ["1.5.5"],             # Dependabot security updates
    "SEC004": ["1.1.6"],             # No CODEOWNERS
    "SEC005": ["1.2.1"],             # No SECURITY.md
    "SEC006": ["1.1.8"],             # Inactive branches
    "SEC007": ["1.5.4"],             # No code vulnerability scanning
    "SEC008": ["1.2.7"],             # Inactive repo not archived
    # Org settings
    "ORG001": ["1.3.5", "1.3.4"],   # 2FA not required (also covers MFA for contributors)
    "ORG002": ["1.3.8"],             # Default repo permission too broad
    "ORG003": ["1.4.1"],             # All actions allowed
    "ORG004": ["2.1.7"],             # Default token write
    "ORG005": ["2.3.5"],             # Fork PR workflows no approval
    "ORG006": ["1.2.2"],             # Repo creation not restricted
    "ORG007": ["1.3.9"],             # Org not verified
    # Identity & access
    "IAM001": ["1.3.3"],             # Too many org admins
    "IAM002": ["1.3.3"],             # Single org admin
    "IAM003": ["1.3.1"],             # Outside collaborators
    "IAM004": ["1.3.6"],             # Pending invitations
    "IAM005": ["1.3.8"],             # Team admin access
    "IAM006": ["1.3.1"],             # Outside collaborator write access
    "IAM007": ["1.3.7"],             # Too many repo admins
    "IAM009": ["1.3.1"],             # Inactive member 6 months
    "IAM010": ["1.3.1"],             # Inactive member 3 months
    "IAM011": ["1.3.1"],             # Inactive member 1 month
    # Apps & tokens
    "APP001": ["1.4.2"],             # Inactive app
    "APP002": ["1.4.3"],             # Overly permissive app
    "APP003": ["1.4.3"],             # App all repo access
    "APP004": ["1.4.2"],             # Suspended app installed
    "APP005": ["1.4.4"],             # App sensitive events
    "PAT001": ["2.1.7"],             # PAT no expiration
    "PAT002": ["2.1.7"],             # Inactive PAT
    "PAT003": ["2.1.7"],             # Overly permissive PAT
    "PAT004": ["2.1.7"],             # PAT all repo access
}

# Controls that are inherently PASS when using GitHub with pipeaudit
# (no rule needed — the condition is always satisfied)
_INHERENTLY_PASS: dict[str, str] = {
    "1.1.1": "Code is tracked in GitHub, a version control platform",
    "1.5.2": "pipeaudit scans CI/CD pipeline instructions for misconfigurations",
    "2.3.6": "pipeaudit automatically scans pipelines for misconfigurations",
}

# Reverse map: CIS control ID -> list of pipeaudit rule_ids that test it
_CIS_TO_RULES: dict[str, list[str]] = {}
for rule_id, cis_ids in _RULE_TO_CIS.items():
    for cis_id in cis_ids:
        _CIS_TO_RULES.setdefault(cis_id, []).append(rule_id)


def generate_cis_report(report: dict) -> dict:
    """Generate a CIS benchmark report in kube-bench JSON format.

    Args:
        report: The pipeaudit audit report dict.

    Returns:
        A dict in kube-bench Controls JSON format.
    """
    # Collect all findings from the report
    all_findings: list[dict] = []
    for repo in report.get("repos", []):
        all_findings.extend(repo.get("findings", []))
    for finding in report.get("identity", {}).get("findings", []):
        all_findings.append(finding)
    for finding in report.get("org_settings", {}).get("findings", []):
        all_findings.append(finding)
    for finding in report.get("apps_and_tokens", {}).get("findings", []):
        all_findings.append(finding)

    # Build set of triggered rule IDs and their findings
    triggered_rules: dict[str, list[dict]] = {}
    for f in all_findings:
        rule_id = f.get("rule_id", "")
        triggered_rules.setdefault(rule_id, []).append(f)

    # Determine status for each CIS control
    cis_results: dict[str, dict] = {}
    for control in _CIS_CONTROLS:
        cis_id = control["id"]
        mapped_rules = _CIS_TO_RULES.get(cis_id, [])

        if cis_id in _INHERENTLY_PASS:
            # Control is inherently satisfied when using GitHub with pipeaudit
            cis_results[cis_id] = {
                "status": "PASS",
                "actual_value": _INHERENTLY_PASS[cis_id],
                "expected_result": control["title"],
                "reason": _INHERENTLY_PASS[cis_id],
                "findings": [],
            }
        elif not mapped_rules:
            # No pipeaudit rule maps to this CIS control — WARN (not assessed)
            cis_results[cis_id] = {
                "status": "WARN",
                "actual_value": "",
                "expected_result": "",
                "reason": "Not assessed by pipeaudit automated checks",
                "findings": [],
            }
        else:
            # Check if any mapped rule triggered findings
            related_findings = []
            for rule_id in mapped_rules:
                related_findings.extend(triggered_rules.get(rule_id, []))

            if related_findings:
                # Findings exist → FAIL
                descriptions = []
                for f in related_findings[:5]:
                    descriptions.append(f.get("title", f.get("description", ""))[:200])
                cis_results[cis_id] = {
                    "status": "FAIL",
                    "actual_value": "; ".join(descriptions),
                    "expected_result": control["title"],
                    "reason": f"Found {len(related_findings)} finding(s) from rules: {', '.join(mapped_rules)}",
                    "findings": related_findings,
                }
            else:
                # No findings → PASS
                cis_results[cis_id] = {
                    "status": "PASS",
                    "actual_value": "",
                    "expected_result": control["title"],
                    "reason": f"No findings from rules: {', '.join(mapped_rules)}",
                    "findings": [],
                }

    # Build kube-bench format groups
    groups = _build_groups(cis_results)

    # Compute totals
    total_pass = sum(1 for r in cis_results.values() if r["status"] == "PASS")
    total_fail = sum(1 for r in cis_results.values() if r["status"] == "FAIL")
    total_warn = sum(1 for r in cis_results.values() if r["status"] == "WARN")
    total_info = 0

    return {
        "id": "cis-github-benchmark",
        "version": "1.2.0",
        "detected_version": "1.2.0",
        "text": "CIS GitHub Benchmark",
        "node_type": "github",
        "tests": groups,
        "total_pass": total_pass,
        "total_fail": total_fail,
        "total_warn": total_warn,
        "total_info": total_info,
    }


def _build_groups(cis_results: dict[str, dict]) -> list[dict]:
    """Build kube-bench 'tests' (groups) from CIS results."""
    # Group controls by section (e.g., "1.1", "1.2", etc.)
    section_controls: dict[str, list[dict]] = {}
    for control in _CIS_CONTROLS:
        parts = control["id"].split(".")
        section = f"{parts[0]}.{parts[1]}"
        section_controls.setdefault(section, []).append(control)

    groups = []
    for section in sorted(section_controls, key=lambda s: [int(x) for x in s.split(".")]):
        controls = section_controls[section]
        section_name = _SECTION_NAMES.get(section, section)

        checks = []
        pass_count = 0
        fail_count = 0
        warn_count = 0
        info_count = 0

        for control in controls:
            cis_id = control["id"]
            result = cis_results.get(cis_id, {"status": "WARN"})
            status = result["status"]

            if status == "PASS":
                pass_count += 1
            elif status == "FAIL":
                fail_count += 1
            elif status == "WARN":
                warn_count += 1
            else:
                info_count += 1

            # Build remediation text
            mapped_rules = _CIS_TO_RULES.get(cis_id, [])
            if mapped_rules:
                remediation = f"Address findings from pipeaudit rules: {', '.join(mapped_rules)}. {control['title']}."
            else:
                remediation = f"Manual review required: {control['title']}."

            checks.append({
                "test_number": cis_id,
                "test_desc": control["title"],
                "audit": f"pipeaudit --platform github (rules: {', '.join(mapped_rules) if mapped_rules else 'none'})",
                "type": control["type"],
                "remediation": remediation,
                "test_info": [result.get("reason", "")],
                "status": status,
                "actual_value": result.get("actual_value", ""),
                "scored": control.get("scored", True),
                "expected_result": result.get("expected_result", ""),
                "reason": result.get("reason", ""),
            })

        groups.append({
            "section": section,
            "type": "",
            "pass": pass_count,
            "fail": fail_count,
            "warn": warn_count,
            "info": info_count,
            "desc": f"{section} {section_name}",
            "results": checks,
        })

    return groups


def write_cis_report(report: dict, path: str) -> None:
    """Generate and write the CIS benchmark report to a file."""
    cis = generate_cis_report(report)
    with open(path, "w") as f:
        json.dump(cis, f, indent=2)
