"""Check for Trivy supply chain compromise (CVE-2026-33634 / GHSA-69fq-xp46-6x23).

Scans workflow files across repos for usage of affected Trivy actions/images
and flags vulnerable versions.

Advisory: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
"""

from __future__ import annotations

import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

from .github_client import GitHubClient

logger = logging.getLogger(__name__)

# --- Affected components and versions ---

ADVISORY_ID = "GHSA-69fq-xp46-6x23"
CVE_ID = "CVE-2026-33634"
ADVISORY_URL = "https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23"

# Actions to check (lowercased owner/name)
TRIVY_ACTIONS = {
    "aquasecurity/trivy-action": {
        "affected_below": "0.35.0",  # < 0.35.0 is affected
        "safe_version": "0.35.0",
    },
    "aquasecurity/setup-trivy": {
        "affected_below": "0.2.6",  # < 0.2.6 is affected
        "safe_version": "0.2.6",
    },
}

# Affected binary/image versions
AFFECTED_BINARY_VERSIONS = {"0.69.4", "0.69.5", "0.69.6"}
SAFE_BINARY_VERSIONS = ["0.69.2", "0.69.3", "0.69.7+"]

# Known malicious tags that were force-pushed
MALICIOUS_FORCE_PUSHED = True  # All mutable tags were compromised

# Docker images to check in workflow `uses` or `run` commands
TRIVY_DOCKER_IMAGES = [
    "aquasec/trivy",
    "ghcr.io/aquasecurity/trivy",
]


def _parse_version(v: str) -> tuple[int, ...] | None:
    """Parse a version string like 'v0.35.0' or '0.35.0' into a tuple."""
    v = v.lstrip("vV")
    m = re.match(r"^(\d+(?:\.\d+)*)", v)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _version_lt(a: str, b: str) -> bool | None:
    """Return True if version a < b. None if unparseable."""
    va = _parse_version(a)
    vb = _parse_version(b)
    if va is None or vb is None:
        return None
    return va < vb


def _check_action_ref(action_path: str, ref: str) -> dict | None:
    """Check if a specific action@ref is affected by the advisory.

    Returns a finding dict or None.
    """
    action_lower = action_path.lower()

    for action_name, info in TRIVY_ACTIONS.items():
        if action_lower != action_name:
            continue

        safe_ver = info["safe_version"]
        is_sha = bool(re.fullmatch(r"[0-9a-f]{40}", ref))

        # SHA-pinned: can't determine version from ref alone, flag as needs-review
        if is_sha:
            return {
                "action": f"{action_path}@{ref}",
                "status": "review",
                "severity": "medium",
                "message": (
                    f"Action is SHA-pinned — verify the pinned commit is not one of "
                    f"the malicious releases. Safe versions: >= {safe_ver}."
                ),
            }

        # Check mutable tag (e.g., v1, master, main)
        version_check = _version_lt(ref, safe_ver)

        if version_check is True:
            return {
                "action": f"{action_path}@{ref}",
                "status": "affected",
                "severity": "critical",
                "message": (
                    f"Version '{ref}' is AFFECTED by {CVE_ID}. "
                    f"All tags < {safe_ver} were force-pushed to malicious code. "
                    f"Upgrade immediately to >= {safe_ver} and rotate all secrets."
                ),
            }
        elif version_check is False:
            return {
                "action": f"{action_path}@{ref}",
                "status": "safe",
                "severity": "info",
                "message": f"Version '{ref}' is safe (>= {safe_ver}).",
            }
        else:
            # Unparseable version (e.g., 'master', 'main', 'v1')
            # Mutable tags were force-pushed — this is dangerous
            return {
                "action": f"{action_path}@{ref}",
                "status": "affected",
                "severity": "critical",
                "message": (
                    f"Mutable ref '{ref}' was used. During the attack window, "
                    f"76 of 77 trivy-action tags were force-pushed to malicious code. "
                    f"Pin to a safe version >= {safe_ver} or a verified SHA."
                ),
            }

    return None


def _check_docker_image_in_run(run_cmd: str) -> dict | None:
    """Check if a `run:` command references an affected trivy Docker image version."""
    for image_base in TRIVY_DOCKER_IMAGES:
        # Match patterns like aquasec/trivy:0.69.4 or aquasec/trivy:v0.69.5
        pattern = re.escape(image_base) + r":v?(\d+\.\d+\.\d+)"
        for m in re.finditer(pattern, run_cmd):
            version = m.group(1)
            if version in AFFECTED_BINARY_VERSIONS:
                return {
                    "action": f"{image_base}:{m.group(0).split(':')[-1]}",
                    "status": "affected",
                    "severity": "critical",
                    "message": (
                        f"Docker image version {version} is AFFECTED by {CVE_ID}. "
                        f"Malicious images were published to Docker Hub. "
                        f"Use a safe version (0.69.2, 0.69.3, or >= 0.69.7)."
                    ),
                }
    return None


def scan_workflows_for_trivy(
    client: GitHubClient,
    org: str,
    repos: list[tuple[dict, str]],
    on_status=None,
) -> dict:
    """Scan all repo workflows for Trivy advisory exposure.

    Args:
        client: GitHub API client
        org: Organization name
        repos: List of (repo_meta, branch) tuples
        on_status: Optional callback for progress updates

    Returns:
        Dict with findings grouped by repo, plus summary stats.
    """
    all_findings: list[dict] = []
    repos_affected: set[str] = set()
    repos_safe: set[str] = set()
    repos_using_trivy: set[str] = set()
    _wf_cache: dict[str, str | None] = {}
    _cache_lock = threading.Lock()

    def _get_workflow_content(owner: str, repo: str, path: str, branch: str) -> str | None:
        key = f"{owner}/{repo}/{path}@{branch}"
        with _cache_lock:
            if key in _wf_cache:
                return _wf_cache[key]
        content = None
        try:
            content = client.get_file_content(owner, repo, path, branch)
        except Exception:
            pass
        with _cache_lock:
            _wf_cache[key] = content
        return content

    def _scan_repo(repo_meta: dict, branch: str) -> list[dict]:
        full_name = repo_meta["full_name"]
        owner, repo = full_name.split("/", 1)
        findings = []
        seen: set[tuple[str, str]] = set()  # (workflow, action) dedup key

        try:
            wf_files = client.list_workflow_files(owner, repo, branch)
        except Exception:
            return []

        for wf_name in wf_files:
            path = f".github/workflows/{wf_name}"
            content = _get_workflow_content(owner, repo, path, branch)
            if not content:
                continue

            try:
                wf = yaml.safe_load(content)
            except yaml.YAMLError:
                continue

            if not isinstance(wf, dict):
                continue

            for job_id, job_def in (wf.get("jobs") or {}).items():
                if not isinstance(job_def, dict):
                    continue
                for i, step in enumerate(job_def.get("steps") or []):
                    if not isinstance(step, dict):
                        continue

                    # Check `uses:` field
                    uses = step.get("uses", "")
                    if uses and "@" in uses:
                        action_path, ref = uses.rsplit("@", 1)
                        dedup_key = (wf_name, f"{action_path}@{ref}")
                        if dedup_key in seen:
                            continue
                        result = _check_action_ref(action_path, ref)
                        if result:
                            seen.add(dedup_key)
                            result["repo"] = full_name
                            result["workflow"] = wf_name
                            result["job"] = job_id
                            result["step"] = step.get("name") or step.get("id") or f"step-{i}"
                            findings.append(result)

                    # Check `run:` commands for docker image references
                    run_cmd = step.get("run", "")
                    if run_cmd:
                        result = _check_docker_image_in_run(run_cmd)
                        if result:
                            dedup_key = (wf_name, result["action"])
                            if dedup_key in seen:
                                continue
                            seen.add(dedup_key)
                            result["repo"] = full_name
                            result["workflow"] = wf_name
                            result["job"] = job_id
                            result["step"] = step.get("name") or step.get("id") or f"step-{i}"
                            findings.append(result)

        return findings

    total = len(repos)
    completed = 0
    max_workers = min(4, total) if total else 1

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_scan_repo, meta, branch): meta
            for meta, branch in repos
        }
        for future in as_completed(futures):
            completed += 1
            meta = futures[future]
            try:
                findings = future.result()
                if findings:
                    all_findings.extend(findings)
                    for f in findings:
                        repos_using_trivy.add(f["repo"])
                        if f["status"] == "affected":
                            repos_affected.add(f["repo"])
                        elif f["status"] == "safe":
                            repos_safe.add(f["repo"])
                if on_status:
                    on_status(f"Trivy advisory scan: {completed}/{total} repos")
            except Exception as e:
                logger.debug("Trivy scan failed for %s: %s", meta["full_name"], e)

    # Build per-repo grouped results
    by_repo: dict[str, list[dict]] = {}
    for f in all_findings:
        by_repo.setdefault(f["repo"], []).append(f)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "advisory_id": ADVISORY_ID,
        "cve_id": CVE_ID,
        "advisory_url": ADVISORY_URL,
        "total_findings": len(all_findings),
        "repos_using_trivy": len(repos_using_trivy),
        "repos_affected": len(repos_affected),
        "repos_safe": len(repos_safe) - len(repos_affected),  # don't double-count
        "severity_counts": severity_counts,
        "findings": all_findings,
        "by_repo": by_repo,
        "affected_actions": {
            name: info for name, info in TRIVY_ACTIONS.items()
        },
        "affected_binary_versions": sorted(AFFECTED_BINARY_VERSIONS),
    }
