"""Fetch workflow action runs across org repos for a given time frame."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import yaml

from .github_client import GitHubClient

logger = logging.getLogger(__name__)

# Max runs to fetch per repo (avoids pagination explosion)
MAX_RUNS_PER_REPO = 30


def fetch_action_runs(
    client: GitHubClient,
    org: str,
    repos: list[dict],
    since: str,
    until: str | None = None,
    status_filter: str | None = None,
    on_status: Callable[[str], None] | None = None,
) -> dict:
    """Fetch workflow runs across repos within a time window.

    For each run, fetches jobs + steps from the API and also parses
    the workflow YAML to extract step.uses (actions used).
    """
    created_range = f">={since}" if not until else f"{since}..{until}"

    all_runs: list[dict] = []
    errors: list[dict] = []

    # Thread-safe cache for workflow YAML -> actions_used
    _wf_cache: dict[str, list[str]] = {}
    _wf_lock = threading.Lock()

    def _get_actions_used(owner: str, name: str, workflow_path: str, branch: str) -> list[str]:
        """Get actions used from a workflow file, with caching."""
        cache_key = f"{owner}/{name}/{workflow_path}"
        with _wf_lock:
            if cache_key in _wf_cache:
                return list(_wf_cache[cache_key])

        uses_list: list[str] = []
        try:
            content = client.get_file_content(owner, name, workflow_path, branch)
            if content:
                wf = yaml.safe_load(content)
                if isinstance(wf, dict):
                    for job_def in (wf.get("jobs") or {}).values():
                        if not isinstance(job_def, dict):
                            continue
                        for step_def in job_def.get("steps") or []:
                            if isinstance(step_def, dict) and step_def.get("uses"):
                                uses_list.append(step_def["uses"])
        except Exception:
            pass

        uses_list = sorted(set(uses_list))
        with _wf_lock:
            _wf_cache[cache_key] = uses_list
        return uses_list

    def _fetch_repo_runs(repo_meta: dict) -> list[dict]:
        owner, name = repo_meta["full_name"].split("/", 1)
        logger.info("Fetching action runs for %s...", repo_meta["full_name"])
        try:
            runs = client.list_workflow_runs(
                owner, name,
                created=created_range,
                status=status_filter,
                per_page=MAX_RUNS_PER_REPO,
            )
        except Exception as e:
            logger.warning("Failed to fetch runs for %s: %s", repo_meta["full_name"], e)
            errors.append({"repo": repo_meta["full_name"], "error": str(e)})
            return []

        runs = runs[:MAX_RUNS_PER_REPO]

        if not runs:
            return []

        logger.info("  Found %d run(s) for %s", len(runs), repo_meta["full_name"])

        results = []
        for run in runs:
            run_id = run["id"]
            workflow_path = run.get("path", "")
            default_branch = repo_meta.get("default_branch", "main")
            head_branch = run.get("head_branch", default_branch)

            # Fetch jobs + steps from the API
            job_details = []
            try:
                jobs = client.list_workflow_run_jobs(owner, name, run_id)
                for job in jobs:
                    steps = []
                    for step in job.get("steps", []):
                        steps.append({
                            "number": step.get("number", 0),
                            "name": step.get("name", ""),
                            "status": step.get("status", ""),
                            "conclusion": step.get("conclusion", ""),
                            "started_at": step.get("started_at", ""),
                            "completed_at": step.get("completed_at", ""),
                        })
                    job_details.append({
                        "name": job.get("name", ""),
                        "status": job.get("status", ""),
                        "conclusion": job.get("conclusion", ""),
                        "started_at": job.get("started_at", ""),
                        "completed_at": job.get("completed_at", ""),
                        "steps": steps,
                    })
            except Exception as e:
                logger.debug("Failed to fetch jobs for run %d: %s", run_id, e)

            # Get actions used from cached workflow YAML
            actions_used = []
            if workflow_path:
                actions_used = _get_actions_used(owner, name, workflow_path, head_branch)

            results.append({
                "repo": repo_meta["full_name"],
                "run_id": run_id,
                "workflow_name": run.get("name", ""),
                "workflow_path": workflow_path,
                "event": run.get("event", ""),
                "status": run.get("status", ""),
                "conclusion": run.get("conclusion", ""),
                "branch": head_branch,
                "actor": run.get("actor", {}).get("login", ""),
                "created_at": run.get("created_at", ""),
                "updated_at": run.get("updated_at", ""),
                "html_url": run.get("html_url", ""),
                "run_number": run.get("run_number", 0),
                "jobs": job_details,
                "actions_used": actions_used,
            })

        return results

    max_workers = min(4, len(repos)) if repos else 1
    completed = 0
    total = len(repos)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_fetch_repo_runs, repo): repo
            for repo in repos
        }
        for future in as_completed(futures):
            completed += 1
            repo = futures[future]
            try:
                repo_runs = future.result()
                all_runs.extend(repo_runs)
                if on_status:
                    on_status(f"Action runs: {completed}/{total} repos ({len(all_runs)} runs so far)")
            except Exception as e:
                logger.warning("Action runs fetch failed for %s: %s", repo["full_name"], e)

    logger.info("Action runs complete: %d runs across %d repos", len(all_runs), total)

    # Sort by created_at descending
    all_runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    # Build summary
    by_repo: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_conclusion: dict[str, int] = {}
    all_actions: dict[str, int] = {}
    for run in all_runs:
        by_repo[run["repo"]] = by_repo.get(run["repo"], 0) + 1
        by_status[run["status"]] = by_status.get(run["status"], 0) + 1
        c = run["conclusion"] or "in_progress"
        by_conclusion[c] = by_conclusion.get(c, 0) + 1
        for action in run.get("actions_used", []):
            all_actions[action] = all_actions.get(action, 0) + 1

    return {
        "runs": all_runs,
        "summary": {
            "total_runs": len(all_runs),
            "by_repo": by_repo,
            "by_status": by_status,
            "by_conclusion": by_conclusion,
            "actions_used": all_actions,
        },
        "filters_applied": {
            "since": since,
            "until": until,
            "status": status_filter,
        },
        "errors": errors,
    }
