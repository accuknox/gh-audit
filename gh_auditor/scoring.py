"""Security risk scoring for repositories and organizations.

Scoring model:
- Each unique rule violation deducts points from a perfect score of 100.
- The first instance of a rule deducts the full severity weight.
- Additional instances of the same rule have diminishing returns:
  each extra instance adds 1 point, capped at 2x the base weight per rule.
- This means 50 unpinned-action findings (GHA003) are treated similarly to 5,
  because they reflect the same underlying practice gap.

Severity weights (base points per rule):
    critical = 10, high = 7, medium = 4, low = 2, info = 0.5

Per-rule cap: first instance = base weight, extras = +1 each, max = 2x base.
    e.g., GHA003 (high=7): 1 instance = 7, 5 instances = 11, 50 instances = 14

Org-level category cap:
    Each org-level penalty category (org settings, identity, apps & tokens)
    is individually capped at ORG_CATEGORY_PENALTY_CAP (default 15) points.
    This prevents any single category from dominating the org score and
    ensures the score remains meaningful even with many findings.

    With three categories capped at 15 each, max org-level deduction is 45,
    yielding a worst-case org score of ~55 (F) from org-level issues alone.

Grade scale:
    A+ (97-100), A (93-96), A- (90-92)
    B+ (87-89),  B (83-86), B- (80-82)
    C+ (77-79),  C (73-76), C- (70-72)
    D  (60-69),  F (<60)
"""

from __future__ import annotations

from collections import Counter

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.5,
}

# Maximum penalty from any single org-level category.
# Prevents categories with many rules (identity=11, apps&tokens=10) from
# dominating the score.  Three categories × 15 = 45 max org deduction.
ORG_CATEGORY_PENALTY_CAP = 15.0


def grade_for_score(score: float) -> str:
    """Return a letter grade for a numeric score (0-100)."""
    if score >= 97:
        return "A+"
    if score >= 93:
        return "A"
    if score >= 90:
        return "A-"
    if score >= 87:
        return "B+"
    if score >= 83:
        return "B"
    if score >= 80:
        return "B-"
    if score >= 77:
        return "C+"
    if score >= 73:
        return "C"
    if score >= 70:
        return "C-"
    if score >= 60:
        return "D"
    return "F"


def _penalty(findings: list[dict]) -> float:
    """Compute penalty with per-rule diminishing returns.

    For each unique rule_id:
      penalty = base_weight + min(extra_count, base_weight)
    where extra_count = count - 1. This caps each rule at 2x its base weight.
    """
    # Group findings by rule_id
    rule_counts: dict[str, dict] = {}
    for f in findings:
        rid = f.get("rule_id", "UNKNOWN")
        if rid not in rule_counts:
            rule_counts[rid] = {"severity": f.get("severity", "info"), "count": 0}
        rule_counts[rid]["count"] += 1

    total = 0.0
    for rid, info in rule_counts.items():
        base = SEVERITY_WEIGHTS.get(info["severity"], 0.5)
        extra = min(info["count"] - 1, base)  # cap extra at base weight
        total += base + extra

    return total


def score_repo(repo_report: dict) -> dict:
    """Compute a risk score for a single repository.

    Returns {"score": float, "grade": str, "penalty": float,
             "finding_count": int, "unique_rules": int}.
    """
    findings = repo_report.get("findings", [])
    penalty = _penalty(findings)
    score = max(0.0, 100.0 - penalty)
    unique_rules = len({f.get("rule_id") for f in findings})
    return {
        "score": round(score, 1),
        "grade": grade_for_score(score),
        "penalty": round(penalty, 1),
        "finding_count": len(findings),
        "unique_rules": unique_rules,
    }


def score_org(report: dict) -> dict:
    """Compute the organization-level risk score.

    The org score starts as the average of all repo scores, then deducts
    penalties for org-level settings findings and identity findings.

    Returns {
        "score": float, "grade": str,
        "repo_average": float, "org_penalty": float, "identity_penalty": float,
        "repo_scores": {repo_name: {score, grade, ...}},
    }
    """
    repos = report.get("repos", [])

    # Score each repo
    repo_scores: dict[str, dict] = {}
    for repo in repos:
        repo_name = repo["repo"]
        repo_scores[repo_name] = score_repo(repo)

    # Repo average (default 100 if no repos)
    if repo_scores:
        repo_avg = sum(r["score"] for r in repo_scores.values()) / len(repo_scores)
    else:
        repo_avg = 100.0

    # Org-level penalties (diminishing returns + per-category cap)
    org_findings = report.get("org_settings", {}).get("findings", [])
    org_penalty = min(_penalty(org_findings), ORG_CATEGORY_PENALTY_CAP)

    identity_findings = report.get("identity", {}).get("findings", [])
    identity_penalty = min(_penalty(identity_findings), ORG_CATEGORY_PENALTY_CAP)

    apps_tokens_findings = report.get("apps_and_tokens", {}).get("findings", [])
    apps_tokens_penalty = min(_penalty(apps_tokens_findings), ORG_CATEGORY_PENALTY_CAP)

    # Org score: repo average minus org-level deductions
    org_score = max(0.0, repo_avg - org_penalty - identity_penalty - apps_tokens_penalty)

    return {
        "score": round(org_score, 1),
        "grade": grade_for_score(org_score),
        "repo_average": round(repo_avg, 1),
        "org_penalty": round(org_penalty, 1),
        "identity_penalty": round(identity_penalty, 1),
        "apps_tokens_penalty": round(apps_tokens_penalty, 1),
        "repo_scores": repo_scores,
    }


def enrich_report(report: dict) -> None:
    """Add scoring data to an existing audit report (mutates in place).

    Adds:
    - report["audit_metadata"]["org_score"] = {score, grade, ...}
    - report["repos"][i]["score"] = {score, grade, ...} for each repo
    """
    org = score_org(report)

    # Attach per-repo scores
    for repo in report.get("repos", []):
        repo_name = repo["repo"]
        repo["score"] = org["repo_scores"].get(repo_name, score_repo(repo))

    # Attach org-level score to metadata (without duplicating repo_scores)
    report["audit_metadata"]["org_score"] = {
        "score": org["score"],
        "grade": org["grade"],
        "repo_average": org["repo_average"],
        "org_penalty": org["org_penalty"],
        "identity_penalty": org["identity_penalty"],
        "apps_tokens_penalty": org["apps_tokens_penalty"],
    }
