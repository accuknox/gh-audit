"""Generate a self-contained HTML report from the audit results."""

from __future__ import annotations

import html
import json
from datetime import datetime

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_COLORS = {
    "critical": {"bg": "#dc2626", "fg": "#fff", "badge": "#fecaca", "text": "#991b1b"},
    "high": {"bg": "#ea580c", "fg": "#fff", "badge": "#fed7aa", "text": "#9a3412"},
    "medium": {"bg": "#ca8a04", "fg": "#fff", "badge": "#fef08a", "text": "#854d0e"},
    "low": {"bg": "#2563eb", "fg": "#fff", "badge": "#bfdbfe", "text": "#1e40af"},
    "info": {"bg": "#6b7280", "fg": "#fff", "badge": "#e5e7eb", "text": "#374151"},
}


def generate_html_report(report: dict) -> str:
    """Generate a complete self-contained HTML report string."""
    meta = report["audit_metadata"]
    repos = report["repos"]

    severity_counts = meta["findings_by_severity"]
    total_findings = meta["total_findings"]

    # Compute repo-only severity counts for the Repository Details section
    repo_severity_counts: dict[str, int] = {}
    for repo in repos:
        for f in repo.get("findings", []):
            sev = f.get("severity", "info")
            repo_severity_counts[sev] = repo_severity_counts.get(sev, 0) + 1

    # Sort repos: most findings first, then alphabetically
    sorted_repos = sorted(repos, key=lambda r: (-len(r["findings"]), r["repo"]))

    # Build per-rule summary (includes repo, identity, and org_settings findings)
    rule_summary = _build_rule_summary(report)

    # Build nav items dynamically based on what sections exist
    nav_items = _build_nav_items(report)

    platform = meta.get("platform", "github")
    platform_labels = {"azure": "Azure DevOps", "gitlab": "GitLab", "github": "GitHub"}
    platform_label = platform_labels.get(platform, "GitHub")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{platform_label} Audit &mdash; {_esc(meta['organization'])}</title>
<style>
{_CSS}
</style>
</head>
<body>

<header>
  <div class="container">
    <h1>{platform_label} Audit Report</h1>
    <p class="subtitle">
      Organization: <strong>{_esc(meta['organization'])}</strong>
      &middot; Generated: <strong>{_format_ts(meta['timestamp'])}</strong>
    </p>
  </div>
</header>

<!-- Sticky Section Nav -->
<nav class="section-nav" id="section-nav">
  <div class="container nav-inner">
    {nav_items}
    <span class="nav-sep"></span>
    <button class="nav-btn" onclick="expandAllSections()" title="Expand all sections">Expand All</button>
    <button class="nav-btn" onclick="collapseAllSections()" title="Collapse all sections">Collapse All</button>
  </div>
</nav>

<main class="container">

<!-- Summary Cards -->
<section class="summary-grid" id="sec-summary">
  {_render_org_score_card(meta.get("org_score"))}
  <div class="card stat-card">
    <div class="stat-number">{meta['total_repos_scanned']}</div>
    <div class="stat-label">Repos Scanned</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number">{meta['total_workflows_scanned']}</div>
    <div class="stat-label">Workflows Scanned</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number">{total_findings}</div>
    <div class="stat-label">Total Findings</div>
  </div>
</section>

<!-- Severity Breakdown -->
<section class="card collapsible" id="sec-severity">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Findings by Severity
  </h2>
  <div class="section-body">
    <div class="severity-bar-container">
      {_render_severity_bar(severity_counts, total_findings)}
    </div>
    <div class="severity-legend">
      {_render_severity_legend(severity_counts)}
    </div>
  </div>
</section>

<!-- Rule Summary -->
<section class="card collapsible" id="sec-rules">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Findings by Rule
  </h2>
  <div class="section-body">
    <input type="text" class="filter-input" placeholder="Filter rules..."
           onkeyup="filterTable(this, 'rule-summary-table')">
    <table class="data-table sortable" id="rule-summary-table">
      <thead>
        <tr>
          <th class="sortable-th" onclick="sortTable('rule-summary-table', 0, 'text')">Rule ID <span class="sort-icon"></span></th>
          <th class="sortable-th" onclick="sortTable('rule-summary-table', 1, 'text')">Title <span class="sort-icon"></span></th>
          <th class="sortable-th" onclick="sortTable('rule-summary-table', 2, 'severity')">Severity <span class="sort-icon"></span></th>
          <th class="num sortable-th" onclick="sortTable('rule-summary-table', 3, 'num')">Count <span class="sort-icon"></span></th>
          <th class="num sortable-th" onclick="sortTable('rule-summary-table', 4, 'num')">Repos Affected <span class="sort-icon"></span></th>
        </tr>
      </thead>
      <tbody>
        {_render_rule_summary_rows(rule_summary)}
      </tbody>
    </table>
  </div>
</section>

{_render_identity_section(report.get("identity"))}

{_render_org_settings_section(report.get("org_settings"))}

{_render_apps_and_tokens_section(report.get("apps_and_tokens"))}

{_render_cis_section(report.get("cis_benchmark"))}

{_render_action_runs_section(report.get("action_runs"))}

{_render_trivy_advisory_section(report.get("trivy_advisory"))}

<!-- Per-Repo Details -->
<section class="card collapsible" id="sec-repos">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Repository Details
  </h2>
  <div class="section-body">
    <div class="toolbar">
      <input type="text" id="repo-filter" class="filter-input"
             placeholder="Filter repositories..." onkeyup="filterRepos()">
      <div class="filter-buttons">
        <button class="filter-btn active" onclick="filterSeverity('all', this)">All</button>
        {"".join(f'<button class="filter-btn sev-btn-{s}" onclick="filterSeverity({chr(39)}{s}{chr(39)}, this)">{s.upper()} ({repo_severity_counts.get(s, 0)})</button>' for s in SEVERITY_ORDER if repo_severity_counts.get(s, 0) > 0)}
        <span class="toolbar-sep"></span>
        <button class="nav-btn" onclick="expandAllInContainer('repo-list')">Expand All</button>
        <button class="nav-btn" onclick="collapseAllInContainer('repo-list')">Collapse All</button>
      </div>
    </div>

    <div id="repo-list">
      {_render_repo_sections(sorted_repos)}
    </div>
  </div>
</section>

</main>

<footer>
  <div class="container">
    {platform_label} Audit &middot; {_format_ts(meta['timestamp'])}
  </div>
</footer>

<script>
{_JS}
</script>

</body>
</html>"""


def write_html_report(report: dict, path: str) -> None:
    """Generate and write the HTML report to a file."""
    html_content = generate_html_report(report)
    with open(path, "w") as f:
        f.write(html_content)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _grade_color(grade: str) -> str:
    """Return a CSS color for a letter grade."""
    if grade.startswith("A"):
        return "#16a34a"
    if grade.startswith("B"):
        return "#2563eb"
    if grade.startswith("C"):
        return "#ca8a04"
    if grade.startswith("D"):
        return "#ea580c"
    return "#dc2626"


def _render_org_score_card(org_score: dict | None) -> str:
    """Render the org-level score as a summary card."""
    if not org_score:
        return ""
    score = org_score["score"]
    grade = org_score["grade"]
    color = _grade_color(grade)
    return (
        f'<div class="card stat-card">'
        f'<div class="stat-number" style="color:{color}">{grade}</div>'
        f'<div class="stat-label">Org Score: {score}/100</div>'
        f'</div>'
    )


def _render_repo_score_badge(score_data: dict | None) -> str:
    """Render an inline score badge for a repo header."""
    if not score_data:
        return ""
    grade = score_data["grade"]
    score = score_data["score"]
    color = _grade_color(grade)
    return (
        f'<span class="score-badge" style="background:{color};color:#fff;'
        f'padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;'
        f'margin-left:8px" title="Risk score: {score}/100">{grade} ({score})</span>'
    )


def _esc(text: str) -> str:
    return html.escape(str(text))


def _format_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts


def _build_nav_items(report: dict) -> str:
    """Build navigation links based on which sections the report has."""
    items = [
        ("sec-severity", "Severity"),
        ("sec-rules", "Rules"),
    ]
    identity = report.get("identity")
    if identity and "error" not in identity:
        items.append(("sec-iam-findings", "IAM Findings"))
        items.append(("sec-owners", "Owners"))
        items.append(("sec-inactive", "Inactive"))
        if identity.get("outside_collaborators"):
            items.append(("sec-outside", "Outside Collabs"))
        if identity.get("teams"):
            items.append(("sec-teams", "Teams"))
        if identity.get("repo_access"):
            items.append(("sec-access", "Repo Access"))
    org_settings = report.get("org_settings")
    if org_settings and "error" not in org_settings:
        items.append(("sec-org-settings", "Org Settings"))
    apps_tokens = report.get("apps_and_tokens")
    if apps_tokens and "error" not in apps_tokens:
        items.append(("sec-apps-tokens", "Apps & Tokens"))
    cis_data = report.get("cis_benchmark")
    if cis_data:
        items.append(("sec-cis", "CIS Benchmark"))
    action_runs = report.get("action_runs")
    if action_runs and "error" not in action_runs and action_runs.get("runs"):
        items.append(("sec-action-runs", "Action Runs"))
    trivy = report.get("trivy_advisory")
    if trivy and "error" not in trivy and trivy.get("total_findings", 0) > 0:
        items.append(("sec-trivy-advisory", "Trivy Advisory"))
    items.append(("sec-repos", "Repositories"))
    return "".join(
        f'<a class="nav-link" href="#{sid}">{label}</a>'
        for sid, label in items
    )


def _render_severity_bar(counts: dict, total: int) -> str:
    if total == 0:
        return '<div class="severity-bar"><div class="sev-segment" style="width:100%;background:#e5e7eb">No findings</div></div>'
    parts = []
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        pct = (count / total) * 100
        color = SEVERITY_COLORS[sev]["bg"]
        parts.append(
            f'<div class="sev-segment" style="width:{pct:.1f}%;background:{color}" '
            f'title="{sev.upper()}: {count}">{count}</div>'
        )
    return f'<div class="severity-bar">{"".join(parts)}</div>'


def _render_severity_legend(counts: dict) -> str:
    items = []
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]["bg"]
        items.append(
            f'<span class="legend-item">'
            f'<span class="legend-dot" style="background:{color}"></span>'
            f'{sev.upper()}: {count}</span>'
        )
    return " ".join(items)


def _severity_badge(sev: str) -> str:
    colors = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    return f'<span class="badge" style="background:{colors["badge"]};color:{colors["text"]}">{_esc(sev.upper())}</span>'


def _build_rule_summary(report: dict) -> list[dict]:
    rules: dict[str, dict] = {}

    # Repo-level findings (workflow + branch protection + repo security)
    for repo in report.get("repos", []):
        for f in repo["findings"]:
            rid = f["rule_id"]
            if rid not in rules:
                rules[rid] = {
                    "rule_id": rid,
                    "title": f.get("title", ""),
                    "severity": f.get("severity", "info"),
                    "count": 0,
                    "repos": set(),
                }
            rules[rid]["count"] += 1
            rules[rid]["repos"].add(repo["repo"])

    # Identity findings
    for f in report.get("identity", {}).get("findings", []):
        rid = f["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "rule_id": rid,
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "count": 0,
                "repos": set(),
            }
        rules[rid]["count"] += 1
        if f.get("repo"):
            rules[rid]["repos"].add(f["repo"])

    # Org settings findings
    org = report.get("audit_metadata", {}).get("organization", "org")
    for f in report.get("org_settings", {}).get("findings", []):
        rid = f["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "rule_id": rid,
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
                "count": 0,
                "repos": set(),
            }
        rules[rid]["count"] += 1
        rules[rid]["repos"].add(org)

    result = sorted(
        rules.values(),
        key=lambda r: (SEVERITY_ORDER.index(r["severity"]) if r["severity"] in SEVERITY_ORDER else 99, -r["count"]),
    )
    return result


def _render_rule_summary_rows(rule_summary: list[dict]) -> str:
    if not rule_summary:
        return '<tr><td colspan="5" class="empty">No findings</td></tr>'
    rows = []
    for r in rule_summary:
        rows.append(
            f'<tr data-severity="{_esc(r["severity"])}">'
            f'<td><code>{_esc(r["rule_id"])}</code></td>'
            f'<td>{_esc(r["title"])}</td>'
            f'<td>{_severity_badge(r["severity"])}</td>'
            f'<td class="num">{r["count"]}</td>'
            f'<td class="num">{len(r["repos"])}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def _render_repo_sections(repos: list[dict]) -> str:
    sections = []
    for repo in repos:
        findings = repo["findings"]
        finding_severities = " ".join(
            set(f.get("severity", "info") for f in findings)
        ) if findings else ""

        # Determine highest severity for the repo badge
        highest = "info"
        for sev in SEVERITY_ORDER:
            if any(f.get("severity") == sev for f in findings):
                highest = sev
                break

        count_str = f"{len(findings)} finding{'s' if len(findings) != 1 else ''}"
        visibility_badge = (
            '<span class="badge" style="background:#fee2e2;color:#991b1b">PUBLIC</span>'
            if repo.get("visibility") == "public"
            else '<span class="badge" style="background:#e0e7ff;color:#3730a3">PRIVATE</span>'
        )

        findings_html = _render_findings_table(findings) if findings else '<p class="empty">No findings - all clear.</p>'

        sections.append(f"""
    <div class="repo-section" data-repo="{_esc(repo['repo'].lower())}" data-severities="{finding_severities}">
      <div class="repo-header" onclick="toggleRepo(this)">
        <span class="repo-toggle">&#9654;</span>
        <span class="repo-name">{_esc(repo['repo'])}</span>
        <span class="repo-branch">@ {_esc(repo['branch'])}</span>
        {visibility_badge}
        {_severity_badge(highest) if findings else '<span class="badge" style="background:#d1fae5;color:#065f46">CLEAN</span>'}
        {_render_repo_score_badge(repo.get("score"))}
        <span class="repo-count">{count_str} &middot; {repo['workflows_scanned']} workflow(s)</span>
      </div>
      <div class="repo-body">
        {findings_html}
      </div>
    </div>""")

    return "\n".join(sections)


def _render_findings_table(findings: list[dict]) -> str:
    # Group by workflow file
    by_workflow: dict[str, list[dict]] = {}
    for f in findings:
        wf = f.get("workflow_file", "unknown")
        by_workflow.setdefault(wf, []).append(f)

    parts = []
    for wf, wf_findings in by_workflow.items():
        rows = []
        for f in sorted(wf_findings, key=lambda x: SEVERITY_ORDER.index(x.get("severity", "info")) if x.get("severity", "info") in SEVERITY_ORDER else 99):
            job = f.get("job", "")
            step = f.get("step", "")
            location = ""
            if job:
                location = f"job: {_esc(job)}"
                if step:
                    location += f" / step: {_esc(step)}"

            line_hint = ""
            if f.get("line_hint"):
                line_hint = f'<div class="line-hint"><code>{_esc(f["line_hint"])}</code></div>'

            rows.append(
                f'<tr class="finding-row" data-severity="{_esc(f.get("severity", "info"))}">'
                f'<td><code>{_esc(f.get("rule_id", ""))}</code></td>'
                f'<td>{_severity_badge(f.get("severity", "info"))}</td>'
                f'<td>'
                f'<div class="finding-title">{_esc(f.get("title", ""))}</div>'
                f'<div class="finding-desc">{_esc(f.get("description", ""))}</div>'
                f'{f"<div class=finding-location>{location}</div>" if location else ""}'
                f'{line_hint}'
                f'</td>'
                f'</tr>'
            )

        parts.append(
            f'<div class="workflow-group">'
            f'<h4 class="workflow-name">{_esc(wf)}</h4>'
            f'<table class="data-table findings-table">'
            f'<thead><tr><th style="width:80px">Rule</th><th style="width:90px">Severity</th><th>Details</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody>'
            f'</table></div>'
        )

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Identity section rendering
# ---------------------------------------------------------------------------

def _render_org_settings_section(org_settings: dict | None) -> str:
    """Render the organization settings audit section."""
    if not org_settings or "error" in org_settings:
        return ""

    findings = org_settings.get("findings", [])
    settings = org_settings.get("settings", {})

    parts = []

    # --- Settings summary cards ---
    two_fa = settings.get("two_factor_requirement_enabled")
    default_perm = settings.get("default_repository_permission", "unknown")
    actions_perms = settings.get("actions_permissions", {})
    allowed_actions = actions_perms.get("allowed_actions", "unknown")
    default_wf_perm = actions_perms.get("default_workflow_permissions", "unknown")

    two_fa_color = "#16a34a" if two_fa else "#dc2626"
    two_fa_text = "Enabled" if two_fa else "Not Required"
    perm_color = "#16a34a" if default_perm in ("read", "none") else "#dc2626"
    actions_color = "#16a34a" if allowed_actions != "all" else "#dc2626"
    wf_perm_color = "#16a34a" if default_wf_perm != "write" else "#dc2626"

    parts.append(f"""
<section class="summary-grid">
  <div class="card stat-card">
    <div class="stat-number" style="color:{two_fa_color};font-size:1.1rem">{_esc(two_fa_text)}</div>
    <div class="stat-label">2FA Requirement</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number" style="color:{perm_color};font-size:1.1rem">{_esc(default_perm)}</div>
    <div class="stat-label">Default Repo Permission</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number" style="color:{actions_color};font-size:1.1rem">{_esc(allowed_actions)}</div>
    <div class="stat-label">Allowed Actions</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number" style="color:{wf_perm_color};font-size:1.1rem">{_esc(default_wf_perm)}</div>
    <div class="stat-label">Default Token Permission</div>
  </div>
</section>""")

    # --- Findings table ---
    if findings:
        sev_counts = {}
        for f in findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        rows = []
        for f in findings:
            rows.append(
                f'<tr class="finding-row" data-severity="{_esc(f.get("severity", "info"))}">'
                f'<td><code>{_esc(f.get("rule_id", ""))}</code></td>'
                f'<td>{_severity_badge(f.get("severity", "info"))}</td>'
                f'<td>'
                f'<div class="finding-title">{_esc(f.get("title", ""))}</div>'
                f'<div class="finding-desc">{_esc(f.get("description", ""))}</div>'
                f'</td></tr>'
            )

        sev_filter_btns = '<button class="filter-btn active" onclick="filterOrgSeverity(\'all\', this)">All</button>'
        for s in SEVERITY_ORDER:
            if sev_counts.get(s, 0) > 0:
                sev_filter_btns += f'<button class="filter-btn" onclick="filterOrgSeverity(\'{s}\', this)">{s.upper()} ({sev_counts[s]})</button>'

        parts.append(f"""
<section class="card collapsible" id="sec-org-settings">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Organization Settings Findings ({len(findings)})
  </h2>
  <div class="section-body">
    <div class="filter-buttons" id="org-severity-filters">
      {sev_filter_btns}
    </div>
    <table class="data-table" id="org-settings-table">
      <thead><tr><th style="width:80px">Rule</th><th style="width:90px">Severity</th><th>Details</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
  </div>
</section>""")
    else:
        parts.append("""
<section class="card collapsible" id="sec-org-settings">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Organization Settings Findings
  </h2>
  <div class="section-body">
    <p class="empty">No organization settings findings.</p>
  </div>
</section>""")

    return "\n".join(parts)


def _render_cis_section(cis_data: dict | None) -> str:
    """Render the CIS Benchmark section."""
    if not cis_data:
        return ""

    total_pass = cis_data.get("total_pass", 0)
    total_fail = cis_data.get("total_fail", 0)
    total_warn = cis_data.get("total_warn", 0)
    total_controls = total_pass + total_fail + total_warn
    pass_pct = (total_pass / total_controls * 100) if total_controls else 0

    CIS_STATUS_COLORS = {
        "PASS": {"bg": "#16a34a", "badge": "#bbf7d0", "text": "#166534"},
        "FAIL": {"bg": "#dc2626", "badge": "#fecaca", "text": "#991b1b"},
        "WARN": {"bg": "#ca8a04", "badge": "#fef08a", "text": "#854d0e"},
        "INFO": {"bg": "#6b7280", "badge": "#e5e7eb", "text": "#374151"},
    }

    def _cis_badge(status: str) -> str:
        c = CIS_STATUS_COLORS.get(status, CIS_STATUS_COLORS["INFO"])
        return f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:600;background:{c["badge"]};color:{c["text"]}">{status}</span>'

    # Summary cards
    parts = [f"""
<section class="card collapsible" id="sec-cis">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> CIS GitHub Benchmark v1.2.0
  </h2>
  <div class="section-body">

<section class="summary-grid">
  <div class="card stat-card">
    <div class="stat-number" style="color:#16a34a">{total_pass}</div>
    <div class="stat-label">PASS</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number" style="color:#dc2626">{total_fail}</div>
    <div class="stat-label">FAIL</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number" style="color:#ca8a04">{total_warn}</div>
    <div class="stat-label">NOT ASSESSED</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number">{pass_pct:.0f}%</div>
    <div class="stat-label">Compliance ({total_pass}/{total_controls})</div>
  </div>
</section>

<div style="margin-bottom:12px">
  <div style="background:#e5e7eb;border-radius:6px;height:20px;overflow:hidden;display:flex">
    <div style="width:{(total_pass/total_controls*100) if total_controls else 0:.1f}%;background:#16a34a;height:100%" title="PASS: {total_pass}"></div>
    <div style="width:{(total_fail/total_controls*100) if total_controls else 0:.1f}%;background:#dc2626;height:100%" title="FAIL: {total_fail}"></div>
    <div style="width:{(total_warn/total_controls*100) if total_controls else 0:.1f}%;background:#ca8a04;height:100%" title="NOT ASSESSED: {total_warn}"></div>
  </div>
</div>
"""]

    # Render each section group
    for group in cis_data.get("tests", []):
        section_desc = _esc(group.get("desc", ""))
        g_pass = group.get("pass", 0)
        g_fail = group.get("fail", 0)
        g_warn = group.get("warn", 0)
        g_total = g_pass + g_fail + g_warn

        rows = []
        for check in group.get("results", []):
            status = check.get("status", "WARN")
            test_num = _esc(check.get("test_number", ""))
            test_desc = _esc(check.get("test_desc", ""))
            reason = _esc(check.get("reason", ""))
            remediation = _esc(check.get("remediation", ""))

            rows.append(
                f'<tr class="cis-row" data-cis-status="{status}">'
                f'<td style="white-space:nowrap"><code>{test_num}</code></td>'
                f'<td>{_cis_badge(status)}</td>'
                f'<td>'
                f'<div style="font-weight:500">{test_desc}</div>'
                f'<div style="font-size:0.85em;color:#6b7280;margin-top:2px">{reason}</div>'
                f'</td></tr>'
            )

        status_summary = f'<span style="color:#16a34a;font-weight:600">{g_pass}P</span> / <span style="color:#dc2626;font-weight:600">{g_fail}F</span> / <span style="color:#ca8a04;font-weight:600">{g_warn}W</span>'

        parts.append(f"""
<div class="collapsible" style="margin-bottom:8px">
  <h3 class="section-toggle" onclick="toggleSection(this)" style="padding:8px 12px;margin:0;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;font-size:0.95em">
    <span class="toggle-icon">&#9654;</span> {section_desc} &mdash; {status_summary}
  </h3>
  <div class="section-body" style="display:none">
    <table class="data-table">
      <thead><tr><th style="width:70px">Control</th><th style="width:70px">Status</th><th>Description</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
  </div>
</div>""")

    parts.append("""
  </div>
</section>""")

    return "\n".join(parts)


def _render_action_runs_section(action_runs: dict | None) -> str:
    """Render the Action Runs section with filters, jobs, and steps."""
    if not action_runs or "error" in action_runs or not action_runs.get("runs"):
        return ""

    runs = action_runs["runs"]
    summary = action_runs.get("summary", {})
    filters_applied = action_runs.get("filters_applied", {})

    total_runs = summary.get("total_runs", len(runs))
    by_conclusion = summary.get("by_conclusion", {})
    by_repo = summary.get("by_repo", {})
    actions_used = summary.get("actions_used", {})

    repos_list = sorted(by_repo.keys())
    conclusions_list = sorted(by_conclusion.keys())
    all_actions_list = sorted(actions_used.keys())
    workflow_names = sorted(set(r.get("workflow_name", "") for r in runs if r.get("workflow_name")))

    success_count = by_conclusion.get("success", 0)
    failure_count = by_conclusion.get("failure", 0)
    cancelled_count = by_conclusion.get("cancelled", 0)
    in_progress_count = by_conclusion.get("in_progress", 0)

    time_range = _esc(filters_applied.get("since", ""))
    if filters_applied.get("until"):
        time_range += f" to {_esc(filters_applied['until'])}"
    else:
        time_range += " to now"

    # Compute min/max timestamps for date filter
    timestamps = [r.get("created_at", "")[:10] for r in runs if r.get("created_at")]
    min_date = min(timestamps) if timestamps else filters_applied.get("since", "")
    max_date = max(timestamps) if timestamps else filters_applied.get("until", "")

    # Build filter options
    repo_options = '<option value="all">All Repos</option>'
    for r in repos_list:
        repo_options += f'<option value="{_esc(r)}">{_esc(r)} ({by_repo[r]})</option>'

    conclusion_colors = {
        "success": "#16a34a", "failure": "#dc2626", "cancelled": "#6b7280",
        "in_progress": "#ca8a04", "skipped": "#94a3b8",
    }
    conclusion_btns = '<button class="filter-btn active" onclick="filterActionRuns(\'conclusion\', \'all\', this)">All</button>'
    for c in conclusions_list:
        color = conclusion_colors.get(c, "#6b7280")
        conclusion_btns += (
            f'<button class="filter-btn" onclick="filterActionRuns(\'conclusion\', \'{_esc(c)}\', this)" '
            f'style="border-left:3px solid {color}">'
            f'{_esc(c.upper())} ({by_conclusion[c]})</button>'
        )

    wf_options = '<option value="all">All Workflows</option>'
    for wf in workflow_names:
        wf_options += f'<option value="{_esc(wf)}">{_esc(wf)}</option>'

    action_options = '<option value="all">All Actions</option>'
    for a in all_actions_list:
        action_options += f'<option value="{_esc(a)}">{_esc(a)} ({actions_used[a]})</option>'

    uses_datalist_options = "".join(
        f'<option value="{_esc(a)}">' for a in all_actions_list
    )

    # Build run rows with expandable jobs/steps
    rows = []
    for run in runs:
        conclusion = run.get("conclusion") or run.get("status") or "unknown"
        conclusion_color = conclusion_colors.get(conclusion, "#6b7280")
        created_ts = run.get("created_at", "")
        created_date = created_ts[:10] if created_ts else ""

        # Actions used as badges (shown in detail row)
        actions_badges = ""
        for a in run.get("actions_used", []):
            actions_badges += f'<span class="action-badge">{_esc(a)}</span> '

        # Build jobs/steps detail
        jobs = run.get("jobs", [])
        jobs_html = ""
        if jobs:
            job_parts = []
            for job in jobs:
                jc = job.get("conclusion") or job.get("status") or ""
                jc_color = conclusion_colors.get(jc, "#6b7280")
                jc_icon = "&#10003;" if jc == "success" else "&#10007;" if jc == "failure" else "&#9644;" if jc == "skipped" else "&#9679;"

                step_rows = []
                for step in job.get("steps", []):
                    sc = step.get("conclusion") or step.get("status") or ""
                    sc_color = conclusion_colors.get(sc, "#6b7280")
                    sc_icon = "&#10003;" if sc == "success" else "&#10007;" if sc == "failure" else "&#9644;" if sc == "skipped" else "&#9679;"
                    step_name = step.get("name", "")
                    is_action = step_name.startswith("Run ") or step_name.startswith("Post Run ")
                    name_class = ' class="step-action"' if is_action else ""
                    step_rows.append(
                        f'<div class="step-row">'
                        f'<span style="color:{sc_color}">{sc_icon}</span> '
                        f'<span{name_class}>{_esc(step_name)}</span>'
                        f'</div>'
                    )

                job_parts.append(
                    f'<div class="job-block">'
                    f'<div class="job-header" style="color:{jc_color}">'
                    f'{jc_icon} <strong>{_esc(job["name"])}</strong>'
                    f' <span class="job-conclusion">({_esc(jc)})</span>'
                    f'</div>'
                    f'<div class="steps-container">{"".join(step_rows)}</div>'
                    f'</div>'
                )
            jobs_html = "".join(job_parts)

        actions_data = "|".join(run.get("actions_used", []))

        # Detail extras: event, branch, actor, actions used
        detail_meta = (
            f'<div class="run-detail-meta">'
            f'<span><strong>Event:</strong> {_esc(run.get("event", "—"))}</span>'
            f'<span><strong>Branch:</strong> {_esc(run.get("branch", "—"))}</span>'
            f'<span><strong>Actor:</strong> {_esc(run.get("actor", "—"))}</span>'
            f'</div>'
        )
        if actions_badges:
            detail_meta += (
                f'<div class="run-detail-actions">'
                f'<strong>Actions used:</strong><br>{actions_badges}'
                f'</div>'
            )

        detail_body = detail_meta + (jobs_html if jobs_html else "<em>No job data</em>")

        # Main row — compact: Run #, Repo, Workflow, Status, Created, expand
        row_id = f"ar-{run['run_id']}"
        rows.append(
            f'<tr class="action-run-row" '
            f'data-repo="{_esc(run["repo"])}" '
            f'data-conclusion="{_esc(conclusion)}" '
            f'data-workflow="{_esc(run.get("workflow_name", ""))}" '
            f'data-actions="{_esc(actions_data)}" '
            f'data-date="{_esc(created_date)}">'
            f'<td><a href="{_esc(run.get("html_url", "#"))}" target="_blank" rel="noopener">#{run.get("run_number", "")}</a></td>'
            f'<td style="word-break:break-word;max-width:180px">{_esc(run["repo"])}</td>'
            f'<td style="word-break:break-word;max-width:200px">{_esc(run.get("workflow_name", ""))}</td>'
            f'<td><span style="color:{conclusion_color};font-weight:600">{_esc(conclusion.upper())}</span></td>'
            f'<td class="ts-cell">{_esc(created_ts[:10] if created_ts else "")}</td>'
            f'<td class="expand-cell"><button class="expand-btn" onclick="toggleRunDetail(\'{row_id}\')">&#9654;</button></td>'
            f'</tr>'
            f'<tr class="run-detail-row" id="{row_id}" style="display:none">'
            f'<td colspan="6"><div class="run-detail">{detail_body}</div></td>'
            f'</tr>'
        )

    return f"""
<section class="card collapsible" id="sec-action-runs">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Action Runs ({total_runs} runs, {time_range})
  </h2>
  <div class="section-body">

    <div class="summary-grid" style="margin-bottom:16px">
      <div class="card stat-card">
        <div class="stat-number">{total_runs}</div>
        <div class="stat-label">Total Runs</div>
      </div>
      <div class="card stat-card">
        <div class="stat-number" style="color:#16a34a">{success_count}</div>
        <div class="stat-label">Success</div>
      </div>
      <div class="card stat-card">
        <div class="stat-number" style="color:#dc2626">{failure_count}</div>
        <div class="stat-label">Failure</div>
      </div>
      <div class="card stat-card">
        <div class="stat-number" style="color:#6b7280">{cancelled_count + in_progress_count}</div>
        <div class="stat-label">Other</div>
      </div>
      <div class="card stat-card">
        <div class="stat-number">{len(all_actions_list)}</div>
        <div class="stat-label">Unique Actions</div>
      </div>
    </div>

    <div class="toolbar" style="flex-wrap:wrap;gap:8px;margin-bottom:12px">
      <select id="ar-repo-filter" class="filter-select" onchange="applyActionRunFilters()">
        {repo_options}
      </select>
      <select id="ar-workflow-filter" class="filter-select" onchange="applyActionRunFilters()">
        {wf_options}
      </select>
      <input type="text" id="ar-text-filter" class="filter-input" placeholder="Search runs..."
             onkeyup="applyActionRunFilters()" style="max-width:180px">
    </div>
    <div class="toolbar" style="flex-wrap:wrap;gap:8px;margin-bottom:12px;align-items:center">
      <label style="font-size:0.83rem;color:var(--text-muted);white-space:nowrap">step.uses filter:</label>
      <div class="uses-filter-wrap">
        <input type="text" id="ar-uses-filter" class="filter-input" placeholder="e.g. actions/checkout"
               list="ar-uses-datalist" onkeyup="applyActionRunFilters()" oninput="applyActionRunFilters()"
               style="min-width:220px">
        <datalist id="ar-uses-datalist">
          {uses_datalist_options}
        </datalist>
        <button class="filter-clear-btn" id="ar-uses-clear" onclick="clearUsesFilter()" title="Clear">&#10005;</button>
      </div>
      <span id="ar-uses-match-count" style="font-size:0.8rem;color:var(--text-muted)"></span>
    </div>
    <div class="toolbar" style="flex-wrap:wrap;gap:8px;margin-bottom:12px;align-items:center">
      <label style="font-size:0.85rem;color:var(--text-muted)">Date range:</label>
      <input type="date" id="ar-date-from" class="filter-input" value="{_esc(min_date)}"
             onchange="applyActionRunFilters()" style="max-width:160px">
      <span style="font-size:0.85rem;color:var(--text-muted)">to</span>
      <input type="date" id="ar-date-to" class="filter-input" value="{_esc(max_date)}"
             onchange="applyActionRunFilters()" style="max-width:160px">
    </div>
    <div class="filter-buttons" id="ar-conclusion-filters" style="margin-bottom:12px">
      {conclusion_btns}
    </div>

    <table class="data-table" id="action-runs-table" style="width:100%;table-layout:fixed">
      <colgroup>
        <col style="width:70px">
        <col style="width:22%">
        <col style="width:auto">
        <col style="width:100px">
        <col style="width:100px">
        <col style="width:40px">
      </colgroup>
      <thead>
        <tr>
          <th>Run</th>
          <th>Repository</th>
          <th>Workflow</th>
          <th>Status</th>
          <th>Created</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows)}
      </tbody>
    </table>
  </div>
</section>"""


def _render_apps_and_tokens_section(apps_tokens: dict | None) -> str:
    """Render the Apps & Tokens audit section."""
    if not apps_tokens or "error" in apps_tokens:
        return ""

    findings = apps_tokens.get("findings", [])
    app_count = len(apps_tokens.get("app_installations", []))
    pat_count = len(apps_tokens.get("fine_grained_pats", []))

    parts = []

    # Summary cards
    parts.append(f"""
<section class="summary-grid">
  <div class="card stat-card">
    <div class="stat-number">{app_count}</div>
    <div class="stat-label">App Installations</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number">{pat_count}</div>
    <div class="stat-label">Fine-Grained PATs</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number">{len(findings)}</div>
    <div class="stat-label">Findings</div>
  </div>
</section>""")

    # Findings table
    if findings:
        sev_counts: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        rows = []
        for f in findings:
            rows.append(
                f'<tr class="finding-row" data-severity="{_esc(f.get("severity", "info"))}">'
                f'<td><code>{_esc(f.get("rule_id", ""))}</code></td>'
                f'<td>{_severity_badge(f.get("severity", "info"))}</td>'
                f'<td>'
                f'<div class="finding-title">{_esc(f.get("title", ""))}</div>'
                f'<div class="finding-desc">{_esc(f.get("description", ""))}</div>'
                f'</td></tr>'
            )

        sev_filter_btns = '<button class="filter-btn active" onclick="filterAppsTokensSeverity(\'all\', this)">All</button>'
        for s in SEVERITY_ORDER:
            if sev_counts.get(s, 0) > 0:
                sev_filter_btns += f'<button class="filter-btn" onclick="filterAppsTokensSeverity(\'{s}\', this)">{s.upper()} ({sev_counts[s]})</button>'

        parts.append(f"""
<section class="card collapsible" id="sec-apps-tokens">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Apps &amp; Tokens Findings ({len(findings)})
  </h2>
  <div class="section-body">
    <div class="filter-buttons" id="apps-tokens-severity-filters">
      {sev_filter_btns}
    </div>
    <table class="data-table" id="apps-tokens-table">
      <thead><tr><th style="width:80px">Rule</th><th style="width:90px">Severity</th><th>Details</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
  </div>
</section>""")
    else:
        parts.append("""
<section class="card collapsible" id="sec-apps-tokens">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Apps &amp; Tokens Findings
  </h2>
  <div class="section-body">
    <p class="empty">No apps &amp; tokens findings.</p>
  </div>
</section>""")

    return "\n".join(parts)


def _render_identity_section(identity: dict | None) -> str:
    if not identity or "error" in identity:
        return ""

    findings = identity.get("findings", [])
    org_owners = identity.get("org_owners", [])
    org_member_count = identity.get("org_member_count", 0)
    outside_collabs = identity.get("outside_collaborators", [])
    teams = identity.get("teams", [])
    pending = identity.get("pending_invitations", [])
    repo_access = identity.get("repo_access", [])

    parts = []

    # --- Summary cards ---
    parts.append(f"""
<section class="summary-grid">
  <div class="card stat-card">
    <div class="stat-number">{org_member_count}</div>
    <div class="stat-label">Org Members</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number" style="color:{'#dc2626' if len(org_owners) > 3 else '#2563eb'}">{len(org_owners)}</div>
    <div class="stat-label">Org Owners</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number">{len(outside_collabs)}</div>
    <div class="stat-label">Outside Collaborators</div>
  </div>
  <div class="card stat-card">
    <div class="stat-number">{len(teams)}</div>
    <div class="stat-label">Teams</div>
  </div>
</section>""")

    # --- Identity findings ---
    if findings:
        sev_counts_iam = {}
        for f in findings:
            s = f.get("severity", "info")
            sev_counts_iam[s] = sev_counts_iam.get(s, 0) + 1

        rows = []
        for f in findings:
            users_str = ""
            users = f.get("users") or ([f["user"]] if f.get("user") else [])
            if users:
                users_str = f'<div class="finding-location">Users: {_esc(", ".join(users[:15]))}'
                if len(users) > 15:
                    users_str += f" ... and {len(users) - 15} more"
                users_str += "</div>"

            repo_str = ""
            if f.get("repo"):
                repo_str = f'<div class="finding-location">Repo: {_esc(f["repo"])}</div>'

            team_str = ""
            if f.get("team"):
                team_str = f'<div class="finding-location">Team: {_esc(f["team"])}</div>'

            rows.append(
                f'<tr class="finding-row" data-severity="{_esc(f.get("severity", "info"))}">'
                f'<td><code>{_esc(f.get("rule_id", ""))}</code></td>'
                f'<td>{_severity_badge(f.get("severity", "info"))}</td>'
                f'<td>'
                f'<div class="finding-title">{_esc(f.get("title", ""))}</div>'
                f'<div class="finding-desc">{_esc(f.get("description", ""))}</div>'
                f'{team_str}{repo_str}{users_str}'
                f'</td></tr>'
            )

        sev_filter_btns = '<button class="filter-btn active" onclick="filterIAMSeverity(\'all\', this)">All</button>'
        for s in SEVERITY_ORDER:
            if sev_counts_iam.get(s, 0) > 0:
                sev_filter_btns += f'<button class="filter-btn" onclick="filterIAMSeverity(\'{s}\', this)">{s.upper()} ({sev_counts_iam[s]})</button>'

        parts.append(f"""
<section class="card collapsible" id="sec-iam-findings">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Identity &amp; Access Findings ({len(findings)})
  </h2>
  <div class="section-body">
    <div class="filter-buttons" id="iam-severity-filters">
      {sev_filter_btns}
    </div>
    <input type="text" class="filter-input" placeholder="Search findings..."
           onkeyup="filterTable(this, 'iam-findings-table')">
    <table class="data-table" id="iam-findings-table">
      <thead><tr><th style="width:80px">Rule</th><th style="width:90px">Severity</th><th>Details</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
  </div>
</section>""")
    else:
        parts.append("""
<section class="card collapsible" id="sec-iam-findings">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Identity &amp; Access Findings
  </h2>
  <div class="section-body">
    <p class="empty">No identity findings.</p>
  </div>
</section>""")

    # --- Org owners list ---
    parts.append(f"""
<section class="card collapsible" id="sec-owners">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Organization Owners ({len(org_owners)})
  </h2>
  <div class="section-body">
    <div class="user-grid">
      {"".join(f'<span class="user-tag admin-tag">{_esc(u)}</span>' for u in org_owners)}
    </div>
  </div>
</section>""")

    # --- Inactive members table ---
    inactive = identity.get("inactive_members", {})
    parts.append(_render_inactive_members_table(inactive))

    # --- Outside collaborators ---
    if outside_collabs:
        parts.append(f"""
<section class="card collapsible" id="sec-outside">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Outside Collaborators ({len(outside_collabs)})
  </h2>
  <div class="section-body">
    <div class="user-grid">
      {"".join(f'<span class="user-tag outside-tag">{_esc(c["login"])}</span>' for c in outside_collabs)}
    </div>
  </div>
</section>""")

    # --- Teams ---
    if teams:
        team_sections = []
        for t in teams:
            repo_rows = ""
            for r in t.get("repos", [])[:20]:
                perm = r["permission"]
                pstyle = "color:#dc2626;font-weight:700" if perm == "admin" else (
                    "color:#ea580c;font-weight:600" if perm in ("write", "maintain") else ""
                )
                repo_rows += (
                    f'<tr><td>{_esc(r["repo"])}</td>'
                    f'<td style="{pstyle}">{_esc(perm)}</td></tr>'
                )
            if len(t.get("repos", [])) > 20:
                repo_rows += f'<tr><td colspan="2" class="empty">... and {len(t["repos"]) - 20} more repos</td></tr>'

            members_str = ", ".join(t.get("members", [])[:20])
            if len(t.get("members", [])) > 20:
                members_str += f" ... and {len(t['members']) - 20} more"

            team_sections.append(f"""
    <div class="repo-section" data-repo="{_esc(t['slug'])}">
      <div class="repo-header" onclick="toggleRepo(this)">
        <span class="repo-toggle">&#9654;</span>
        <span class="repo-name">{_esc(t['name'])}</span>
        <span class="repo-count">{t['member_count']} members &middot; {len(t.get('repos',[]))} repos</span>
      </div>
      <div class="repo-body">
        <p style="margin-bottom:8px"><strong>Members:</strong> {_esc(members_str)}</p>
        <table class="data-table">
          <thead><tr><th>Repository</th><th style="width:100px">Permission</th></tr></thead>
          <tbody>{repo_rows}</tbody>
        </table>
      </div>
    </div>""")

        parts.append(f"""
<section class="card collapsible" id="sec-teams">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Teams ({len(teams)})
  </h2>
  <div class="section-body">
    <input type="text" class="filter-input" placeholder="Filter teams..."
           onkeyup="filterCollapsibles(this, this.closest('.section-body'))">
    <div class="filter-buttons">
      <button class="nav-btn" onclick="expandAllInContainer(this.closest('.section-body'))">Expand All</button>
      <button class="nav-btn" onclick="collapseAllInContainer(this.closest('.section-body'))">Collapse All</button>
    </div>
    {"".join(team_sections)}
  </div>
</section>""")

    # --- Repo access matrix ---
    if repo_access:
        sorted_access = sorted(repo_access, key=lambda r: -r.get("admin_count", 0))
        access_rows = []
        for r in sorted_access[:30]:
            outside = [c["login"] for c in r["collaborators"] if c.get("is_outside_collaborator")]
            outside_str = f'<span class="user-tag outside-tag" style="font-size:0.7rem">{", ".join(outside[:5])}</span>' if outside else "-"
            access_rows.append(
                f'<tr>'
                f'<td>{_esc(r["repo"])}</td>'
                f'<td class="num">{r["admin_count"]}</td>'
                f'<td class="num">{r["write_count"]}</td>'
                f'<td class="num">{len(r["collaborators"])}</td>'
                f'<td>{outside_str}</td>'
                f'</tr>'
            )

        parts.append(f"""
<section class="card collapsible" id="sec-access">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Repository Access Overview
  </h2>
  <div class="section-body">
    <input type="text" class="filter-input" placeholder="Filter repositories..."
           onkeyup="filterTable(this, 'repo-access-table')">
    <table class="data-table sortable" id="repo-access-table">
      <thead>
        <tr>
          <th class="sortable-th" onclick="sortTable('repo-access-table', 0, 'text')">Repository <span class="sort-icon"></span></th>
          <th class="num sortable-th" onclick="sortTable('repo-access-table', 1, 'num')">Admins <span class="sort-icon"></span></th>
          <th class="num sortable-th" onclick="sortTable('repo-access-table', 2, 'num')">Writers <span class="sort-icon"></span></th>
          <th class="num sortable-th" onclick="sortTable('repo-access-table', 3, 'num')">Total <span class="sort-icon"></span></th>
          <th>Outside Collaborators</th>
        </tr>
      </thead>
      <tbody>{"".join(access_rows)}</tbody>
    </table>
  </div>
</section>""")

    return "\n".join(parts)


def _render_inactive_members_table(inactive: dict) -> str:
    """Render a table of inactive members with 1/3/6 month columns."""
    users_6m = set(inactive.get("no_contributions_6_months", []))
    users_3m = set(inactive.get("no_contributions_3_months", []))
    users_1m = set(inactive.get("no_contributions_1_month", []))

    # Collect all inactive users; 6m users are also inactive at 3m and 1m, etc.
    all_inactive: dict[str, dict[str, bool]] = {}
    for user in users_6m:
        all_inactive[user] = {"1m": True, "3m": True, "6m": True}
    for user in users_3m:
        all_inactive[user] = {"1m": True, "3m": True, "6m": False}
    for user in users_1m:
        all_inactive[user] = {"1m": True, "3m": False, "6m": False}

    if not all_inactive:
        return """
<section class="card collapsible" id="sec-inactive">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Inactive Members
  </h2>
  <div class="section-body">
    <p class="empty">All members have recent contributions.</p>
  </div>
</section>"""

    check = '<span class="inactive-check">&#10007;</span>'
    dash = '<span class="inactive-dash">&ndash;</span>'

    rows = []
    for user in sorted(all_inactive, key=lambda u: (not all_inactive[u]["6m"], not all_inactive[u]["3m"], u)):
        flags = all_inactive[user]
        # data-period: highest inactivity tier for filtering
        period = "6m" if flags["6m"] else ("3m" if flags["3m"] else "1m")
        sev_class = f"inactive-{period}"
        rows.append(
            f'<tr class="{sev_class}" data-period="{period}">'
            f'<td><span class="user-tag member-tag">{_esc(user)}</span></td>'
            f'<td class="num">{check if flags["1m"] else dash}</td>'
            f'<td class="num">{check if flags["3m"] else dash}</td>'
            f'<td class="num">{check if flags["6m"] else dash}</td>'
            f'</tr>'
        )

    count_6m = len(users_6m)
    count_3m = len(users_3m)
    count_1m = len(users_1m)

    return f"""
<section class="card collapsible" id="sec-inactive">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span> Inactive Members ({len(all_inactive)})
  </h2>
  <div class="section-body">
    <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:12px">
      Members with no contributions (commits) in the organization within the specified period.
    </p>
    <div class="filter-buttons" id="inactive-filters">
      <button class="filter-btn active" onclick="filterInactive('all', this)">All ({len(all_inactive)})</button>
      <button class="filter-btn" onclick="filterInactive('6m', this)" style="border-color:#dc2626;color:#991b1b">6 Months ({count_6m})</button>
      <button class="filter-btn" onclick="filterInactive('3m', this)" style="border-color:#ca8a04;color:#854d0e">3 Months ({count_3m})</button>
      <button class="filter-btn" onclick="filterInactive('1m', this)" style="border-color:#2563eb;color:#1e40af">1 Month ({count_1m})</button>
    </div>
    <input type="text" class="filter-input" placeholder="Search users..."
           onkeyup="filterTable(this, 'inactive-table')">
    <table class="data-table sortable" id="inactive-table">
      <thead>
        <tr>
          <th class="sortable-th" onclick="sortTable('inactive-table', 0, 'text')">User <span class="sort-icon"></span></th>
          <th class="num sortable-th" onclick="sortTable('inactive-table', 1, 'text')">No Activity<br>1 Month <span class="sort-icon"></span></th>
          <th class="num sortable-th" onclick="sortTable('inactive-table', 2, 'text')">No Activity<br>3 Months <span class="sort-icon"></span></th>
          <th class="num sortable-th" onclick="sortTable('inactive-table', 3, 'text')">No Activity<br>6 Months <span class="sort-icon"></span></th>
        </tr>
      </thead>
      <tbody>{"".join(rows)}</tbody>
    </table>
  </div>
</section>"""


# ---------------------------------------------------------------------------
# Trivy Supply Chain Advisory Section (CVE-2026-33634)
# ---------------------------------------------------------------------------

def _render_trivy_advisory_section(trivy_data: dict | None) -> str:
    """Render the Trivy supply chain advisory section."""
    if not trivy_data or "error" in trivy_data or trivy_data.get("total_findings", 0) == 0:
        return ""

    findings = trivy_data.get("findings", [])
    by_repo = trivy_data.get("by_repo", {})
    sev_counts = trivy_data.get("severity_counts", {})
    total = trivy_data["total_findings"]
    repos_affected = trivy_data.get("repos_affected", 0)
    repos_using = trivy_data.get("repos_using_trivy", 0)
    repos_safe = trivy_data.get("repos_safe", 0)
    cve_id = trivy_data.get("cve_id", "CVE-2026-33634")
    advisory_url = trivy_data.get("advisory_url", "#")
    affected_actions = trivy_data.get("affected_actions", {})
    affected_binary = trivy_data.get("affected_binary_versions", [])

    critical_count = sev_counts.get("critical", 0)
    medium_count = sev_counts.get("medium", 0)
    info_count = sev_counts.get("info", 0)

    # Status colors
    status_styles = {
        "affected": "background:#fecaca;color:#991b1b;border:1px solid #fca5a5",
        "review": "background:#fef08a;color:#854d0e;border:1px solid #fde047",
        "safe": "background:#bbf7d0;color:#166534;border:1px solid #86efac",
    }

    # Build affected actions info
    actions_info = ""
    for action_name, info in affected_actions.items():
        actions_info += (
            f'<tr><td><code>{_esc(action_name)}</code></td>'
            f'<td>&lt; {_esc(info["safe_version"])}</td>'
            f'<td><strong>&ge; {_esc(info["safe_version"])}</strong></td></tr>'
        )
    if affected_binary:
        actions_info += (
            f'<tr><td><code>aquasec/trivy</code> (Docker image)</td>'
            f'<td>{_esc(", ".join(affected_binary))}</td>'
            f'<td><strong>0.69.2, 0.69.3, or &ge; 0.69.7</strong></td></tr>'
        )

    # Build per-repo finding rows
    repo_sections = []
    for repo_name in sorted(by_repo.keys()):
        repo_findings = by_repo[repo_name]
        has_critical = any(f.get("severity") == "critical" for f in repo_findings)
        repo_border = "#dc2626" if has_critical else "#ca8a04" if any(f.get("severity") == "medium" for f in repo_findings) else "#16a34a"

        finding_rows = ""
        for f in repo_findings:
            status = f.get("status", "review")
            style = status_styles.get(status, "")
            finding_rows += (
                f'<tr>'
                f'<td><span class="trivy-status-badge" style="{style}">'
                f'{_esc(status.upper())}</span></td>'
                f'<td><code>{_esc(f.get("action", ""))}</code></td>'
                f'<td>{_esc(f.get("workflow", ""))}</td>'
                f'<td>{_esc(f.get("job", ""))}</td>'
                f'<td>{_esc(f.get("step", ""))}</td>'
                f'<td style="font-size:0.82rem">{_esc(f.get("message", ""))}</td>'
                f'</tr>'
            )

        repo_sections.append(
            f'<div class="trivy-repo-block" style="border-left:4px solid {repo_border};'
            f'padding:12px 16px;margin-bottom:12px;background:var(--bg);border-radius:6px">'
            f'<h4 style="margin:0 0 8px 0;font-size:0.95rem">{_esc(repo_name)}'
            f' <span style="font-weight:normal;color:var(--text-muted)">({len(repo_findings)} finding(s))</span></h4>'
            f'<table class="findings-table" style="width:100%;font-size:0.83rem">'
            f'<thead><tr><th>Status</th><th>Action/Image</th><th>Workflow</th><th>Job</th><th>Step</th><th>Details</th></tr></thead>'
            f'<tbody>{finding_rows}</tbody>'
            f'</table></div>'
        )

    # Banner color based on severity
    banner_bg = "#fef2f2" if critical_count > 0 else "#fffbeb" if medium_count > 0 else "#f0fdf4"
    banner_border = "#dc2626" if critical_count > 0 else "#ca8a04" if medium_count > 0 else "#16a34a"

    return f"""
<section class="card collapsible" id="sec-trivy-advisory">
  <h2 class="section-toggle" onclick="toggleSection(this)">
    <span class="toggle-icon open">&#9660;</span>
    Trivy Supply Chain Advisory ({cve_id})
    {f'<span style="background:#dc2626;color:#fff;padding:2px 10px;border-radius:12px;font-size:0.75rem;margin-left:8px;vertical-align:middle">CRITICAL</span>' if critical_count > 0 else ''}
  </h2>
  <div class="section-body">

    <!-- Advisory Banner -->
    <div style="background:{banner_bg};border:1px solid {banner_border};border-radius:8px;padding:16px 20px;margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:1.3rem">{"&#9888;" if critical_count > 0 else "&#9432;"}</span>
        <strong style="font-size:1rem">{cve_id} &mdash; Trivy Ecosystem Supply Chain Compromise</strong>
      </div>
      <p style="margin:0 0 8px 0;font-size:0.88rem;color:#374151">
        Threat actors compromised Trivy distribution channels (binaries, Docker images, and GitHub Actions)
        by exploiting non-atomic credential rotation. Malicious releases exfiltrate CI secrets including
        SSH keys, credentials, and tokens.
      </p>
      <a href="{_esc(advisory_url)}" target="_blank" rel="noopener"
         style="font-size:0.85rem;color:#2563eb">View full advisory &rarr;</a>
    </div>

    <!-- Summary Stats -->
    <div class="summary-grid" style="margin-bottom:16px">
      <div class="card stat-card">
        <div class="stat-number">{repos_using}</div>
        <div class="stat-label">Repos Using Trivy</div>
      </div>
      <div class="card stat-card">
        <div class="stat-number" style="color:#dc2626">{repos_affected}</div>
        <div class="stat-label">Repos Affected</div>
      </div>
      <div class="card stat-card">
        <div class="stat-number" style="color:#16a34a">{max(0, repos_safe)}</div>
        <div class="stat-label">Repos Safe</div>
      </div>
      <div class="card stat-card">
        <div class="stat-number">{total}</div>
        <div class="stat-label">Total Findings</div>
      </div>
    </div>

    <!-- Severity breakdown -->
    <div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap">
      {f'<span style="background:#fecaca;color:#991b1b;padding:4px 12px;border-radius:12px;font-size:0.83rem;font-weight:600">Critical: {critical_count}</span>' if critical_count else ''}
      {f'<span style="background:#fef08a;color:#854d0e;padding:4px 12px;border-radius:12px;font-size:0.83rem;font-weight:600">Needs Review: {medium_count}</span>' if medium_count else ''}
      {f'<span style="background:#bbf7d0;color:#166534;padding:4px 12px;border-radius:12px;font-size:0.83rem;font-weight:600">Safe: {info_count}</span>' if info_count else ''}
    </div>

    <!-- Affected Versions Reference -->
    <details style="margin-bottom:16px">
      <summary style="cursor:pointer;font-weight:600;font-size:0.9rem;color:var(--text-primary)">
        Affected Versions Reference
      </summary>
      <table class="findings-table" style="width:100%;margin-top:8px;font-size:0.85rem">
        <thead><tr><th>Component</th><th>Affected Versions</th><th>Safe Versions</th></tr></thead>
        <tbody>{actions_info}</tbody>
      </table>
      <div style="margin-top:8px;font-size:0.82rem;color:var(--text-muted)">
        <strong>Recommendation:</strong> Pin GitHub Actions to immutable commit SHAs rather than mutable version tags.
        Rotate all secrets that may have been exposed during the attack window (March 19-22, 2026).
      </div>
    </details>

    <!-- Per-Repo Findings -->
    <h3 style="font-size:0.95rem;margin-bottom:10px">Findings by Repository</h3>
    {"".join(repo_sections)}

  </div>
</section>
"""


# ---------------------------------------------------------------------------
# Embedded CSS
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #f8fafc;
  --card-bg: #fff;
  --text: #1e293b;
  --text-muted: #64748b;
  --border: #e2e8f0;
  --accent: #2563eb;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
}

.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }

header {
  background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
  color: #fff;
  padding: 32px 0;
}
header h1 { font-size: 1.75rem; font-weight: 700; }
header .subtitle { color: #bfdbfe; margin-top: 4px; font-size: 0.95rem; }
header .subtitle strong { color: #fff; }

main { padding: 24px 0 48px; }

/* Sticky section nav */
.section-nav {
  position: sticky;
  top: 0;
  z-index: 100;
  background: #fff;
  border-bottom: 1px solid var(--border);
  box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}
.nav-inner {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 8px 0;
  overflow-x: auto;
  white-space: nowrap;
  -webkit-overflow-scrolling: touch;
}
.nav-link {
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: 500;
  color: var(--text-muted);
  text-decoration: none;
  transition: all 0.15s;
  flex-shrink: 0;
}
.nav-link:hover { background: #f1f5f9; color: var(--accent); }
.nav-sep { flex-grow: 1; }
.nav-btn {
  padding: 4px 12px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: #fff;
  cursor: pointer;
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--text-muted);
  transition: all 0.15s;
  flex-shrink: 0;
}
.nav-btn:hover { background: #f1f5f9; color: var(--accent); border-color: var(--accent); }

.card {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 20px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.card h2 {
  font-size: 1.15rem;
  font-weight: 600;
  margin-bottom: 16px;
  color: var(--text);
}

/* Collapsible sections */
.section-toggle {
  cursor: pointer;
  user-select: none;
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 0 !important;
  transition: margin 0.2s;
}
.section-toggle:hover { color: var(--accent); }
.collapsible .section-body { transition: max-height 0.3s ease, opacity 0.2s ease; overflow: hidden; }
.collapsible .section-toggle.open { margin-bottom: 16px !important; }
.collapsible .section-toggle:not(.open) + .section-body {
  max-height: 0;
  opacity: 0;
  padding-top: 0;
  margin-top: 0;
  overflow: hidden;
}
.collapsible .section-toggle.open + .section-body {
  max-height: none;
  opacity: 1;
}
.toggle-icon {
  font-size: 0.7rem;
  transition: transform 0.2s;
  display: inline-block;
}
.toggle-icon:not(.open) { transform: rotate(-90deg); }

/* Summary grid */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}
.stat-card { text-align: center; }
.stat-number { font-size: 2.25rem; font-weight: 700; color: var(--accent); }
.stat-label { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

/* Severity bar */
.severity-bar-container { margin-bottom: 12px; }
.severity-bar {
  display: flex;
  height: 32px;
  border-radius: 6px;
  overflow: hidden;
  font-size: 0.8rem;
  font-weight: 600;
  color: #fff;
}
.sev-segment {
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  transition: opacity 0.2s;
}
.sev-segment:hover { opacity: 0.85; }
.severity-legend { display: flex; flex-wrap: wrap; gap: 16px; font-size: 0.85rem; }
.legend-item { display: flex; align-items: center; gap: 6px; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }

/* Badge */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  vertical-align: middle;
}

/* Tables */
.data-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
.data-table th {
  text-align: left;
  padding: 10px 12px;
  background: #f1f5f9;
  border-bottom: 2px solid var(--border);
  font-weight: 600;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-muted);
}
.data-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
.data-table .num { text-align: right; }
.data-table code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }

/* Sortable columns */
.sortable-th { cursor: pointer; position: relative; }
.sortable-th:hover { color: var(--accent); }
.sort-icon { font-size: 0.7rem; margin-left: 2px; opacity: 0.4; }
.sort-icon.asc::after { content: "\\25B2"; }
.sort-icon.desc::after { content: "\\25BC"; }

.finding-title { font-weight: 600; margin-bottom: 4px; }
.finding-desc { color: var(--text-muted); font-size: 0.85rem; line-height: 1.5; }
.finding-location { color: var(--text-muted); font-size: 0.8rem; margin-top: 4px; font-style: italic; }
.line-hint { margin-top: 6px; }
.line-hint code { background: #fef3c7; color: #92400e; font-size: 0.8rem; word-break: break-all; }

.empty { color: var(--text-muted); font-style: italic; text-align: center; padding: 16px; }

/* Toolbar */
.toolbar { margin-bottom: 8px; }
.toolbar-sep { display: inline-block; width: 1px; height: 20px; background: var(--border); vertical-align: middle; margin: 0 4px; }

/* Repo sections (accordion items) */
.repo-section { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 8px; overflow: hidden; }
.repo-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  background: #f8fafc;
  cursor: pointer;
  user-select: none;
  flex-wrap: wrap;
}
.repo-header:hover { background: #f1f5f9; }
.repo-toggle { font-size: 0.7rem; color: var(--text-muted); transition: transform 0.2s; display: inline-block; }
.repo-header.open .repo-toggle { transform: rotate(90deg); }
.repo-name { font-weight: 600; font-size: 0.95rem; }
.repo-branch { color: var(--text-muted); font-size: 0.85rem; }
.repo-count { margin-left: auto; color: var(--text-muted); font-size: 0.8rem; }
.repo-body { display: none; padding: 16px; }
.repo-header.open + .repo-body { display: block; }

.workflow-group { margin-bottom: 16px; }
.workflow-name { font-size: 0.9rem; color: var(--text-muted); margin-bottom: 8px; padding-left: 4px; }
.workflow-name::before { content: "\\1F4C4 "; }

/* Filter */
.filter-input {
  width: 100%;
  padding: 10px 14px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.9rem;
  margin-bottom: 12px;
  outline: none;
}
.filter-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }

.filter-buttons { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; align-items: center; }
.filter-btn {
  padding: 4px 14px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: #fff;
  cursor: pointer;
  font-size: 0.8rem;
  font-weight: 500;
  transition: all 0.15s;
}
.filter-btn:hover { background: #f1f5f9; }
.filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }

/* No-match message (injected by JS) */
.no-match-msg { text-align: center; color: var(--text-muted); font-style: italic; padding: 20px; display: none; }

footer {
  text-align: center;
  padding: 24px 0;
  color: var(--text-muted);
  font-size: 0.8rem;
  border-top: 1px solid var(--border);
}

/* User tags */
.user-grid { display: flex; flex-wrap: wrap; gap: 8px; }
.user-tag {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 16px;
  font-size: 0.85rem;
  font-weight: 500;
}
.admin-tag { background: #fee2e2; color: #991b1b; }
.outside-tag { background: #fef3c7; color: #92400e; }
.member-tag { background: #e0e7ff; color: #3730a3; }

/* Inactive members */
.inactive-check { color: #dc2626; font-weight: 700; font-size: 1.1rem; }
.inactive-dash { color: #d1d5db; font-size: 1.1rem; }
.inactive-6m td { background: #fef2f2; }
.inactive-3m td { background: #fffbeb; }
.inactive-1m td { background: #f8fafc; }

/* Smooth scroll */
html { scroll-behavior: smooth; scroll-padding-top: 60px; }

/* Action Runs */
.filter-select {
  padding: 6px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.85rem;
  background: #fff;
  color: var(--text);
}
.trivy-status-badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 0.73rem;
  font-weight: 700;
  letter-spacing: 0.02em;
  white-space: nowrap;
}
.trivy-repo-block table th {
  text-align: left;
  padding: 6px 8px;
  border-bottom: 2px solid var(--border);
  font-size: 0.78rem;
  color: var(--text-muted);
}
.trivy-repo-block table td {
  padding: 6px 8px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
.action-badge {
  display: inline-block;
  padding: 1px 6px;
  margin: 1px 2px;
  border-radius: 4px;
  font-size: 0.72rem;
  font-family: monospace;
  background: #e0e7ff;
  color: #3730a3;
  white-space: nowrap;
}
.job-row {
  padding: 2px 0;
  font-size: 0.8rem;
  line-height: 1.4;
}
.job-badge {
  font-size: 0.85rem;
  margin-right: 2px;
}
.step-list {
  color: var(--text-muted);
  font-size: 0.75rem;
  margin-left: 6px;
}
.ts-cell { white-space: nowrap; font-size: 0.8rem; }
.actions-cell { max-width: 250px; }
.jobs-cell { max-width: 300px; min-width: 180px; }
.expand-cell { text-align: center; width: 40px; }
.expand-btn {
  background: none;
  border: 1px solid var(--border);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.75rem;
  padding: 2px 8px;
  color: var(--text-muted);
  transition: all 0.15s;
}
.expand-btn:hover { background: #f1f5f9; color: var(--accent); border-color: var(--accent); }
.expand-btn.open { transform: rotate(90deg); }
.uses-filter-wrap { position: relative; display: inline-flex; align-items: center; gap: 4px; }
.filter-clear-btn { display: none; align-items: center; justify-content: center; width: 22px; height: 22px; border: 1px solid var(--border); border-radius: 4px; background: #fff; color: var(--text-muted); font-size: 0.75rem; cursor: pointer; padding: 0; line-height: 1; }
.filter-clear-btn:hover { background: #fee2e2; color: #dc2626; border-color: #dc2626; }
.run-detail-row td { padding: 0 !important; border-bottom: 1px solid var(--border); }
.run-detail { padding: 12px 16px 12px 24px; background: #f8fafc; }
.run-detail-meta { display: flex; flex-wrap: wrap; gap: 12px 24px; font-size: 0.83rem; color: var(--text-muted); margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
.run-detail-meta span { white-space: nowrap; }
.run-detail-actions { font-size: 0.83rem; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--border); line-height: 1.8; }
.job-block { margin-bottom: 10px; }
.job-block:last-child { margin-bottom: 0; }
.job-header { font-size: 0.85rem; margin-bottom: 4px; }
.job-conclusion { font-size: 0.8rem; font-weight: 400; opacity: 0.8; }
.steps-container { margin-left: 18px; border-left: 2px solid var(--border); padding-left: 10px; }
.step-row { font-size: 0.8rem; padding: 1px 0; color: var(--text-muted); }
.step-action { font-family: monospace; font-size: 0.78rem; color: #3730a3; }

/* Print */
@media print {
  header { background: #1e3a5f !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .section-nav { display: none; }
  .collapsible .section-toggle:not(.open) + .section-body { max-height: none; opacity: 1; }
  .repo-body { display: block !important; }
  .filter-input, .filter-buttons, .nav-btn, .toolbar { display: none; }
}
"""

# ---------------------------------------------------------------------------
# Embedded JS
# ---------------------------------------------------------------------------

_JS = """
/* ---- Collapsible sections ---- */
function toggleSection(heading) {
  heading.classList.toggle('open');
  var icon = heading.querySelector('.toggle-icon');
  if (icon) icon.classList.toggle('open');
}

function expandAllSections() {
  document.querySelectorAll('.section-toggle').forEach(function(h) {
    h.classList.add('open');
    var icon = h.querySelector('.toggle-icon');
    if (icon) icon.classList.add('open');
  });
  document.querySelectorAll('.repo-header').forEach(function(h) {
    h.classList.add('open');
  });
}

function collapseAllSections() {
  document.querySelectorAll('.section-toggle').forEach(function(h) {
    h.classList.remove('open');
    var icon = h.querySelector('.toggle-icon');
    if (icon) icon.classList.remove('open');
  });
  document.querySelectorAll('.repo-header').forEach(function(h) {
    h.classList.remove('open');
  });
}

function expandAllInContainer(container) {
  if (typeof container === 'string') container = document.getElementById(container);
  if (!container) return;
  container.querySelectorAll('.repo-header').forEach(function(h) { h.classList.add('open'); });
}

function collapseAllInContainer(container) {
  if (typeof container === 'string') container = document.getElementById(container);
  if (!container) return;
  container.querySelectorAll('.repo-header').forEach(function(h) { h.classList.remove('open'); });
}

/* ---- Repo toggle (accordion items) ---- */
function toggleRepo(header) {
  header.classList.toggle('open');
}

/* ---- Repo text + severity filter ---- */
function filterRepos() {
  var query = document.getElementById('repo-filter').value.toLowerCase();
  var sections = document.querySelectorAll('#repo-list .repo-section');
  sections.forEach(function(s) {
    var name = s.getAttribute('data-repo');
    var matchText = !query || name.indexOf(query) !== -1;
    var matchSev = activeSeverity === 'all' || (s.getAttribute('data-severities') || '').indexOf(activeSeverity) !== -1;
    s.style.display = (matchText && matchSev) ? '' : 'none';
  });
}

var activeSeverity = 'all';

function filterSeverity(sev, btn) {
  activeSeverity = sev;
  btn.closest('.filter-buttons').querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  filterRepos();
  // Also filter individual finding rows within expanded repos
  document.querySelectorAll('#repo-list .finding-row').forEach(function(row) {
    if (sev === 'all') {
      row.style.display = '';
    } else {
      row.style.display = row.getAttribute('data-severity') === sev ? '' : 'none';
    }
  });
}

/* ---- Generic table text filter ---- */
function filterTable(input, tableId) {
  var query = input.value.toLowerCase();
  var table = document.getElementById(tableId);
  if (!table) return;
  var rows = table.querySelectorAll('tbody tr');
  var visible = 0;
  rows.forEach(function(row) {
    // Skip rows hidden by other filters (data-period, data-severity)
    var text = row.textContent.toLowerCase();
    if (!query || text.indexOf(query) !== -1) {
      // Don't override period/severity filter — only hide text-non-matches
      if (!row.hasAttribute('data-filter-hidden')) {
        row.style.display = '';
        visible++;
      }
    } else {
      row.style.display = 'none';
    }
  });
}

/* ---- Filter collapsible items (teams) by text ---- */
function filterCollapsibles(input, container) {
  var query = input.value.toLowerCase();
  container.querySelectorAll('.repo-section').forEach(function(s) {
    var name = s.getAttribute('data-repo') || s.textContent.toLowerCase();
    s.style.display = (!query || name.indexOf(query) !== -1) ? '' : 'none';
  });
}

/* ---- IAM findings severity filter ---- */
function filterIAMSeverity(sev, btn) {
  btn.closest('.filter-buttons').querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  var table = document.getElementById('iam-findings-table');
  if (!table) return;
  table.querySelectorAll('tbody tr.finding-row').forEach(function(row) {
    if (sev === 'all') {
      row.style.display = '';
    } else {
      row.style.display = row.getAttribute('data-severity') === sev ? '' : 'none';
    }
  });
}

/* ---- Org settings severity filter ---- */
function filterOrgSeverity(sev, btn) {
  btn.closest('.filter-buttons').querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  var table = document.getElementById('org-settings-table');
  if (!table) return;
  table.querySelectorAll('tbody tr.finding-row').forEach(function(row) {
    if (sev === 'all') {
      row.style.display = '';
    } else {
      row.style.display = row.getAttribute('data-severity') === sev ? '' : 'none';
    }
  });
}

/* ---- Inactive members period filter ---- */
function filterInactive(period, btn) {
  btn.closest('.filter-buttons').querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  var table = document.getElementById('inactive-table');
  if (!table) return;
  table.querySelectorAll('tbody tr').forEach(function(row) {
    if (period === 'all') {
      row.style.display = '';
      row.removeAttribute('data-filter-hidden');
    } else {
      var rowPeriod = row.getAttribute('data-period');
      // 6m filter shows only 6m, 3m filter shows 3m+6m, 1m shows all
      var match = false;
      if (period === '6m') match = rowPeriod === '6m';
      else if (period === '3m') match = rowPeriod === '6m' || rowPeriod === '3m';
      else if (period === '1m') match = true;
      row.style.display = match ? '' : 'none';
      if (!match) row.setAttribute('data-filter-hidden', '1');
      else row.removeAttribute('data-filter-hidden');
    }
  });
}

/* ---- Column sorting ---- */
var sortState = {};

function sortTable(tableId, colIdx, dataType) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var tbody = table.querySelector('tbody');
  var rows = Array.from(tbody.querySelectorAll('tr'));

  // Determine direction
  var key = tableId + ':' + colIdx;
  var dir = sortState[key] === 'asc' ? 'desc' : 'asc';
  sortState[key] = dir;

  // Clear previous sort indicators
  table.querySelectorAll('.sort-icon').forEach(function(icon) {
    icon.className = 'sort-icon';
  });
  var th = table.querySelectorAll('thead th')[colIdx];
  if (th) {
    var icon = th.querySelector('.sort-icon');
    if (icon) icon.className = 'sort-icon ' + dir;
  }

  var sevOrder = {critical: 0, high: 1, medium: 2, low: 3, info: 4};

  rows.sort(function(a, b) {
    var aCell = a.cells[colIdx];
    var bCell = b.cells[colIdx];
    if (!aCell || !bCell) return 0;

    var aVal, bVal;
    if (dataType === 'num') {
      aVal = parseFloat(aCell.textContent) || 0;
      bVal = parseFloat(bCell.textContent) || 0;
    } else if (dataType === 'severity') {
      aVal = sevOrder[(aCell.textContent || '').trim().toLowerCase()] || 99;
      bVal = sevOrder[(bCell.textContent || '').trim().toLowerCase()] || 99;
    } else {
      aVal = (aCell.textContent || '').trim().toLowerCase();
      bVal = (bCell.textContent || '').trim().toLowerCase();
    }

    if (aVal < bVal) return dir === 'asc' ? -1 : 1;
    if (aVal > bVal) return dir === 'asc' ? 1 : -1;
    return 0;
  });

  rows.forEach(function(row) { tbody.appendChild(row); });
}

/* ---- Action Runs filters ---- */
var arConclusionFilter = 'all';

function filterActionRuns(type, value, btn) {
  if (type === 'conclusion') {
    arConclusionFilter = value;
    if (btn) {
      btn.closest('.filter-buttons').querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
    }
  }
  applyActionRunFilters();
}

function toggleRunDetail(rowId) {
  var detailRow = document.getElementById(rowId);
  if (!detailRow) return;
  var isVisible = detailRow.style.display !== 'none';
  detailRow.style.display = isVisible ? 'none' : '';
  // Toggle the expand button icon
  var mainRow = detailRow.previousElementSibling;
  if (mainRow) {
    var btn = mainRow.querySelector('.expand-btn');
    if (btn) {
      btn.classList.toggle('open');
      btn.innerHTML = isVisible ? '&#9654;' : '&#9660;';
    }
  }
}

function applyActionRunFilters() {
  var repoVal = (document.getElementById('ar-repo-filter') || {}).value || 'all';
  var wfVal = (document.getElementById('ar-workflow-filter') || {}).value || 'all';
  var textVal = ((document.getElementById('ar-text-filter') || {}).value || '').toLowerCase();
  var usesVal = ((document.getElementById('ar-uses-filter') || {}).value || '').toLowerCase().trim();
  var dateFrom = (document.getElementById('ar-date-from') || {}).value || '';
  var dateTo = (document.getElementById('ar-date-to') || {}).value || '';

  var clearBtn = document.getElementById('ar-uses-clear');
  if (clearBtn) clearBtn.style.display = usesVal ? 'inline-flex' : 'none';

  var rows = document.querySelectorAll('#action-runs-table tbody .action-run-row');
  var visibleCount = 0;
  rows.forEach(function(row) {
    var matchRepo = (repoVal === 'all' || row.getAttribute('data-repo') === repoVal);
    var matchConclusion = (arConclusionFilter === 'all' || row.getAttribute('data-conclusion') === arConclusionFilter);
    var matchWf = (wfVal === 'all' || row.getAttribute('data-workflow') === wfVal);
    var matchText = !textVal || row.textContent.toLowerCase().indexOf(textVal) !== -1;
    var matchUses = true;
    if (usesVal) {
      var actions = (row.getAttribute('data-actions') || '').toLowerCase().split('|');
      matchUses = actions.some(function(a) { return a.indexOf(usesVal) !== -1; });
    }
    var matchDate = true;
    var rowDate = row.getAttribute('data-date') || '';
    if (dateFrom && rowDate) matchDate = rowDate >= dateFrom;
    if (matchDate && dateTo && rowDate) matchDate = rowDate <= dateTo;

    var visible = matchRepo && matchConclusion && matchWf && matchText && matchUses && matchDate;
    row.style.display = visible ? '' : 'none';
    if (visible) visibleCount++;
    var detailRow = row.nextElementSibling;
    if (detailRow && detailRow.classList.contains('run-detail-row')) {
      if (!visible) detailRow.style.display = 'none';
    }
  });

  var countEl = document.getElementById('ar-uses-match-count');
  if (countEl) {
    countEl.textContent = usesVal ? visibleCount + ' run' + (visibleCount !== 1 ? 's' : '') + ' matched' : '';
  }
}

function clearUsesFilter() {
  var inp = document.getElementById('ar-uses-filter');
  if (inp) { inp.value = ''; }
  applyActionRunFilters();
}

/* ---- Init: open sections by default, auto-expand critical/high repos ---- */
document.addEventListener('DOMContentLoaded', function() {
  // All sections start open
  document.querySelectorAll('.section-toggle').forEach(function(h) {
    h.classList.add('open');
    var icon = h.querySelector('.toggle-icon');
    if (icon) icon.classList.add('open');
  });

  // Auto-expand repos with critical/high findings
  document.querySelectorAll('#repo-list .repo-section').forEach(function(s) {
    var sevs = s.getAttribute('data-severities') || '';
    if (sevs.indexOf('critical') !== -1 || sevs.indexOf('high') !== -1) {
      s.querySelector('.repo-header').classList.add('open');
    }
  });

  // Highlight active nav link on scroll
  var sections = document.querySelectorAll('[id^="sec-"]');
  var navLinks = document.querySelectorAll('.nav-link');
  if (sections.length && navLinks.length && 'IntersectionObserver' in window) {
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          navLinks.forEach(function(l) { l.classList.remove('active-nav'); });
          var link = document.querySelector('.nav-link[href="#' + entry.target.id + '"]');
          if (link) link.classList.add('active-nav');
        }
      });
    }, { rootMargin: '-80px 0px -70% 0px' });
    sections.forEach(function(s) { observer.observe(s); });
  }
});
"""
