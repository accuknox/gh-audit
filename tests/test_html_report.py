"""Tests for HTML report generation."""

import os

from pipeaudit.html_report import generate_html_report, write_html_report


SAMPLE_REPORT = {
    "audit_metadata": {
        "organization": "test-org",
        "timestamp": "2026-03-10T12:00:00+00:00",
        "total_repos_scanned": 2,
        "total_workflows_scanned": 3,
        "total_findings": 5,
        "findings_by_severity": {
            "critical": 1,
            "high": 2,
            "medium": 1,
            "low": 1,
            "info": 0,
        },
    },
    "repos": [
        {
            "repo": "test-org/repo-a",
            "branch": "main",
            "visibility": "public",
            "archived": False,
            "fork": False,
            "default_branch": "main",
            "workflows_scanned": 2,
            "findings": [
                {
                    "rule_id": "GHA001",
                    "severity": "critical",
                    "title": "pull_request_target trigger detected",
                    "description": "Dangerous trigger in public repo.",
                    "workflow_file": "ci.yml",
                    "job": "build",
                },
                {
                    "rule_id": "GHA002",
                    "severity": "high",
                    "title": "Script injection via expression",
                    "description": "Untrusted input in run block.",
                    "workflow_file": "ci.yml",
                    "job": "build",
                    "step": "Echo title",
                    "line_hint": "${{ github.event.issue.title }}",
                },
                {
                    "rule_id": "GHA003",
                    "severity": "medium",
                    "title": "Action not pinned to SHA",
                    "description": "Uses tag ref instead of SHA.",
                    "workflow_file": "deploy.yml",
                    "job": "deploy",
                },
            ],
        },
        {
            "repo": "test-org/repo-b",
            "branch": "main",
            "visibility": "private",
            "archived": False,
            "fork": False,
            "default_branch": "main",
            "workflows_scanned": 1,
            "findings": [
                {
                    "rule_id": "GHA004",
                    "severity": "high",
                    "title": "No permissions declared",
                    "description": "Missing top-level permissions.",
                    "workflow_file": "build.yml",
                },
                {
                    "rule_id": "GHA009",
                    "severity": "low",
                    "title": "persist-credentials not disabled",
                    "description": "Token persisted in git config.",
                    "workflow_file": "build.yml",
                    "job": "test",
                    "step": "Checkout",
                },
            ],
        },
    ],
}


class TestGenerateHtmlReport:
    def test_produces_valid_html_structure(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "test-org" in html

    def test_contains_summary_numbers(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert ">2<" in html  # repos scanned
        assert ">3<" in html  # workflows scanned
        assert ">5<" in html  # total findings

    def test_contains_severity_counts(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert "CRITICAL" in html
        assert "HIGH" in html
        assert "MEDIUM" in html

    def test_contains_repo_names(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert "test-org/repo-a" in html
        assert "test-org/repo-b" in html

    def test_contains_finding_details(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert "GHA001" in html
        assert "pull_request_target trigger detected" in html
        assert "Script injection" in html
        assert "github.event.issue.title" in html

    def test_contains_rule_summary_table(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert "GHA002" in html
        assert "GHA003" in html
        assert "GHA004" in html

    def test_contains_visibility_badges(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert "PUBLIC" in html
        assert "PRIVATE" in html

    def test_contains_filter_controls(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert 'id="repo-filter"' in html
        assert "filterRepos" in html
        assert "filterSeverity" in html

    def test_self_contained_css_and_js(self):
        html = generate_html_report(SAMPLE_REPORT)

        assert "<style>" in html
        assert "<script>" in html
        # No external references
        assert "href=\"http" not in html
        assert "src=\"http" not in html


class TestWriteHtmlReport:
    def test_writes_file(self, tmp_path):
        path = str(tmp_path / "report.html")
        write_html_report(SAMPLE_REPORT, path)

        assert os.path.exists(path)
        content = open(path).read()
        assert "<!DOCTYPE html>" in content
        assert "test-org" in content

    def test_empty_report(self):
        empty_report = {
            "audit_metadata": {
                "organization": "empty-org",
                "timestamp": "2026-03-10T12:00:00+00:00",
                "total_repos_scanned": 0,
                "total_workflows_scanned": 0,
                "total_findings": 0,
                "findings_by_severity": {
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                },
            },
            "repos": [],
        }
        html = generate_html_report(empty_report)
        assert "empty-org" in html
        assert "No findings" in html


class TestInactiveMembersTable:
    def _report_with_identity(self, inactive_members):
        return {
            "audit_metadata": {
                "organization": "test-org",
                "timestamp": "2026-03-10T12:00:00+00:00",
                "total_repos_scanned": 0,
                "total_workflows_scanned": 0,
                "total_findings": 0,
                "findings_by_severity": {
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                },
            },
            "repos": [],
            "identity": {
                "org_members": [],
                "org_owners": ["owner-1"],
                "org_member_count": 5,
                "org_owner_count": 1,
                "inactive_members": inactive_members,
                "outside_collaborators": [],
                "pending_invitations": [],
                "teams": [],
                "repo_access": [],
                "findings": [],
            },
        }

    def test_renders_inactive_members_table(self):
        report = self._report_with_identity({
            "no_contributions_6_months": ["stale-user"],
            "no_contributions_3_months": ["user-3m"],
            "no_contributions_1_month": ["user-1m"],
        })
        html = generate_html_report(report)

        assert "Inactive Members (3)" in html
        assert "stale-user" in html
        assert "user-3m" in html
        assert "user-1m" in html
        assert "No Activity" in html

    def test_6m_user_has_all_checks(self):
        """A user inactive for 6 months should have checks in all three columns."""
        report = self._report_with_identity({
            "no_contributions_6_months": ["stale-user"],
            "no_contributions_3_months": [],
            "no_contributions_1_month": [],
        })
        html = generate_html_report(report)

        # 6m user row should have 3 check marks (&#10007;)
        assert "stale-user" in html
        assert html.count("&#10007;") >= 3  # at least 3 checks for the 6m user

    def test_no_inactive_shows_all_clear(self):
        report = self._report_with_identity({
            "no_contributions_6_months": [],
            "no_contributions_3_months": [],
            "no_contributions_1_month": [],
        })
        html = generate_html_report(report)

        assert "All members have recent contributions" in html

    def test_empty_inactive_key(self):
        """Missing inactive_members key should not crash."""
        report = self._report_with_identity({})
        html = generate_html_report(report)

        assert "Inactive Members" in html
        assert "All members have recent contributions" in html

    def test_inactive_period_filter_buttons(self):
        report = self._report_with_identity({
            "no_contributions_6_months": ["stale-user"],
            "no_contributions_3_months": ["user-3m"],
            "no_contributions_1_month": ["user-1m"],
        })
        html = generate_html_report(report)

        assert "filterInactive" in html
        assert "6 Months (1)" in html
        assert "3 Months (1)" in html
        assert "1 Month (1)" in html


class TestDynamicFeatures:
    """Tests for interactive/dynamic HTML report features."""

    def test_section_nav_present(self):
        html = generate_html_report(SAMPLE_REPORT)
        assert 'class="section-nav"' in html
        assert "Expand All" in html
        assert "Collapse All" in html

    def test_sections_are_collapsible(self):
        html = generate_html_report(SAMPLE_REPORT)
        assert "collapsible" in html
        assert "section-toggle" in html
        assert "toggleSection" in html

    def test_sortable_columns(self):
        html = generate_html_report(SAMPLE_REPORT)
        assert "sortTable" in html
        assert "sortable-th" in html
        assert "sort-icon" in html

    def test_rule_table_has_filter(self):
        html = generate_html_report(SAMPLE_REPORT)
        assert "rule-summary-table" in html
        assert "Filter rules..." in html

    def test_repo_section_expand_collapse_buttons(self):
        html = generate_html_report(SAMPLE_REPORT)
        assert "expandAllInContainer" in html
        assert "collapseAllInContainer" in html

    def test_nav_links_to_sections(self):
        html = generate_html_report(SAMPLE_REPORT)
        assert 'href="#sec-severity"' in html
        assert 'href="#sec-rules"' in html
        assert 'href="#sec-repos"' in html

    def test_identity_nav_links_present(self):
        report = dict(SAMPLE_REPORT)
        report["identity"] = {
            "org_members": [],
            "org_owners": ["admin"],
            "org_member_count": 1,
            "org_owner_count": 1,
            "inactive_members": {},
            "outside_collaborators": [{"login": "ext", "avatar_url": ""}],
            "pending_invitations": [],
            "teams": [{"name": "T", "slug": "t", "member_count": 1, "members": ["a"], "repos": [], "privacy": "closed", "permission": "push"}],
            "repo_access": [{"repo": "x/y", "admin_count": 1, "write_count": 0, "collaborators": [{"login": "a", "permission": "admin", "is_outside_collaborator": False}]}],
            "findings": [],
        }
        html = generate_html_report(report)
        assert 'href="#sec-owners"' in html
        assert 'href="#sec-outside"' in html
        assert 'href="#sec-teams"' in html
        assert 'href="#sec-access"' in html

    def test_iam_findings_severity_filter(self):
        report = dict(SAMPLE_REPORT)
        report["identity"] = {
            "org_members": [],
            "org_owners": ["admin"],
            "org_member_count": 1,
            "org_owner_count": 1,
            "inactive_members": {},
            "outside_collaborators": [],
            "pending_invitations": [],
            "teams": [],
            "repo_access": [],
            "findings": [
                {"rule_id": "IAM001", "severity": "high", "title": "Too many admins", "description": "x", "users": ["a", "b"]},
                {"rule_id": "IAM003", "severity": "medium", "title": "Outside collabs", "description": "y"},
            ],
        }
        html = generate_html_report(report)
        assert "filterIAMSeverity" in html
        assert "iam-severity-filters" in html
        assert "HIGH (1)" in html
        assert "MEDIUM (1)" in html

    def test_repo_access_sortable_and_filterable(self):
        report = dict(SAMPLE_REPORT)
        report["identity"] = {
            "org_members": [],
            "org_owners": ["admin"],
            "org_member_count": 1,
            "org_owner_count": 1,
            "inactive_members": {},
            "outside_collaborators": [],
            "pending_invitations": [],
            "teams": [],
            "repo_access": [{"repo": "x/y", "admin_count": 2, "write_count": 1, "collaborators": [{"login": "a", "permission": "admin", "is_outside_collaborator": False}]}],
            "findings": [],
        }
        html = generate_html_report(report)
        assert "repo-access-table" in html
        assert "Filter repositories..." in html
        assert "sortTable(&#x27;repo-access-table&#x27;" in html or "sortTable('repo-access-table'" in html

    def test_teams_filter_and_expand_collapse(self):
        report = dict(SAMPLE_REPORT)
        report["identity"] = {
            "org_members": [],
            "org_owners": ["admin"],
            "org_member_count": 1,
            "org_owner_count": 1,
            "inactive_members": {},
            "outside_collaborators": [],
            "pending_invitations": [],
            "teams": [{"name": "Alpha", "slug": "alpha", "member_count": 2, "members": ["a", "b"], "repos": [], "privacy": "closed", "permission": "push"}],
            "repo_access": [],
            "findings": [],
        }
        html = generate_html_report(report)
        assert "Filter teams..." in html
        assert "filterCollapsibles" in html
