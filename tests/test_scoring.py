"""Tests for the scoring module."""

from pipeaudit.scoring import (
    grade_for_score,
    score_repo,
    score_org,
    enrich_report,
    _penalty,
    SEVERITY_WEIGHTS,
    ORG_CATEGORY_PENALTY_CAP,
)


class TestGradeForScore:
    def test_perfect_score(self):
        assert grade_for_score(100) == "A+"

    def test_grade_boundaries(self):
        assert grade_for_score(97) == "A+"
        assert grade_for_score(96) == "A"
        assert grade_for_score(93) == "A"
        assert grade_for_score(92) == "A-"
        assert grade_for_score(90) == "A-"
        assert grade_for_score(89) == "B+"
        assert grade_for_score(87) == "B+"
        assert grade_for_score(86) == "B"
        assert grade_for_score(83) == "B"
        assert grade_for_score(82) == "B-"
        assert grade_for_score(80) == "B-"
        assert grade_for_score(79) == "C+"
        assert grade_for_score(77) == "C+"
        assert grade_for_score(76) == "C"
        assert grade_for_score(73) == "C"
        assert grade_for_score(72) == "C-"
        assert grade_for_score(70) == "C-"
        assert grade_for_score(69) == "D"
        assert grade_for_score(60) == "D"
        assert grade_for_score(59) == "F"
        assert grade_for_score(0) == "F"


class TestPenalty:
    def test_no_findings(self):
        assert _penalty([]) == 0.0

    def test_single_finding(self):
        assert _penalty([{"rule_id": "GHA001", "severity": "high"}]) == 7.0

    def test_same_rule_diminishing_returns(self):
        """Multiple instances of the same rule cap at 2x base weight."""
        # GHA003 (high=7): 1 instance = 7, extras capped at +7 = 14 max
        findings = [{"rule_id": "GHA003", "severity": "high"}] * 50
        result = _penalty(findings)
        assert result == 14.0  # 7 base + min(49, 7) extra = 14

    def test_same_rule_few_extras(self):
        """Fewer extras than cap — all count."""
        findings = [{"rule_id": "GHA003", "severity": "high"}] * 3
        result = _penalty(findings)
        assert result == 9.0  # 7 base + 2 extras

    def test_different_rules_independent(self):
        """Different rules are penalized independently."""
        findings = [
            {"rule_id": "GHA001", "severity": "high"},
            {"rule_id": "GHA002", "severity": "high"},
        ]
        assert _penalty(findings) == 14.0  # 7 + 7

    def test_mixed_severities(self):
        findings = [
            {"rule_id": "SEC001", "severity": "high"},     # 7
            {"rule_id": "SEC004", "severity": "medium"},    # 4
            {"rule_id": "SEC005", "severity": "low"},       # 2
        ]
        assert _penalty(findings) == 13.0


class TestScoreRepo:
    def test_no_findings(self):
        result = score_repo({"findings": []})
        assert result["score"] == 100.0
        assert result["grade"] == "A+"
        assert result["penalty"] == 0.0
        assert result["unique_rules"] == 0

    def test_one_critical(self):
        result = score_repo({"findings": [{"rule_id": "BPR005", "severity": "critical"}]})
        assert result["score"] == 90.0
        assert result["penalty"] == 10.0
        assert result["grade"] == "A-"

    def test_many_same_rule_capped(self):
        """50 instances of the same high rule should cap at 2x weight."""
        findings = [{"rule_id": "GHA003", "severity": "high"}] * 50
        result = score_repo({"findings": findings})
        assert result["penalty"] == 14.0  # 7 + 7
        assert result["score"] == 86.0
        assert result["grade"] == "B"
        assert result["unique_rules"] == 1

    def test_baseline_unprotected_repo(self):
        """A repo with typical baseline findings (no protection, no security files)."""
        findings = [
            {"rule_id": "BPR001", "severity": "high"},     # 7
            {"rule_id": "BPR003", "severity": "high"},     # 7
            {"rule_id": "SEC001", "severity": "high"},     # 7
            {"rule_id": "SEC002", "severity": "high"},     # 7
            {"rule_id": "SEC004", "severity": "medium"},   # 4
            {"rule_id": "SEC005", "severity": "low"},      # 2
        ]
        result = score_repo({"findings": findings})
        assert result["penalty"] == 34.0
        assert result["score"] == 66.0
        assert result["grade"] == "D"

    def test_info_findings_low_impact(self):
        findings = [{"rule_id": f"INFO{i}", "severity": "info"} for i in range(10)]
        result = score_repo({"findings": findings})
        assert result["score"] == 95.0  # 10 unique info rules × 0.5 = 5
        assert result["grade"] == "A"


class TestScoreOrg:
    def test_no_repos_no_findings(self):
        report = {"repos": [], "audit_metadata": {"organization": "test"}}
        result = score_org(report)
        assert result["score"] == 100.0
        assert result["grade"] == "A+"

    def test_single_clean_repo(self):
        report = {
            "repos": [{"repo": "org/clean", "findings": []}],
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        assert result["score"] == 100.0
        assert result["repo_scores"]["org/clean"]["score"] == 100.0

    def test_org_penalty_deducted(self):
        report = {
            "repos": [{"repo": "org/r1", "findings": []}],
            "org_settings": {
                "findings": [{"rule_id": "ORG001", "severity": "critical"}],
            },
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        assert result["repo_average"] == 100.0
        assert result["org_penalty"] == 10.0
        assert result["score"] == 90.0

    def test_identity_penalty_deducted(self):
        report = {
            "repos": [{"repo": "org/r1", "findings": []}],
            "identity": {
                "findings": [
                    {"rule_id": "IAM001", "severity": "high"},
                    {"rule_id": "IAM003", "severity": "medium"},
                ],
            },
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        assert result["identity_penalty"] == 11.0  # 7 + 4
        assert result["score"] == 89.0

    def test_org_penalty_capped(self):
        """Each org-level penalty category is capped at ORG_CATEGORY_PENALTY_CAP."""
        report = {
            "repos": [{"repo": "org/r1", "findings": []}],
            "org_settings": {
                "findings": [
                    {"rule_id": "ORG001", "severity": "critical"},  # 10
                    {"rule_id": "ORG002", "severity": "high"},      # 7
                    {"rule_id": "ORG003", "severity": "high"},      # 7
                ],
            },
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        # Raw penalty would be 24, but capped at 15
        assert result["org_penalty"] == ORG_CATEGORY_PENALTY_CAP
        assert result["score"] == 100.0 - ORG_CATEGORY_PENALTY_CAP

    def test_identity_penalty_capped(self):
        """Identity penalty is capped at ORG_CATEGORY_PENALTY_CAP."""
        report = {
            "repos": [{"repo": "org/r1", "findings": []}],
            "identity": {
                "findings": [
                    {"rule_id": f"IAM00{i}", "severity": "high"}
                    for i in range(5)  # 5 × 7 = 35 raw
                ],
            },
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        assert result["identity_penalty"] == ORG_CATEGORY_PENALTY_CAP

    def test_apps_tokens_penalty_capped(self):
        """Apps & tokens penalty is capped at ORG_CATEGORY_PENALTY_CAP."""
        report = {
            "repos": [{"repo": "org/r1", "findings": []}],
            "apps_and_tokens": {
                "findings": [
                    {"rule_id": "APP002", "severity": "high"},
                    {"rule_id": "APP003", "severity": "high"},
                    {"rule_id": "PAT001", "severity": "high"},
                    {"rule_id": "PAT003", "severity": "high"},
                ],
            },
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        # Raw: 4 × 7 = 28, capped at 15
        assert result["apps_tokens_penalty"] == ORG_CATEGORY_PENALTY_CAP

    def test_all_categories_capped_independently(self):
        """All three org-level categories capped → max deduction = 3 × cap."""
        report = {
            "repos": [{"repo": "org/r1", "findings": []}],
            "org_settings": {
                "findings": [
                    {"rule_id": "ORG001", "severity": "critical"},
                    {"rule_id": "ORG002", "severity": "critical"},
                ],
            },
            "identity": {
                "findings": [
                    {"rule_id": f"IAM00{i}", "severity": "high"}
                    for i in range(5)
                ],
            },
            "apps_and_tokens": {
                "findings": [
                    {"rule_id": "APP002", "severity": "high"},
                    {"rule_id": "APP003", "severity": "high"},
                    {"rule_id": "PAT001", "severity": "high"},
                ],
            },
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        assert result["org_penalty"] == ORG_CATEGORY_PENALTY_CAP
        assert result["identity_penalty"] == ORG_CATEGORY_PENALTY_CAP
        assert result["apps_tokens_penalty"] == ORG_CATEGORY_PENALTY_CAP
        # 100 - 15 - 15 - 15 = 55
        assert result["score"] == 100.0 - 3 * ORG_CATEGORY_PENALTY_CAP

    def test_multiple_repos_averaged(self):
        report = {
            "repos": [
                {"repo": "org/clean", "findings": []},  # 100
                {"repo": "org/messy", "findings": [
                    {"rule_id": "BPR001", "severity": "critical"},
                ]},  # 90
            ],
            "audit_metadata": {"organization": "test"},
        }
        result = score_org(report)
        assert result["repo_average"] == 95.0
        assert result["score"] == 95.0


class TestEnrichReport:
    def test_enriches_report_in_place(self):
        report = {
            "repos": [
                {"repo": "org/r1", "findings": [
                    {"rule_id": "GHA001", "severity": "high"},
                ]},
                {"repo": "org/r2", "findings": []},
            ],
            "audit_metadata": {
                "organization": "test",
                "total_findings": 1,
                "findings_by_severity": {"high": 1},
            },
        }
        enrich_report(report)

        assert "org_score" in report["audit_metadata"]
        assert "score" in report["audit_metadata"]["org_score"]
        assert "grade" in report["audit_metadata"]["org_score"]

        assert report["repos"][0]["score"]["score"] == 93.0  # 100 - 7
        assert report["repos"][0]["score"]["grade"] == "A"
        assert report["repos"][1]["score"]["score"] == 100.0
        assert report["repos"][1]["score"]["grade"] == "A+"

        org = report["audit_metadata"]["org_score"]
        assert org["repo_average"] == 96.5  # (93 + 100) / 2
        assert org["score"] == 96.5
