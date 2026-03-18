"""Tests for CIS GitHub Benchmark report generation."""

from pipeaudit.cis_report import generate_cis_report, _CIS_CONTROLS, _RULE_TO_CIS


def _make_report(repo_findings=None, identity_findings=None, org_findings=None):
    """Build a minimal audit report dict."""
    return {
        "audit_metadata": {
            "platform": "github",
            "organization": "test-org",
            "timestamp": "2026-03-18T00:00:00Z",
            "total_repos_scanned": 1,
            "total_workflows_scanned": 1,
            "total_findings": 0,
            "findings_by_severity": {},
        },
        "repos": [
            {
                "repo": "test-org/repo1",
                "branch": "main",
                "findings": repo_findings or [],
            }
        ],
        "identity": {"findings": identity_findings or []},
        "org_settings": {"findings": org_findings or []},
    }


class TestCISReportStructure:
    def test_top_level_keys(self):
        report = _make_report()
        cis = generate_cis_report(report)
        assert cis["id"] == "cis-github-benchmark"
        assert cis["version"] == "1.2.0"
        assert cis["node_type"] == "github"
        assert "tests" in cis
        assert "total_pass" in cis
        assert "total_fail" in cis
        assert "total_warn" in cis

    def test_totals_sum_to_120(self):
        report = _make_report()
        cis = generate_cis_report(report)
        total = cis["total_pass"] + cis["total_fail"] + cis["total_warn"] + cis["total_info"]
        assert total == 120

    def test_groups_are_sections(self):
        report = _make_report()
        cis = generate_cis_report(report)
        sections = [g["section"] for g in cis["tests"]]
        assert "1.1" in sections
        assert "1.2" in sections
        assert "5.2" in sections

    def test_group_counts_consistent(self):
        report = _make_report()
        cis = generate_cis_report(report)
        for group in cis["tests"]:
            results = group["results"]
            assert group["pass"] == sum(1 for r in results if r["status"] == "PASS")
            assert group["fail"] == sum(1 for r in results if r["status"] == "FAIL")
            assert group["warn"] == sum(1 for r in results if r["status"] == "WARN")


class TestCISMapping:
    def test_failing_rule_triggers_cis_fail(self):
        """BPR004 maps to CIS 1.1.4 — a finding should produce FAIL."""
        report = _make_report(repo_findings=[
            {
                "rule_id": "BPR004",
                "severity": "medium",
                "title": "Stale reviews not dismissed",
                "description": "Test finding",
            }
        ])
        cis = generate_cis_report(report)
        # Find CIS 1.1.4
        check = _find_check(cis, "1.1.4")
        assert check is not None
        assert check["status"] == "FAIL"

    def test_no_finding_means_pass(self):
        """CIS 1.1.4 mapped to BPR004 — no BPR004 finding → PASS."""
        report = _make_report()
        cis = generate_cis_report(report)
        check = _find_check(cis, "1.1.4")
        assert check is not None
        assert check["status"] == "PASS"

    def test_inherently_pass_control(self):
        """CIS 1.1.1 is inherently PASS (code tracked in VCS)."""
        report = _make_report()
        cis = generate_cis_report(report)
        check = _find_check(cis, "1.1.1")
        assert check is not None
        assert check["status"] == "PASS"

    def test_unmapped_control_is_warn(self):
        """CIS 1.1.2 has no pipeaudit rule mapping — should be WARN."""
        report = _make_report()
        cis = generate_cis_report(report)
        check = _find_check(cis, "1.1.2")
        assert check is not None
        assert check["status"] == "WARN"

    def test_org_finding_triggers_cis_fail(self):
        """ORG001 maps to CIS 1.3.5 — org finding should produce FAIL."""
        report = _make_report(org_findings=[
            {
                "rule_id": "ORG001",
                "severity": "high",
                "title": "2FA not required",
            }
        ])
        cis = generate_cis_report(report)
        check = _find_check(cis, "1.3.5")
        assert check is not None
        assert check["status"] == "FAIL"

    def test_identity_finding_triggers_cis_fail(self):
        """IAM001 maps to CIS 1.3.3 — identity finding should produce FAIL."""
        report = _make_report(identity_findings=[
            {
                "rule_id": "IAM001",
                "severity": "high",
                "title": "Too many org admins",
            }
        ])
        cis = generate_cis_report(report)
        check = _find_check(cis, "1.3.3")
        assert check is not None
        assert check["status"] == "FAIL"


    def test_new_rules_mapped(self):
        """Verify new automated rules (BPR011, BPR012, SEC006-008, ORG006-007) are mapped."""
        for rule_id in ("BPR011", "BPR012", "SEC006", "SEC007", "SEC008", "ORG006", "ORG007"):
            assert rule_id in _RULE_TO_CIS, f"{rule_id} not in _RULE_TO_CIS"

    def test_sec006_inactive_branches_maps_to_1_1_8(self):
        """SEC006 should map to CIS 1.1.8 (inactive branches)."""
        report = _make_report(repo_findings=[
            {"rule_id": "SEC006", "severity": "low", "title": "Inactive branches"}
        ])
        cis = generate_cis_report(report)
        check = _find_check(cis, "1.1.8")
        assert check is not None
        assert check["status"] == "FAIL"

    def test_sec007_code_scanning_maps_to_1_5_4(self):
        """SEC007 should map to CIS 1.5.4 (code vulnerability scanners)."""
        report = _make_report(repo_findings=[
            {"rule_id": "SEC007", "severity": "medium", "title": "No code scanning"}
        ])
        cis = generate_cis_report(report)
        check = _find_check(cis, "1.5.4")
        assert check is not None
        assert check["status"] == "FAIL"

    def test_org006_repo_creation_maps_to_1_2_2(self):
        """ORG006 should map to CIS 1.2.2."""
        report = _make_report(org_findings=[
            {"rule_id": "ORG006", "severity": "medium", "title": "Repo creation unrestricted"}
        ])
        cis = generate_cis_report(report)
        check = _find_check(cis, "1.2.2")
        assert check is not None
        assert check["status"] == "FAIL"


class TestCISCheckFormat:
    """Verify kube-bench compatible check format."""

    def test_check_has_required_fields(self):
        report = _make_report()
        cis = generate_cis_report(report)
        check = cis["tests"][0]["results"][0]
        required_fields = [
            "test_number", "test_desc", "audit", "type",
            "remediation", "test_info", "status", "actual_value",
            "scored", "expected_result",
        ]
        for field in required_fields:
            assert field in check, f"Missing field: {field}"

    def test_status_values_valid(self):
        report = _make_report()
        cis = generate_cis_report(report)
        valid = {"PASS", "FAIL", "WARN", "INFO"}
        for group in cis["tests"]:
            for check in group["results"]:
                assert check["status"] in valid


class TestCISCatalog:
    def test_120_controls(self):
        assert len(_CIS_CONTROLS) == 120

    def test_all_mapped_rules_exist_in_catalog(self):
        cis_ids = {c["id"] for c in _CIS_CONTROLS}
        for rule_id, cis_list in _RULE_TO_CIS.items():
            for cis_id in cis_list:
                assert cis_id in cis_ids, f"Rule {rule_id} maps to unknown CIS {cis_id}"


def _find_check(cis: dict, cis_id: str) -> dict | None:
    for group in cis["tests"]:
        for check in group["results"]:
            if check["test_number"] == cis_id:
                return check
    return None
