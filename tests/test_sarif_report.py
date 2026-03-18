"""Tests for SARIF v2.1.0 report generation."""

from pipeaudit.sarif_report import (
    generate_sarif_report,
    SARIF_VERSION,
    SARIF_SCHEMA,
    SEVERITY_TO_SARIF_LEVEL,
    SEVERITY_TO_SCORE,
    TOOL_NAME,
)


def _minimal_report():
    return {
        "audit_metadata": {
            "organization": "testorg",
            "timestamp": "2026-01-01T00:00:00Z",
            "total_repos_scanned": 1,
            "total_workflows_scanned": 2,
            "total_findings": 1,
        },
        "repos": [],
        "identity": {"findings": []},
    }


def _report_with_workflow_finding():
    report = _minimal_report()
    report["repos"] = [
        {
            "repo": "testorg/my-repo",
            "branch": "main",
            "visibility": "public",
            "findings": [
                {
                    "rule_id": "GHA002",
                    "severity": "high",
                    "title": "Script injection",
                    "description": "Untrusted input in run block.",
                    "workflow_file": "ci.yml",
                    "job": "build",
                    "step": "Run tests",
                    "line_hint": "${{ github.event.issue.title }}",
                },
            ],
        },
    ]
    return report


def _report_with_identity_finding():
    report = _minimal_report()
    report["identity"] = {
        "findings": [
            {
                "rule_id": "IAM001",
                "severity": "high",
                "title": "Organization has 5 admins",
                "description": "Too many admins.",
                "users": ["admin-0", "admin-1", "admin-2", "admin-3", "admin-4"],
            },
        ],
    }
    return report


class TestSarifStructure:
    def test_schema_and_version(self):
        sarif = generate_sarif_report(_minimal_report())
        assert sarif["$schema"] == SARIF_SCHEMA
        assert sarif["version"] == SARIF_VERSION

    def test_has_single_run(self):
        sarif = generate_sarif_report(_minimal_report())
        assert len(sarif["runs"]) == 1

    def test_tool_info(self):
        sarif = generate_sarif_report(_minimal_report())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == TOOL_NAME
        assert "version" in driver
        assert "informationUri" in driver
        assert "rules" in driver

    def test_empty_report_has_no_results(self):
        sarif = generate_sarif_report(_minimal_report())
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_invocations(self):
        sarif = generate_sarif_report(_minimal_report())
        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True
        assert invocations[0]["properties"]["organization"] == "testorg"


class TestWorkflowFindings:
    def test_workflow_finding_becomes_result(self):
        sarif = generate_sarif_report(_report_with_workflow_finding())
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "GHA002/ScriptInjection"

    def test_severity_mapping(self):
        sarif = generate_sarif_report(_report_with_workflow_finding())
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"  # high -> error

    def test_location_has_artifact_uri(self):
        sarif = generate_sarif_report(_report_with_workflow_finding())
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert "physicalLocation" in loc
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert "ci.yml" in uri
        assert "testorg/my-repo" in uri

    def test_logical_locations(self):
        sarif = generate_sarif_report(_report_with_workflow_finding())
        logical = sarif["runs"][0]["results"][0]["locations"][0]["logicalLocations"]
        kinds = [l["kind"] for l in logical]
        assert "namespace" in kinds   # repo
        assert "module" in kinds      # workflow file
        assert "function" in kinds    # job
        assert "member" in kinds      # step

    def test_properties(self):
        sarif = generate_sarif_report(_report_with_workflow_finding())
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["repository"] == "testorg/my-repo"
        assert props["branch"] == "main"
        assert props["visibility"] == "public"
        assert props["severity"] == "high"

    def test_rule_descriptor_created(self):
        sarif = generate_sarif_report(_report_with_workflow_finding())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "GHA002/ScriptInjection"
        assert rules[0]["name"] == "ScriptInjection"
        assert "security-severity" in rules[0]["properties"]
        assert "github-actions" in rules[0]["properties"]["tags"]

    def test_line_hint_in_properties(self):
        sarif = generate_sarif_report(_report_with_workflow_finding())
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["expressionHint"] == "${{ github.event.issue.title }}"


class TestIdentityFindings:
    def test_identity_finding_becomes_result(self):
        sarif = generate_sarif_report(_report_with_identity_finding())
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "IAM001/TooManyOrgAdmins"

    def test_identity_finding_has_logical_location(self):
        sarif = generate_sarif_report(_report_with_identity_finding())
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert "logicalLocations" in loc
        assert loc["logicalLocations"][0]["kind"] == "namespace"

    def test_identity_users_in_properties(self):
        sarif = generate_sarif_report(_report_with_identity_finding())
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["category"] == "identity"
        assert len(props["users"]) == 5

    def test_identity_rule_tagged(self):
        sarif = generate_sarif_report(_report_with_identity_finding())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "identity" in rules[0]["properties"]["tags"]


class TestSeverityMappings:
    def test_all_severities_mapped_to_sarif_level(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in SEVERITY_TO_SARIF_LEVEL

    def test_all_severities_have_scores(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in SEVERITY_TO_SCORE
            assert float(SEVERITY_TO_SCORE[sev]) > 0

    def test_critical_maps_to_critical(self):
        assert SEVERITY_TO_SARIF_LEVEL["critical"] == "critical"

    def test_high_maps_to_error(self):
        assert SEVERITY_TO_SARIF_LEVEL["high"] == "error"

    def test_medium_maps_to_warning(self):
        assert SEVERITY_TO_SARIF_LEVEL["medium"] == "warning"

    def test_low_maps_to_note(self):
        assert SEVERITY_TO_SARIF_LEVEL["low"] == "note"

    def test_info_maps_to_none(self):
        assert SEVERITY_TO_SARIF_LEVEL["info"] == "none"
