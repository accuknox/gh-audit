"""Tests for Azure DevOps branch policy rules (ABP001-ABP007)."""

from pipeaudit.azure.branch_policies import (
    audit_branch_policies,
    POLICY_MINIMUM_REVIEWERS,
    POLICY_REQUIRED_REVIEWERS,
    POLICY_BUILD_VALIDATION,
    POLICY_COMMENT_RESOLUTION,
    POLICY_MERGE_STRATEGY,
)


def _make_policy(type_id, settings=None, repo_id="r1", ref_name="refs/heads/main"):
    return {
        "isEnabled": True,
        "type": {"id": type_id},
        "settings": {
            **(settings or {}),
            "scope": [{"repositoryId": repo_id, "refName": ref_name}],
        },
    }


class TestABP001:
    def test_no_policies_at_all(self):
        findings = audit_branch_policies([], "proj", "r1", "proj/repo", "main")
        abp001 = [f for f in findings if f["rule_id"] == "ABP001"]
        assert len(abp001) == 1
        assert abp001[0]["severity"] == "high"

    def test_has_policies(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 2})]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp001 = [f for f in findings if f["rule_id"] == "ABP001"]
        assert len(abp001) == 0


class TestABP002:
    def test_no_minimum_reviewer_policy(self):
        policies = [_make_policy(POLICY_BUILD_VALIDATION)]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp002 = [f for f in findings if f["rule_id"] == "ABP002"]
        assert len(abp002) == 1

    def test_minimum_reviewers_zero(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 0})]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp002 = [f for f in findings if f["rule_id"] == "ABP002"]
        assert len(abp002) == 1

    def test_minimum_reviewers_sufficient(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 2})]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp002 = [f for f in findings if f["rule_id"] == "ABP002"]
        assert len(abp002) == 0


class TestABP003:
    def test_no_required_reviewers(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 1})]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp003 = [f for f in findings if f["rule_id"] == "ABP003"]
        assert len(abp003) == 1
        assert abp003[0]["severity"] == "medium"

    def test_has_required_reviewers(self):
        policies = [
            _make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 1}),
            _make_policy(POLICY_REQUIRED_REVIEWERS),
        ]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp003 = [f for f in findings if f["rule_id"] == "ABP003"]
        assert len(abp003) == 0


class TestABP004:
    def test_self_approval_allowed(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {
            "minimumApproverCount": 1,
            "creatorVoteCounts": True,
        })]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp004 = [f for f in findings if f["rule_id"] == "ABP004"]
        assert len(abp004) == 1

    def test_self_approval_disabled(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {
            "minimumApproverCount": 1,
            "creatorVoteCounts": False,
        })]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp004 = [f for f in findings if f["rule_id"] == "ABP004"]
        assert len(abp004) == 0


class TestABP005:
    def test_no_build_validation(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 1})]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp005 = [f for f in findings if f["rule_id"] == "ABP005"]
        assert len(abp005) == 1

    def test_has_build_validation(self):
        policies = [
            _make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 1}),
            _make_policy(POLICY_BUILD_VALIDATION),
        ]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp005 = [f for f in findings if f["rule_id"] == "ABP005"]
        assert len(abp005) == 0


class TestABP006:
    def test_no_comment_resolution(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 1})]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp006 = [f for f in findings if f["rule_id"] == "ABP006"]
        assert len(abp006) == 1
        assert abp006[0]["severity"] == "low"


class TestABP007:
    def test_no_merge_strategy(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 1})]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp007 = [f for f in findings if f["rule_id"] == "ABP007"]
        assert len(abp007) == 1
        assert abp007[0]["severity"] == "low"


class TestPolicyFiltering:
    def test_disabled_policy_ignored(self):
        policies = [{
            "isEnabled": False,
            "type": {"id": POLICY_MINIMUM_REVIEWERS},
            "settings": {
                "minimumApproverCount": 2,
                "scope": [{"repositoryId": "r1", "refName": "refs/heads/main"}],
            },
        }]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp001 = [f for f in findings if f["rule_id"] == "ABP001"]
        assert len(abp001) == 1  # no valid policies → ABP001 triggers

    def test_different_branch_ignored(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 2},
                                 repo_id="r1", ref_name="refs/heads/develop")]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp001 = [f for f in findings if f["rule_id"] == "ABP001"]
        assert len(abp001) == 1  # policy doesn't apply to main

    def test_different_repo_ignored(self):
        policies = [_make_policy(POLICY_MINIMUM_REVIEWERS, {"minimumApproverCount": 2},
                                 repo_id="other-repo")]
        findings = audit_branch_policies(policies, "proj", "r1", "proj/repo", "main")
        abp001 = [f for f in findings if f["rule_id"] == "ABP001"]
        assert len(abp001) == 1
