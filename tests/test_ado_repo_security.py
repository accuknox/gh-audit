"""Tests for Azure DevOps repository security rules (ASC001-ASC004)."""

from unittest.mock import MagicMock

from gh_auditor.azure.repo_security import audit_repo_security


def _make_client(file_exists=False):
    client = MagicMock()
    client.get_file_content.return_value = "# Security Policy" if file_exists else None
    return client


def _make_repo_meta(adv_security=None, forking=False, visibility="private"):
    return {
        "id": "r1",
        "name": "repo1",
        "advancedSecurity": adv_security or {},
        "isForkingAllowed": forking,
        "project": {"visibility": visibility},
    }


class TestASC001:
    def test_no_secret_scanning(self):
        client = _make_client()
        findings = audit_repo_security(
            client, "proj", "r1", "proj/repo", _make_repo_meta(), "main",
        )
        asc001 = [f for f in findings if f["rule_id"] == "ASC001"]
        assert len(asc001) == 1
        assert asc001[0]["severity"] == "high"

    def test_secret_scanning_enabled(self):
        client = _make_client()
        meta = _make_repo_meta(adv_security={
            "secretScanning": {"status": "enabled"},
            "dependencyScanning": {"status": "enabled"},
        })
        findings = audit_repo_security(client, "proj", "r1", "proj/repo", meta, "main")
        asc001 = [f for f in findings if f["rule_id"] == "ASC001"]
        assert len(asc001) == 0


class TestASC002:
    def test_no_dependency_scanning(self):
        client = _make_client()
        findings = audit_repo_security(
            client, "proj", "r1", "proj/repo", _make_repo_meta(), "main",
        )
        asc002 = [f for f in findings if f["rule_id"] == "ASC002"]
        assert len(asc002) == 1
        assert asc002[0]["severity"] == "medium"

    def test_dependency_scanning_enabled(self):
        client = _make_client()
        meta = _make_repo_meta(adv_security={
            "secretScanning": {"status": "enabled"},
            "dependencyScanning": {"status": "enabled"},
        })
        findings = audit_repo_security(client, "proj", "r1", "proj/repo", meta, "main")
        asc002 = [f for f in findings if f["rule_id"] == "ASC002"]
        assert len(asc002) == 0


class TestASC003:
    def test_forking_allowed_public(self):
        client = _make_client()
        meta = _make_repo_meta(forking=True, visibility="public")
        findings = audit_repo_security(client, "proj", "r1", "proj/repo", meta, "main")
        asc003 = [f for f in findings if f["rule_id"] == "ASC003"]
        assert len(asc003) == 1

    def test_forking_allowed_private_no_finding(self):
        client = _make_client()
        meta = _make_repo_meta(forking=True, visibility="private")
        findings = audit_repo_security(client, "proj", "r1", "proj/repo", meta, "main")
        asc003 = [f for f in findings if f["rule_id"] == "ASC003"]
        assert len(asc003) == 0

    def test_forking_not_allowed(self):
        client = _make_client()
        meta = _make_repo_meta(forking=False, visibility="public")
        findings = audit_repo_security(client, "proj", "r1", "proj/repo", meta, "main")
        asc003 = [f for f in findings if f["rule_id"] == "ASC003"]
        assert len(asc003) == 0


class TestASC004:
    def test_no_security_md(self):
        client = _make_client(file_exists=False)
        findings = audit_repo_security(
            client, "proj", "r1", "proj/repo", _make_repo_meta(), "main",
        )
        asc004 = [f for f in findings if f["rule_id"] == "ASC004"]
        assert len(asc004) == 1
        assert asc004[0]["severity"] == "low"

    def test_has_security_md(self):
        client = _make_client(file_exists=True)
        findings = audit_repo_security(
            client, "proj", "r1", "proj/repo", _make_repo_meta(), "main",
        )
        asc004 = [f for f in findings if f["rule_id"] == "ASC004"]
        assert len(asc004) == 0
