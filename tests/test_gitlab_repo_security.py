"""Tests for GitLab repository security rules (GLS001-GLS004)."""

import base64

from unittest.mock import MagicMock

from pipeaudit.gitlab.repo_security import audit_repo_security


def _make_client(ci_content=None, files=None):
    """Create a mock client that returns specified file contents."""
    files = files or {}
    if ci_content is not None:
        files[".gitlab-ci.yml"] = ci_content

    client = MagicMock()

    def _get_file(project_id, path, ref):
        return files.get(path)

    client.get_file_content.side_effect = _get_file
    return client


class TestGLS001:
    def test_no_secret_detection(self):
        ci = "stages:\n  - test\ntest_job:\n  script: echo hello\n"
        client = _make_client(ci_content=ci)
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls001 = [f for f in findings if f["rule_id"] == "GLS001"]
        assert len(gls001) == 1

    def test_secret_detection_template(self):
        ci = "include:\n  - template: Security/Secret-Detection.gitlab-ci.yml\n"
        client = _make_client(ci_content=ci)
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls001 = [f for f in findings if f["rule_id"] == "GLS001"]
        assert len(gls001) == 0

    def test_secret_detection_job(self):
        ci = "secret_detection:\n  script: echo scanning\n"
        client = _make_client(ci_content=ci)
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls001 = [f for f in findings if f["rule_id"] == "GLS001"]
        assert len(gls001) == 0

    def test_no_ci_file(self):
        client = _make_client(ci_content=None)
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls001 = [f for f in findings if f["rule_id"] == "GLS001"]
        assert len(gls001) == 1


class TestGLS002:
    def test_no_dependency_scanning(self):
        ci = "stages:\n  - test\n"
        client = _make_client(ci_content=ci)
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls002 = [f for f in findings if f["rule_id"] == "GLS002"]
        assert len(gls002) == 1

    def test_dependency_scanning_present(self):
        ci = "include:\n  - template: Security/Dependency-Scanning.gitlab-ci.yml\n"
        client = _make_client(ci_content=ci)
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls002 = [f for f in findings if f["rule_id"] == "GLS002"]
        assert len(gls002) == 0


class TestGLS003:
    def test_no_security_md(self):
        client = _make_client(ci_content="stages: [test]\n")
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls003 = [f for f in findings if f["rule_id"] == "GLS003"]
        assert len(gls003) == 1

    def test_security_md_present(self):
        client = _make_client(
            ci_content="stages: [test]\n",
            files={"SECURITY.md": "# Security Policy\n"},
        )
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls003 = [f for f in findings if f["rule_id"] == "GLS003"]
        assert len(gls003) == 0


class TestGLS004:
    def test_dockerfile_no_container_scanning(self):
        client = _make_client(
            ci_content="stages: [test]\n",
            files={"Dockerfile": "FROM alpine\n"},
        )
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls004 = [f for f in findings if f["rule_id"] == "GLS004"]
        assert len(gls004) == 1

    def test_dockerfile_with_container_scanning(self):
        ci = "include:\n  - template: Security/Container-Scanning.gitlab-ci.yml\n"
        client = _make_client(
            ci_content=ci,
            files={"Dockerfile": "FROM alpine\n"},
        )
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls004 = [f for f in findings if f["rule_id"] == "GLS004"]
        assert len(gls004) == 0

    def test_no_dockerfile(self):
        ci = "stages: [test]\n"
        client = _make_client(ci_content=ci)
        findings = audit_repo_security(client, 1, "my-group/project-a", "main")
        gls004 = [f for f in findings if f["rule_id"] == "GLS004"]
        assert len(gls004) == 0
