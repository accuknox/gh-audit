"""Tests for Azure DevOps config loading."""

import os
import tempfile

import pytest
import yaml

from pipeaudit.config import load_config


def _write_config(data: dict) -> str:
    """Write a config dict to a temp YAML file and return path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        yaml.dump(data, f)
    return path


class TestAdoConfigLoading:
    def test_azure_platform_returns_ado_config(self, monkeypatch):
        monkeypatch.setenv("ADO_AUDIT_TOKEN", "test-pat")
        path = _write_config({
            "platform": "azure",
            "org": "my-ado-org",
            "projects": ["ProjectA", "ProjectB"],
        })
        try:
            config, output, verbosity, html, sarif, log, *_ = load_config(path)
            from pipeaudit.azure.ado_auditor import AdoAuditConfig
            assert isinstance(config, AdoAuditConfig)
            assert config.org == "my-ado-org"
            assert config.projects == ["ProjectA", "ProjectB"]
            assert config.token == "test-pat"
            assert config.platform == "azure"
        finally:
            os.unlink(path)

    def test_azure_config_falls_back_to_gh_token(self, monkeypatch):
        monkeypatch.delenv("ADO_AUDIT_TOKEN", raising=False)
        monkeypatch.setenv("GH_AUDIT_TOKEN", "fallback-token")
        path = _write_config({
            "platform": "azure",
            "org": "my-org",
        })
        try:
            config, *_ = load_config(path)
            assert config.token == "fallback-token"
        finally:
            os.unlink(path)

    def test_azure_config_no_token_raises(self, monkeypatch):
        monkeypatch.delenv("ADO_AUDIT_TOKEN", raising=False)
        monkeypatch.delenv("GH_AUDIT_TOKEN", raising=False)
        path = _write_config({
            "platform": "azure",
            "org": "my-org",
        })
        try:
            with pytest.raises(ValueError, match="ADO_AUDIT_TOKEN"):
                load_config(path)
        finally:
            os.unlink(path)

    def test_azure_config_with_all_options(self, monkeypatch):
        monkeypatch.setenv("ADO_AUDIT_TOKEN", "test-pat")
        path = _write_config({
            "platform": "azure",
            "org": "my-org",
            "projects": ["P1"],
            "repos": ["repo1"],
            "skip_identity": True,
            "skip_project_settings": True,
            "skip_pipeline_security": True,
            "include_disabled_repos": True,
            "updated_within_months": 6,
        })
        try:
            config, *_ = load_config(path)
            assert config.skip_identity is True
            assert config.skip_project_settings is True
            assert config.skip_pipeline_security is True
            assert config.include_disabled_repos is True
            assert config.updated_within_months == 6
        finally:
            os.unlink(path)

    def test_github_platform_still_works(self, monkeypatch):
        monkeypatch.setenv("GH_AUDIT_TOKEN", "gh-token")
        path = _write_config({
            "org": "my-gh-org",
        })
        try:
            config, *_ = load_config(path)
            from pipeaudit.auditor import AuditConfig
            assert isinstance(config, AuditConfig)
            assert config.org == "my-gh-org"
        finally:
            os.unlink(path)
