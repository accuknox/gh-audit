"""Tests for config file loading."""

import os
import tempfile

import pytest
import yaml

from pipeaudit.config import load_config, CONFIG_TOKEN_ENV


def _write_config(tmp_path, data):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(data))
    return str(path)


class TestLoadConfig:
    def test_loads_minimal_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {"org": "my-org"})

        config, output, verbosity, html_output, sarif_output, log_file, cis_output = load_config(path)

        assert config.org == "my-org"
        assert config.token == "ghp_testtoken123"
        assert config.repo_specs == []
        assert config.include_archived is False
        assert config.include_forks is False
        assert output == "-"
        assert verbosity == 0
        assert html_output is None
        assert sarif_output is None
        assert log_file is None
        assert cis_output is None

    def test_loads_full_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {
            "org": "my-org",
            "output": "report.json",
            "verbosity": 2,
            "include_archived": True,
            "include_forks": True,
            "repos": [
                {"repo": "my-org/frontend", "branch": "main"},
                {"repo": "my-org/backend", "branch": "develop"},
                {"repo": "my-org/infra"},
            ],
        })

        config, output, verbosity, html_output, sarif_output, log_file, cis_output = load_config(path)

        assert config.org == "my-org"
        assert output == "report.json"
        assert verbosity == 2
        assert config.include_archived is True
        assert config.include_forks is True
        assert len(config.repo_specs) == 3
        assert config.repo_specs[0].owner == "my-org"
        assert config.repo_specs[0].repo == "frontend"
        assert config.repo_specs[0].branch == "main"
        assert config.repo_specs[1].branch == "develop"
        assert config.repo_specs[2].branch is None

    def test_repos_as_strings(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {
            "org": "my-org",
            "repos": ["my-org/frontend", "backend"],
        })

        config, *_ = load_config(path)

        assert len(config.repo_specs) == 2
        assert config.repo_specs[0].owner == "my-org"
        assert config.repo_specs[0].repo == "frontend"
        assert config.repo_specs[1].owner == "my-org"
        assert config.repo_specs[1].repo == "backend"

    def test_loads_html_output(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {
            "org": "my-org",
            "html_output": "report.html",
        })

        config, _, _, html_output, *_ = load_config(path)
        assert html_output == "report.html"

    def test_loads_sarif_output(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {
            "org": "my-org",
            "sarif_output": "report.sarif",
        })

        config, _, _, _, sarif_output, *_ = load_config(path)
        assert sarif_output == "report.sarif"

    def test_loads_regex_repo_spec(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {
            "org": "my-org",
            "repos": [
                {"repo": "frontend-.*", "regex": True},
                {"repo": "backend-api"},
            ],
        })

        config, *_ = load_config(path)

        assert len(config.repo_specs) == 2
        assert config.repo_specs[0].repo == "frontend-.*"
        assert config.repo_specs[0].is_regex is True
        assert config.repo_specs[1].repo == "backend-api"
        assert config.repo_specs[1].is_regex is False

    def test_loads_regex_with_branch_pattern(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {
            "org": "my-org",
            "repos": [
                {"repo": "svc-.*", "branch": "release-.*", "regex": True},
            ],
        })

        config, *_ = load_config(path)

        assert config.repo_specs[0].is_regex is True
        assert config.repo_specs[0].branch == "release-.*"

    def test_loads_log_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {
            "org": "my-org",
            "log_file": "audit.log",
        })

        config, _, _, _, _, log_file, *_ = load_config(path)
        assert log_file == "audit.log"

    def test_fails_without_token_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv(CONFIG_TOKEN_ENV, raising=False)
        path = _write_config(tmp_path, {"org": "my-org"})

        with pytest.raises(ValueError, match="GH_AUDIT_TOKEN"):
            load_config(path)

    def test_fails_without_org(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = _write_config(tmp_path, {"output": "report.json"})

        with pytest.raises(ValueError, match="org"):
            load_config(path)

    def test_fails_with_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_fails_with_invalid_yaml_structure(self, tmp_path, monkeypatch):
        monkeypatch.setenv(CONFIG_TOKEN_ENV, "ghp_testtoken123")
        path = tmp_path / "config.yaml"
        path.write_text("just a string")

        with pytest.raises(ValueError, match="YAML mapping"):
            load_config(str(path))
