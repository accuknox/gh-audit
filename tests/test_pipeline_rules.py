"""Tests for Azure DevOps pipeline security rules (AZP001-AZP008)."""

from unittest.mock import MagicMock

from pipeaudit.azure.pipeline_rules import audit_pipeline_security


def _make_client(yaml_content=None):
    client = MagicMock()
    client.get_file_content.return_value = yaml_content
    client.list_build_definitions.return_value = []
    return client


class TestAZP001:
    def test_persist_credentials_true(self):
        yaml_content = """
steps:
  - checkout: self
    persistCredentials: true
  - script: echo hello
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp001 = [f for f in findings if f["rule_id"] == "AZP001"]
        assert len(azp001) == 1
        assert "persistCredentials" in azp001[0]["description"]

    def test_persist_credentials_false_no_finding(self):
        yaml_content = """
steps:
  - checkout: self
    persistCredentials: false
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp001 = [f for f in findings if f["rule_id"] == "AZP001"]
        assert len(azp001) == 0


class TestAZP002:
    def test_unpinned_template(self):
        yaml_content = """
extends:
  template: templates/build.yml@my-templates
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp002 = [f for f in findings if f["rule_id"] == "AZP002"]
        assert len(azp002) == 1

    def test_pinned_template_tag(self):
        yaml_content = """
extends:
  template: templates/build.yml@refs/tags/v1.0
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp002 = [f for f in findings if f["rule_id"] == "AZP002"]
        assert len(azp002) == 0

    def test_unpinned_resource_repo(self):
        yaml_content = """
resources:
  repositories:
    - repository: templates
      type: git
      name: my-project/my-templates
      ref: main
steps:
  - script: echo hello
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp002 = [f for f in findings if f["rule_id"] == "AZP002"]
        assert len(azp002) == 1


class TestAZP004:
    def test_target_host(self):
        yaml_content = """
steps:
  - script: whoami
    target: host
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp004 = [f for f in findings if f["rule_id"] == "AZP004"]
        assert len(azp004) == 1

    def test_no_target_host(self):
        yaml_content = """
steps:
  - script: whoami
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp004 = [f for f in findings if f["rule_id"] == "AZP004"]
        assert len(azp004) == 0


class TestAZP005:
    def test_self_hosted_public_no_demands(self):
        yaml_content = """
pool:
  name: my-self-hosted
steps:
  - script: echo hello
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", True,
            [], {}, [],
        )
        azp005 = [f for f in findings if f["rule_id"] == "AZP005"]
        assert len(azp005) == 1
        assert azp005[0]["severity"] == "critical"

    def test_self_hosted_private_no_finding(self):
        yaml_content = """
pool:
  name: my-self-hosted
steps:
  - script: echo hello
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp005 = [f for f in findings if f["rule_id"] == "AZP005"]
        assert len(azp005) == 0

    def test_microsoft_hosted_public_no_finding(self):
        yaml_content = """
pool:
  vmImage: ubuntu-latest
steps:
  - script: echo hello
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", True,
            [], {}, [],
        )
        azp005 = [f for f in findings if f["rule_id"] == "AZP005"]
        assert len(azp005) == 0


class TestAZP006:
    def test_unsafe_variable_interpolation(self):
        yaml_content = """
steps:
  - script: echo $(Build.SourceVersionMessage)
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp006 = [f for f in findings if f["rule_id"] == "AZP006"]
        assert len(azp006) == 1

    def test_safe_variable_no_finding(self):
        yaml_content = """
steps:
  - script: echo $(Build.BuildId)
"""
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        azp006 = [f for f in findings if f["rule_id"] == "AZP006"]
        assert len(azp006) == 0


class TestAZP007:
    def test_environment_no_checks(self):
        yaml_content = """
jobs:
  - deployment: deploy
    environment: production
    strategy:
      runOnce:
        deploy:
          steps:
            - script: echo deploying
"""
        envs = [{"id": 1, "name": "production"}]
        env_checks = {1: []}
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            envs, env_checks, [],
        )
        azp007 = [f for f in findings if f["rule_id"] == "AZP007"]
        assert len(azp007) == 1

    def test_environment_with_approval(self):
        yaml_content = """
jobs:
  - deployment: deploy
    environment: production
    strategy:
      runOnce:
        deploy:
          steps:
            - script: echo deploying
"""
        envs = [{"id": 1, "name": "production"}]
        env_checks = {1: [{"type": {"name": "Approval"}}]}
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            envs, env_checks, [],
        )
        azp007 = [f for f in findings if f["rule_id"] == "AZP007"]
        assert len(azp007) == 0


class TestAZP008:
    def test_shared_secret_variable_group(self):
        yaml_content = """
variables:
  - group: my-secret-group
steps:
  - script: echo hello
"""
        vgs = [{
            "name": "my-secret-group",
            "isShared": True,
            "variables": {"DB_PASSWORD": {"isSecret": True, "value": None}},
        }]
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, vgs,
        )
        azp008 = [f for f in findings if f["rule_id"] == "AZP008"]
        assert len(azp008) == 1

    def test_non_shared_secret_group_no_finding(self):
        yaml_content = """
variables:
  - group: my-secret-group
steps:
  - script: echo hello
"""
        vgs = [{
            "name": "my-secret-group",
            "isShared": False,
            "variables": {"DB_PASSWORD": {"isSecret": True, "value": None}},
        }]
        client = _make_client(yaml_content)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, vgs,
        )
        azp008 = [f for f in findings if f["rule_id"] == "AZP008"]
        assert len(azp008) == 0


class TestNoYaml:
    def test_no_pipeline_yaml(self):
        client = _make_client(None)
        findings = audit_pipeline_security(
            client, "proj", "r1", "proj/repo", "main", False,
            [], {}, [],
        )
        assert findings == []
