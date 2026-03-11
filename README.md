# gh-auditor

Audit GitHub Actions workflows, branch protection, repository security features, and organization settings across an entire GitHub organization.

![demo](res/demo.gif)

## Features

- **Workflow Security** (GHA001-GHA013) — pull_request_target misuse, script injection, unpinned actions, overly permissive permissions, self-hosted runner risks, and more
- **Branch Protection** (BPR001-BPR010) — required reviews, push restrictions, status checks, signed commits, code owner reviews, linear history
- **Repository Security** (SEC001-SEC005) — secret scanning, push protection, Dependabot, CODEOWNERS, SECURITY.md
- **Organization Settings** (ORG001-ORG005) — 2FA requirement, default permissions, allowed actions, GITHUB_TOKEN defaults
- **Identity & Access** (IAM001-IAM011) — org admins, outside collaborators, team permissions, inactive members

Reports are generated in JSON, HTML, and SARIF formats.

## Installation

### From source

```bash
git clone https://github.com/nyrahul/gh-audit.git
cd gh-audit
pip install .
```

### For development

```bash
pip install -e ".[dev]"
```

### Pre-built binaries

Download the latest binary for your platform from the [Releases](https://github.com/nyrahul/gh-audit/releases) page.

## Setup

Create a **fine-grained Personal Access Token** (classic PATs are not supported):

1. Go to https://github.com/settings/personal-access-tokens/new
2. Under **Resource owner**, select your organization
3. Under **Repository access**, choose **All repositories**
4. Set these **Repository permissions** to **Read-only**:
   - Administration
   - Contents
   - Metadata (auto-granted)
5. Set this **Organization permission** to **Read-only**:
   - Members
6. Leave all other permissions as **No access**

Export the token:

```bash
export GH_AUDIT_TOKEN=github_pat_...
```

## Usage

### With a config file

```bash
gh-auditor --config audit-config.yaml
```

### With CLI arguments

```bash
gh-auditor --org my-org --output report.json --html report.html --sarif report.sarif
```

### Audit specific repos

```bash
gh-auditor --org my-org --repos my-org/frontend my-org/backend:develop
```

### Skip optional audits

```bash
gh-auditor --config audit-config.yaml --skip-identity
```

## Configuration

Create an `audit-config.yaml`:

```yaml
org: my-org
output: report.json
html_output: report.html
sarif_output: report.sarif
include_archived: false
include_forks: false
skip_identity: false
skip_repo_security: false
skip_org_settings: false
updated_within_months: 3
```

## License

MIT
