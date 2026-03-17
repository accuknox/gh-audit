"""CLI entry point for pipeaudit."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from rich.console import Console

from .auditor import AuditConfig, RepoSpec, run_audit
from .config import CONFIG_TOKEN_ENV, load_config
from .html_report import write_html_report
from .sarif_report import write_sarif_report
from .token_validator import TokenPermissionError, validate_token
from .tui import AuditTUI
from .version import __version__, __build_date__


def _version_string() -> str:
    s = f"pipeaudit {__version__}"
    if __build_date__ != "source":
        s += f" (built {__build_date__})"
    else:
        s += " (source)"
    return s


def main():
    parser = argparse.ArgumentParser(
        prog="pipeaudit",
        description=(
            "Audit CI/CD pipelines, branch protection, repository security, and\n"
            "organization settings across GitHub or Azure DevOps.\n"
            "Generates reports in JSON, HTML, and SARIF formats.\n\n"
            "Configuration can be provided via a YAML config file (--config) "
            "or via command-line arguments. CLI arguments override config file values.\n\n"
            "Tokens are read from environment variables or passed via --token:\n"
            f"  GitHub:      {CONFIG_TOKEN_ENV}\n"
            "  Azure DevOps: ADO_AUDIT_TOKEN"
        ),
        epilog=(
            "GITHUB — FINE-GRAINED PAT SETUP:\n"
            "  This tool requires a fine-grained Personal Access Token (PAT) with\n"
            "  read-only permissions. Classic PATs are NOT supported because they\n"
            "  cannot grant read access to private repos without also granting write.\n\n"
            "  1. Go to: https://github.com/settings/personal-access-tokens/new\n\n"
            "  2. Under 'Resource owner', select your organization.\n\n"
            "  3. Under 'Repository access', choose 'All repositories'\n"
            "     (or select only the repos you want to audit).\n\n"
            "  4. Under 'Repository permissions', set these to 'Read-only':\n"
            "       Administration .... Read-only  (needed to list repo collaborators)\n"
            "       Contents .......... Read-only  (needed to read workflow YAML files)\n"
            "       Metadata .......... Read-only  (auto-granted, lists repositories)\n\n"
            "  5. Under 'Organization permissions', set these to 'Read-only':\n"
            "       Members ........... Read-only  (needed to list org owners, teams,\n"
            "                                       outside collaborators, invitations)\n"
            "       Administration .... Read-only  (needed for Apps & Tokens audit;\n"
            "                                       optional, audit degrades gracefully)\n\n"
            "  6. Leave ALL other permissions as 'No access'.\n"
            "     Do NOT grant any 'Read and write' or 'Admin' permissions.\n"
            "     The tool will reject tokens with write access at startup.\n\n"
            "  7. Click 'Generate token' and export it:\n"
            f"       export {CONFIG_TOKEN_ENV}=github_pat_...\n\n"
            "AZURE DEVOPS — PAT SETUP:\n"
            "  Create a Personal Access Token (PAT) scoped to your organization.\n\n"
            "  1. Go to: https://dev.azure.com/{your-org}/_usersSettings/tokens\n\n"
            "  2. Click 'New Token' and set these scopes:\n"
            "       Code .............. Read       (needed to read repo and pipeline YAML)\n"
            "       Build ............. Read       (needed to inspect pipeline definitions)\n"
            "       Graph ............. Read       (needed for identity/group membership)\n"
            "       Project and Team .. Read       (needed to list projects and settings)\n"
            "       Security .......... Manage     (needed for identity/access audits;\n"
            "                                       optional, audit degrades gracefully)\n\n"
            "  3. Set an appropriate expiration (30-90 days recommended).\n\n"
            "  4. Click 'Create' and export the token:\n"
            "       export ADO_AUDIT_TOKEN=...\n\n"
            "  5. Run the audit:\n"
            "       pipeaudit --platform azure --org my-ado-org --output report.json\n\n"
            "GITLAB — PERSONAL ACCESS TOKEN SETUP:\n"
            "  Create a Personal Access Token (PAT) with read_api scope.\n\n"
            "  1. Go to: https://gitlab.com/-/user_settings/personal_access_tokens\n\n"
            "  2. Create a token with these scopes:\n"
            "       read_api ......... Read       (needed to read groups, projects,\n"
            "                                      pipelines, and settings)\n\n"
            "  3. Set an appropriate expiration (30-90 days recommended).\n\n"
            "  4. Click 'Create personal access token' and export it:\n"
            "       export GL_AUDIT_TOKEN=glpat-...\n\n"
            "  5. Run the audit:\n"
            "       pipeaudit --platform gitlab --org my-group --output report.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=_version_string(),
    )
    parser.add_argument(
        "--platform",
        choices=["github", "azure", "gitlab"],
        default="github",
        help="Platform to audit: 'github' (default), 'azure' (Azure DevOps), or 'gitlab'.",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="FILE",
        help="Path to YAML config file (see audit-config.yaml.sample).",
    )
    parser.add_argument(
        "--token",
        help=(
            f"GitHub fine-grained PAT with read-only permissions "
            f"(see FINE-GRAINED PAT SETUP below). "
            f"Overrides {CONFIG_TOKEN_ENV} env var."
        ),
    )
    parser.add_argument(
        "--org",
        help="GitHub organization to audit.",
    )
    parser.add_argument(
        "--repos",
        nargs="*",
        metavar="OWNER/REPO[:BRANCH]",
        help=(
            "Specific repos to audit (overrides org-wide scan). "
            "Format: 'owner/repo' or 'owner/repo:branch'. "
            "Wrap in /.../ for regex matching: '/frontend-.*/'. "
            "If owner is omitted, --org is used."
        ),
    )
    parser.add_argument(
        "--projects",
        nargs="*",
        metavar="PROJECT",
        help="(Azure DevOps) Specific projects to audit.",
    )
    parser.add_argument(
        "--groups",
        nargs="*",
        metavar="GROUP",
        help="(GitLab) Specific sub-groups to audit.",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for the JSON report (default: stdout).",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Generate an HTML report at the given path.",
    )
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Generate a SARIF v2.1.0 report at the given path.",
    )
    parser.add_argument(
        "--include-archived",
        action="store_true",
        default=None,
        help="Include archived repositories in the scan.",
    )
    parser.add_argument(
        "--include-forks",
        action="store_true",
        default=None,
        help="Include forked repositories in the scan.",
    )
    parser.add_argument(
        "--skip-identity",
        action="store_true",
        default=None,
        help="Skip the identity/access audit (org members, teams, collaborators).",
    )
    parser.add_argument(
        "--skip-apps-tokens",
        action="store_true",
        default=None,
        help="Skip the GitHub Apps & fine-grained PATs audit.",
    )
    parser.add_argument(
        "--skip-project-settings",
        action="store_true",
        default=None,
        help="(Azure DevOps) Skip the project-level settings audit.",
    )
    parser.add_argument(
        "--skip-pipeline-security",
        action="store_true",
        default=None,
        help="(Azure DevOps / GitLab) Skip the pipeline security audit.",
    )
    parser.add_argument(
        "--include-disabled-repos",
        action="store_true",
        default=None,
        help="(Azure DevOps) Include disabled repositories in the scan.",
    )
    parser.add_argument(
        "--skip-group-settings",
        action="store_true",
        default=None,
        help="(GitLab) Skip the group-level settings audit.",
    )
    parser.add_argument(
        "--updated-within",
        type=int,
        metavar="MONTHS",
        default=None,
        help="Only scan repos updated (pushed to) within the last N months.",
    )
    parser.add_argument(
        "--log",
        metavar="FILE",
        help="Write a detailed log file (repos scanned, skipped, errors, etc.).",
    )
    parser.add_argument(
        "--no-tui",
        action="store_true",
        help="Disable the live TUI progress display.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=None,
        help="Increase verbosity (-v for info, -vv for debug).",
    )

    args = parser.parse_args()

    platform = args.platform

    # Load config file if provided, then overlay CLI args
    if args.config:
        try:
            config, cfg_output, cfg_verbosity, cfg_html, cfg_sarif, cfg_log = load_config(args.config)
            # Config file may specify platform
            if hasattr(config, "platform"):
                platform = config.platform
        except (FileNotFoundError, ValueError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        config = None
        cfg_output = "-"
        cfg_verbosity = 0
        cfg_html = None
        cfg_sarif = None
        cfg_log = None

    # CLI --platform always wins
    if args.platform != "github":
        platform = args.platform

    # Resolve final values: CLI args override config file
    token = args.token or (config.token if config else None)
    org = args.org or (config.org if config else None)
    output = args.output or (cfg_output if config else "-")
    html_output = args.html or cfg_html
    sarif_output = args.sarif or cfg_sarif
    log_file = args.log or cfg_log
    verbosity = args.verbose if args.verbose is not None else cfg_verbosity
    include_archived = args.include_archived if args.include_archived is not None else (config.include_archived if config else False)
    include_forks = args.include_forks if args.include_forks is not None else (config.include_forks if config else False)
    skip_identity = args.skip_identity if args.skip_identity is not None else (config.skip_identity if config else False)
    skip_apps_tokens = args.skip_apps_tokens if args.skip_apps_tokens is not None else (getattr(config, "skip_apps_and_tokens", False) if config else False)
    updated_within = args.updated_within if args.updated_within is not None else (config.updated_within_months if config else None)

    # Token env var differs by platform
    import os
    if not token:
        if platform == "azure":
            token = os.environ.get("ADO_AUDIT_TOKEN", "").strip()
        elif platform == "gitlab":
            token = os.environ.get("GL_AUDIT_TOKEN", "").strip()
            if not token:
                token = os.environ.get("GITLAB_TOKEN", "").strip()
        if not token:
            token = os.environ.get(CONFIG_TOKEN_ENV, "").strip()

    if not token:
        env_var_map = {
            "azure": "ADO_AUDIT_TOKEN",
            "gitlab": "GL_AUDIT_TOKEN",
        }
        env_var = env_var_map.get(platform, CONFIG_TOKEN_ENV)
        print(
            f"ERROR: No token provided. Use --token or set {env_var} "
            f"environment variable.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not org:
        print("ERROR: No org provided. Use --org or set 'org' in config file.", file=sys.stderr)
        sys.exit(1)

    # Configure logging -- stderr handler respects verbosity level
    stderr_level = logging.WARNING
    if verbosity >= 2:
        stderr_level = logging.DEBUG
    elif verbosity >= 1:
        stderr_level = logging.INFO

    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    root_logger = logging.getLogger()
    # Set root to DEBUG so file handler can capture everything; handlers filter
    root_logger.setLevel(logging.DEBUG if log_file else stderr_level)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(stderr_level)
    stderr_handler.setFormatter(logging.Formatter(log_format))
    root_logger.addHandler(stderr_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, mode="w")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(log_format))
        root_logger.addHandler(file_handler)

    # Determine if TUI should be shown:
    # - disabled with --no-tui
    # - disabled when outputting JSON to stdout (would corrupt the output)
    # - disabled when not a terminal
    use_tui = (
        not args.no_tui
        and output != "-"
        and sys.stderr.isatty()
    )

    console = Console(stderr=True)

    # Platform-specific validation and audit
    if platform == "gitlab":
        # GitLab flow
        from .gitlab.gitlab_token_validator import GitLabTokenError, validate_gitlab_token
        from .gitlab.gitlab_auditor import GitLabAuditConfig, run_gitlab_audit

        base_url = getattr(config, "base_url", "https://gitlab.com/api/v4") if config else "https://gitlab.com/api/v4"

        if use_tui:
            console.print("[bold blue]Validating GitLab token...[/bold blue]")
        try:
            gl_info = validate_gitlab_token(org, token, base_url)
            if use_tui:
                console.print(
                    f"[green]Authenticated to GitLab group:[/green] {gl_info.get('group', org)}"
                )
            logging.info("Authenticated to GitLab group: %s", org)
        except GitLabTokenError as e:
            console.print(f"[bold red]ERROR:[/bold red] {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]ERROR:[/bold red] Token validation failed: {e}")
            sys.exit(1)

        gl_config = GitLabAuditConfig(
            org=org,
            token=token,
            base_url=base_url,
            groups=args.groups or (getattr(config, "groups", []) if config else []),
            repos=args.repos or [],
            include_archived=include_archived,
            skip_identity=skip_identity,
            skip_group_settings=args.skip_group_settings if args.skip_group_settings is not None else (getattr(config, "skip_group_settings", False) if config else False),
            skip_pipeline_security=args.skip_pipeline_security if args.skip_pipeline_security is not None else (getattr(config, "skip_pipeline_security", False) if config else False),
            updated_within_months=updated_within,
        )

        tui = AuditTUI(console=console) if use_tui else None
        try:
            if tui:
                tui.start()
            report = run_gitlab_audit(gl_config, progress=tui)
            if tui:
                tui.update_severity_counts(report)
                tui.stop()
                tui.print_summary(report)
        except KeyboardInterrupt:
            if tui:
                tui.stop()
            console.print("\n[yellow]Audit interrupted.[/yellow]")
            sys.exit(130)
        except Exception as e:
            if tui:
                tui.stop()
            console.print(f"[bold red]ERROR:[/bold red] Audit failed: {e}")
            sys.exit(1)
    elif platform == "azure":
        # Azure DevOps flow
        from .azure.ado_token_validator import AdoTokenError, validate_ado_token
        from .azure.ado_auditor import AdoAuditConfig, run_ado_audit

        if use_tui:
            console.print("[bold blue]Validating Azure DevOps token...[/bold blue]")
        try:
            ado_info = validate_ado_token(org, token)
            if use_tui:
                console.print(
                    f"[green]Authenticated to Azure DevOps org:[/green] {ado_info.get('organization', org)}"
                )
            logging.info("Authenticated to ADO org: %s", org)
        except AdoTokenError as e:
            console.print(f"[bold red]ERROR:[/bold red] {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]ERROR:[/bold red] Token validation failed: {e}")
            sys.exit(1)

        ado_config = AdoAuditConfig(
            org=org,
            token=token,
            projects=args.projects or (getattr(config, "projects", []) if config else []),
            repos=args.repos or [],
            skip_identity=skip_identity,
            skip_project_settings=args.skip_project_settings if args.skip_project_settings is not None else (getattr(config, "skip_project_settings", False) if config else False),
            skip_pipeline_security=args.skip_pipeline_security if args.skip_pipeline_security is not None else (getattr(config, "skip_pipeline_security", False) if config else False),
            include_disabled_repos=args.include_disabled_repos if args.include_disabled_repos is not None else (getattr(config, "include_disabled_repos", False) if config else False),
            updated_within_months=updated_within,
        )

        tui = AuditTUI(console=console) if use_tui else None
        try:
            if tui:
                tui.start()
            report = run_ado_audit(ado_config, progress=tui)
            if tui:
                tui.update_severity_counts(report)
                tui.stop()
                tui.print_summary(report)
        except KeyboardInterrupt:
            if tui:
                tui.stop()
            console.print("\n[yellow]Audit interrupted.[/yellow]")
            sys.exit(130)
        except Exception as e:
            if tui:
                tui.stop()
            console.print(f"[bold red]ERROR:[/bold red] Audit failed: {e}")
            sys.exit(1)
    else:
        # GitHub flow (existing)
        if use_tui:
            console.print("[bold blue]Validating token...[/bold blue]")
        try:
            user_info = validate_token(token, org)
            if use_tui:
                console.print(
                    f"[green]Authenticated as:[/green] {user_info.get('login', 'unknown')}"
                )
            logging.info(
                "Authenticated as: %s", user_info.get("login", "unknown")
            )
        except TokenPermissionError as e:
            console.print(f"[bold red]ERROR:[/bold red] {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]ERROR:[/bold red] Token validation failed: {e}")
            sys.exit(1)

        # Parse repo specs: CLI --repos overrides config file repos
        repo_specs = []
        if args.repos:
            for spec_str in args.repos:
                repo_specs.append(_parse_repo_spec(spec_str, org))
        elif config and config.repo_specs:
            repo_specs = config.repo_specs

        audit_config = AuditConfig(
            org=org,
            token=token,
            repo_specs=repo_specs,
            include_archived=include_archived,
            include_forks=include_forks,
            skip_identity=skip_identity,
            skip_apps_and_tokens=skip_apps_tokens,
            updated_within_months=updated_within,
        )

        # Run the audit
        tui = AuditTUI(console=console) if use_tui else None

        try:
            if tui:
                tui.start()
            report = run_audit(audit_config, progress=tui)
            if tui:
                tui.update_severity_counts(report)
                tui.stop()
                tui.print_summary(report)
        except KeyboardInterrupt:
            if tui:
                tui.stop()
            console.print("\n[yellow]Audit interrupted.[/yellow]")
            sys.exit(130)
        except Exception as e:
            if tui:
                tui.stop()
            console.print(f"[bold red]ERROR:[/bold red] Audit failed: {e}")
            sys.exit(1)

    # Output JSON report
    report_json = json.dumps(report, indent=2)

    if output == "-":
        print(report_json)
    else:
        with open(output, "w") as f:
            f.write(report_json)
        if use_tui:
            console.print(
                f"\n[bold green]JSON report written to {output}[/bold green] "
                f"({report['audit_metadata']['total_findings']} findings)"
            )
        else:
            print(
                f"Report written to {output} "
                f"({report['audit_metadata']['total_findings']} findings)",
                file=sys.stderr,
            )

    # Output HTML report
    if html_output:
        write_html_report(report, html_output)
        if use_tui:
            console.print(
                f"[bold green]HTML report written to {html_output}[/bold green]"
            )
        else:
            print(f"HTML report written to {html_output}", file=sys.stderr)

    # Output SARIF report
    if sarif_output:
        write_sarif_report(report, sarif_output)
        if use_tui:
            console.print(
                f"[bold green]SARIF report written to {sarif_output}[/bold green]"
            )
        else:
            print(f"SARIF report written to {sarif_output}", file=sys.stderr)

    if log_file:
        if use_tui:
            console.print(
                f"[bold green]Log written to {log_file}[/bold green]"
            )
        else:
            print(f"Log written to {log_file}", file=sys.stderr)


def _parse_repo_spec(spec_str: str, default_org: str) -> RepoSpec:
    """Parse 'owner/repo:branch' or 'repo:branch' or 'owner/repo'.

    Supports regex patterns wrapped in /.../  e.g.:
        /frontend-.*/           -> regex on repo name
        /frontend-.*/:/release-.*/  -> regex on both repo and branch
        myorg/frontend-.*:main  -> exact owner, regex repo (auto-detected)
    """
    is_regex = False

    # Check for /pattern/ syntax
    if spec_str.startswith("/"):
        is_regex = True
        # Strip leading / — the rest may contain :branch
        spec_str = spec_str[1:]
        # Find the closing / (may be before :branch or at end)
        slash_pos = spec_str.find("/")
        if slash_pos == -1:
            # No closing slash, treat entire string as pattern
            repo_part = spec_str
            branch = None
        else:
            repo_part = spec_str[:slash_pos]
            remainder = spec_str[slash_pos + 1:]
            branch = None
            if remainder.startswith(":"):
                branch_str = remainder[1:]
                # Branch may also be /regex/
                if branch_str.startswith("/") and branch_str.endswith("/"):
                    branch = branch_str[1:-1]
                elif branch_str:
                    branch = branch_str

        return RepoSpec(
            owner=default_org, repo=repo_part, branch=branch, is_regex=True
        )

    branch = None
    if ":" in spec_str:
        spec_str, branch = spec_str.rsplit(":", 1)

    if "/" in spec_str:
        owner, repo = spec_str.split("/", 1)
    else:
        owner = default_org
        repo = spec_str

    return RepoSpec(owner=owner, repo=repo, branch=branch)


if __name__ == "__main__":
    main()
