"""Rich-based TUI for live progress display during audit."""

from __future__ import annotations

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from .auditor import ProgressCallback

SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class AuditTUI(ProgressCallback):
    """Live TUI that shows audit progress with Rich."""

    def __init__(self, console: Console | None = None):
        self._console = console or Console(stderr=True)

        # Overall repo progress bar
        self._repo_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self._console,
        )
        self._repo_task: TaskID | None = None

        # Current repo detail line
        self._current_repo = Text("")
        self._current_detail = Text("")

        # Severity tallies
        self._severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        self._total_workflows = 0
        self._total_repos_done = 0
        self._errors: list[str] = []

        # Recent findings log (last N)
        self._recent_findings: list[tuple[str, str, int]] = []  # (repo, workflow, count)

        self._live: Live | None = None

    def start(self) -> None:
        self._live = Live(
            self._build_layout(),
            console=self._console,
            refresh_per_second=8,
            transient=False,
        )
        self._live.start()

    def stop(self) -> None:
        if self._live:
            self._live.update(self._build_layout())
            self._live.stop()
            self._live = None

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._build_layout())

    def _build_layout(self) -> Panel:
        parts = []

        # Progress bar
        parts.append(self._repo_progress)

        # Current activity
        if self._current_repo:
            parts.append(Text(""))
            parts.append(self._current_repo)
            if self._current_detail:
                parts.append(self._current_detail)

        # Findings summary table
        parts.append(Text(""))
        parts.append(self._build_severity_table())

        # Recent scan log
        if self._recent_findings:
            parts.append(Text(""))
            parts.append(self._build_recent_log())

        # Errors
        if self._errors:
            parts.append(Text(""))
            for err in self._errors[-3:]:
                parts.append(Text(f"  ERR  {err}", style="bold red"))

        return Panel(
            Group(*parts),
            title="[bold]pipeaudit[/bold]",
            border_style="blue",
            padding=(1, 2),
        )

    def _build_severity_table(self) -> Table:
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("label", style="bold")
        table.add_column("count", justify="right")

        total = sum(self._severity_counts.values())
        row_items = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = self._severity_counts[sev]
            style = SEVERITY_STYLES[sev]
            row_items.append(Text(f"{sev.upper()}: {count}", style=style))

        table.add_row(
            Text("Findings", style="bold"),
            Text(" | ").join(row_items),
        )
        table.add_row(
            Text("Stats", style="bold"),
            Text(
                f"Repos: {self._total_repos_done}  "
                f"Workflows: {self._total_workflows}  "
                f"Total findings: {total}"
            ),
        )
        return table

    def _build_recent_log(self) -> Table:
        table = Table(
            show_header=True,
            header_style="bold dim",
            box=None,
            padding=(0, 1),
        )
        table.add_column("Repository", style="cyan", min_width=30)
        table.add_column("Workflow", style="white")
        table.add_column("Findings", justify="right")

        for repo, wf, count in self._recent_findings[-8:]:
            style = "bold red" if count > 0 else "green"
            table.add_row(repo, wf, Text(str(count), style=style))

        return table

    # -- ProgressCallback interface --

    def on_discovery_start(self) -> None:
        self._repo_task = self._repo_progress.add_task(
            "Discovering repos...", total=None
        )
        self._current_repo = Text("  Fetching repository list...", style="italic")
        self._refresh()

    def on_discovery_done(self, total_repos: int, skipped: int) -> None:
        if self._repo_task is not None:
            self._repo_progress.update(
                self._repo_task,
                description=f"Auditing {total_repos} repos",
                total=total_repos,
                completed=0,
            )
        skip_msg = f" (skipped {skipped} archived/forked)" if skipped else ""
        self._current_repo = Text(
            f"  Found {total_repos} repos to audit{skip_msg}",
            style="green",
        )
        self._current_detail = Text("")
        self._refresh()

    def on_repo_start(self, repo_name: str, branch: str) -> None:
        self._current_repo = Text(f"  Scanning ", style="white")
        self._current_repo.append(repo_name, style="bold cyan")
        self._current_repo.append(f" @ {branch}", style="dim")
        self._current_detail = Text("    Listing workflows...", style="italic dim")
        self._refresh()

    def on_repo_workflows_found(self, repo_name: str, count: int) -> None:
        if count == 0:
            self._current_detail = Text(
                "    No workflow files found", style="dim"
            )
        else:
            self._current_detail = Text(
                f"    Found {count} workflow file(s), analyzing...", style="dim"
            )
        self._refresh()

    def on_workflow_scanned(
        self, repo_name: str, workflow: str, findings_count: int,
        severity_counts: dict[str, int] | None = None,
    ) -> None:
        self._total_workflows += 1
        self._recent_findings.append((repo_name, workflow, findings_count))

        # Accumulate severity counts as they come in
        if severity_counts:
            for sev, count in severity_counts.items():
                self._severity_counts[sev] = self._severity_counts.get(sev, 0) + count

        self._current_detail = Text("    Scanned ", style="dim")
        self._current_detail.append(workflow, style="white")
        if findings_count > 0:
            self._current_detail.append(
                f" ({findings_count} findings)", style="yellow"
            )
        else:
            self._current_detail.append(" (clean)", style="green")
        self._refresh()

    def on_repo_done(self, repo_name: str, findings_count: int) -> None:
        self._total_repos_done += 1
        if self._repo_task is not None:
            self._repo_progress.advance(self._repo_task)
        self._refresh()

    def on_repo_error(self, repo_name: str, error: str) -> None:
        self._errors.append(f"{repo_name}: {error}")
        if self._repo_task is not None:
            self._repo_progress.advance(self._repo_task)
        self._refresh()

    def on_identity_start(self) -> None:
        self._current_repo = Text("  Auditing identity & access...", style="bold magenta")
        self._current_detail = Text("")
        self._refresh()

    def on_identity_status(self, message: str) -> None:
        self._current_detail = Text(f"    {message}", style="dim")
        self._refresh()

    def on_identity_done(self, findings_count: int, severity_counts: dict[str, int] | None = None) -> None:
        # Accumulate identity severity counts
        if severity_counts:
            for sev, count in severity_counts.items():
                self._severity_counts[sev] = self._severity_counts.get(sev, 0) + count

        style = "yellow" if findings_count > 0 else "green"
        self._current_repo = Text(
            f"  Identity audit complete: {findings_count} finding(s)",
            style=style,
        )
        self._current_detail = Text("")
        self._refresh()

    def update_severity_counts(self, report: dict) -> None:
        """Update final severity counts from the completed report."""
        self._severity_counts = dict(
            report["audit_metadata"]["findings_by_severity"]
        )
        self._refresh()

    def print_summary(self, report: dict) -> None:
        """Print a final summary after the live display stops."""
        meta = report["audit_metadata"]
        self._console.print()

        summary = Table(
            title="Audit Complete",
            show_header=False,
            border_style="green",
            padding=(0, 2),
        )
        summary.add_column("key", style="bold")
        summary.add_column("value")
        summary.add_row("Organization", meta["organization"])
        summary.add_row("Repos scanned", str(meta["total_repos_scanned"]))
        summary.add_row("Workflows scanned", str(meta["total_workflows_scanned"]))
        summary.add_row("Total findings", str(meta["total_findings"]))

        for sev in ("critical", "high", "medium", "low", "info"):
            count = meta["findings_by_severity"].get(sev, 0)
            if count > 0:
                style = SEVERITY_STYLES[sev]
                summary.add_row(f"  {sev.upper()}", Text(str(count), style=style))

        # Identity stats
        identity = report.get("identity", {})
        if identity and "error" not in identity:
            summary.add_row("", "")
            summary.add_row("Org members", str(identity.get("org_member_count", 0)))
            summary.add_row("Org owners", Text(
                str(identity.get("org_owner_count", 0)),
                style="bold red" if identity.get("org_owner_count", 0) > 3 else "",
            ))
            summary.add_row("Outside collaborators", str(len(identity.get("outside_collaborators", []))))
            summary.add_row("Teams", str(len(identity.get("teams", []))))
            summary.add_row("Identity findings", str(len(identity.get("findings", []))))

        self._console.print(summary)

        # Top offenders
        repos_with_findings = [
            (r["repo"], len(r["findings"]))
            for r in report["repos"]
            if r["findings"]
        ]
        if repos_with_findings:
            repos_with_findings.sort(key=lambda x: x[1], reverse=True)

            top = Table(
                title="Top Repos by Findings",
                border_style="yellow",
                padding=(0, 2),
            )
            top.add_column("Repository", style="cyan")
            top.add_column("Findings", justify="right", style="bold")
            for repo, count in repos_with_findings[:10]:
                top.add_row(repo, str(count))

            self._console.print()
            self._console.print(top)
