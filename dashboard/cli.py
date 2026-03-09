#!/usr/bin/env python3
"""
cli.py — Rich terminal dashboard for the eBPF EDR.

Architecture:
  - collector.py puts alert dicts into a shared queue
  - this dashboard runs in the main thread, consuming the queue
  - Rich Live re-renders the layout on every new alert

Layout:
  ┌─────────────────────────────────┐
  │  Header: status + uptime        │
  ├─────────────────────────────────┤
  │  Alert feed (scrolling)         │
  ├─────────────────────────────────┤
  │  Stats: counts by severity/type │
  └─────────────────────────────────┘
"""

import time
import queue
from datetime import datetime, timedelta
from collections import defaultdict

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Maximum alerts to keep in the feed before dropping oldest
MAX_ALERTS = 50

# Color mapping by severity label
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "INFO":     "yellow",
    "DEBUG":    "dim white",
}

# Color mapping by alert type prefix
TYPE_COLORS = {
    "EXECVE":  "cyan",
    "PTRACE":  "magenta",
    "OPENAT":  "blue",
    "CONNECT": "green",
}


class Dashboard:
    """
    Owns the alert queue, display state, and Rich layout.
    collector.py imports and calls dashboard.push(alert_dict)
    to feed new alerts in.
    """

    def __init__(self):
        self.queue      = queue.Queue()   # collector pushes here
        self.alerts     = []              # recent alerts, newest last
        self.counts     = defaultdict(int) # counts["EXECVE"], counts["HIGH"], etc.
        self.start_time = datetime.now()
        self.console    = Console()

    def push(self, alert: dict):
        """Called by collector.py to enqueue a new alert."""
        self.queue.put(alert)

    def _drain_queue(self):
        """Pull all pending alerts from the queue into self.alerts."""
        while True:
            try:
                alert = self.queue.get_nowait()
                self.alerts.append(alert)
                # Track counts by type and severity
                self.counts[alert.get("type", "UNKNOWN")] += 1
                self.counts[alert.get("severity", "INFO")] += 1
                # Keep the feed bounded
                if len(self.alerts) > MAX_ALERTS:
                    self.alerts.pop(0)
            except queue.Empty:
                break

    def _build_header(self) -> Panel:
        """Top panel: EDR name, status, uptime."""
        uptime = datetime.now() - self.start_time
        uptime_str = str(timedelta(seconds=int(uptime.total_seconds())))

        text = Text()
        text.append("● ", style="bold green")
        text.append("eBPF EDR", style="bold white")
        text.append("  |  ", style="dim")
        text.append("STATUS: ", style="dim")
        text.append("RUNNING", style="bold green")
        text.append("  |  ", style="dim")
        text.append("UPTIME: ", style="dim")
        text.append(uptime_str, style="bold cyan")
        text.append("  |  ", style="dim")
        text.append("ALERTS: ", style="dim")
        text.append(str(len(self.alerts)), style="bold yellow")

        return Panel(text, style="bold", box=box.HORIZONTALS)

    def _build_feed(self) -> Panel:
        """Middle panel: scrolling alert table, newest at bottom."""
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold white",
            expand=True,
        )
        table.add_column("Time",     style="dim",   width=10, no_wrap=True)
        table.add_column("Type",     width=8,       no_wrap=True)
        table.add_column("Severity", width=10,      no_wrap=True)
        table.add_column("Score",    width=6,       no_wrap=True)
        table.add_column("Process",  width=16,      no_wrap=True)
        table.add_column("Detail",   ratio=1)

        # Show last 20 alerts so the panel doesn't overflow
        for alert in self.alerts[-20:]:
            alert_type = alert.get("type", "?")
            severity   = alert.get("severity", "INFO")
            score      = str(alert.get("score", ""))
            proc       = alert.get("comm", "?")
            detail     = alert.get("detail", "")
            ts         = alert.get("time", "")

            type_color = TYPE_COLORS.get(alert_type, "white")
            sev_color  = SEVERITY_COLORS.get(severity, "white")

            table.add_row(
                ts,
                Text(alert_type, style=type_color),
                Text(severity,   style=sev_color),
                score,
                proc,
                detail,
            )

        return Panel(table, title="[bold]Alert Feed[/bold]", box=box.ROUNDED)

    def _build_stats(self) -> Panel:
        """Bottom panel: alert counts by type and severity."""
        table = Table(box=box.SIMPLE, show_header=False, expand=True)
        table.add_column("Label", style="dim", width=12)
        table.add_column("Count", style="bold white", width=8)
        table.add_column("Label", style="dim", width=12)
        table.add_column("Count", style="bold white", width=8)

        # Left column: by type, Right column: by severity
        types      = ["EXECVE", "PTRACE", "OPENAT", "CONNECT"]
        severities = ["CRITICAL", "HIGH", "INFO"]

        rows = max(len(types), len(severities))
        for i in range(rows):
            t_label = types[i]      if i < len(types)      else ""
            s_label = severities[i] if i < len(severities) else ""
            t_count = str(self.counts.get(t_label, 0)) if t_label else ""
            s_count = str(self.counts.get(s_label, 0)) if s_label else ""

            t_color = TYPE_COLORS.get(t_label, "white")
            s_color = SEVERITY_COLORS.get(s_label, "white")

            table.add_row(
                Text(t_label, style=t_color), t_count,
                Text(s_label, style=s_color), s_count,
            )

        return Panel(table, title="[bold]Stats[/bold]", box=box.ROUNDED)

    def run(self):
        """
        Main loop — renders the dashboard and refreshes on new alerts.
        Call this from collector.py after starting the BPF poll loop
        in a background thread.
        """
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="feed",   ratio=3),
            Layout(name="stats",  size=8),
        )

        with Live(layout, console=self.console, refresh_per_second=4, screen=True):
            while True:
                self._drain_queue()
                layout["header"].update(self._build_header())
                layout["feed"].update(self._build_feed())
                layout["stats"].update(self._build_stats())
                time.sleep(0.25)