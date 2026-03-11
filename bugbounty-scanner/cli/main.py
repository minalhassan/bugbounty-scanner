"""
cli/main.py
===========
Command-Line Interface for the AI Bug Bounty Scanner.

Features:
- Beautiful Rich terminal output
- Real-time progress display
- Multiple output formats
- Modular scan control
"""

import asyncio
import sys
import time
from typing import Optional, List
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.rule import Rule
from rich import box
from loguru import logger

# Configure loguru to use Rich
logger.remove()
logger.add(sys.stderr, level="WARNING", format="<red>{message}</red>")

console = Console()

BANNER = """
[bold cyan]
  ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
  ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
  ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
  ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
  ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
  ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝  
[/bold cyan]
[dim]  AI-Powered Bug Bounty Autonomous Scanner v1.0.0[/dim]
[dim]  For authorized security testing only.[/dim]
"""

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "bold orange1",
    "medium":   "bold yellow",
    "low":      "bold cyan",
    "info":     "bold white",
}


def print_banner():
    console.print(BANNER)
    console.print()


def print_ethics_warning():
    """Display mandatory ethics warning before scan."""
    warning = Panel(
        "[bold yellow]⚠️  IMPORTANT LEGAL & ETHICAL NOTICE[/bold yellow]\n\n"
        "This tool is designed EXCLUSIVELY for:\n"
        "  ✅  Authorized penetration testing\n"
        "  ✅  Bug bounty programs (HackerOne, Bugcrowd, etc.)\n"
        "  ✅  Security research on systems you own\n"
        "  ✅  CTF challenges\n\n"
        "[bold red]UNAUTHORIZED USE IS ILLEGAL AND PUNISHABLE BY LAW.[/bold red]\n\n"
        "By continuing, you confirm you have explicit written permission\n"
        "to test the target system.",
        title="[bold yellow]⚠ Ethics Warning[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
    )
    console.print(warning)
    console.print()


def confirm_scan(target: str) -> bool:
    """Prompt user to confirm the scan target."""
    response = console.input(
        f"[cyan]Confirm scan target:[/cyan] [bold]{target}[/bold] [dim](yes/no): [/dim]"
    )
    return response.lower() in ("yes", "y")


@click.group()
def cli():
    """AI Bug Bounty Autonomous Scanner - Intelligent Vulnerability Discovery"""
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="Target domain or URL")
@click.option("--modules", "-m", default="all",
              help="Comma-separated modules: recon,crawl,sqli,xss,cmdi,idor,auth (default: all)")
@click.option("--depth", "-d", default=3, show_default=True, help="Crawl depth")
@click.option("--threads", default=10, show_default=True, help="Concurrent threads")
@click.option("--output", "-o", default="html,json", help="Output formats (html,json,markdown)")
@click.option("--output-dir", default="reports", help="Directory for reports")
@click.option("--auth-token", help="Bearer token for authenticated scans")
@click.option("--cookie", multiple=True, help="Cookie in name=value format (repeat for multiple)")
@click.option("--full", is_flag=True, help="Run full scan with all modules")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--no-confirm", is_flag=True, help="Skip ethics confirmation prompt")
@click.option("--continuous", is_flag=True, help="Run continuously on interval")
@click.option("--interval", default=3600, help="Continuous scan interval in seconds")
def scan(
    target, modules, depth, threads, output, output_dir,
    auth_token, cookie, full, quiet, no_confirm, continuous, interval
):
    """Run an autonomous vulnerability scan against a target."""
    if not quiet:
        print_banner()
        print_ethics_warning()

    if not no_confirm and not confirm_scan(target):
        console.print("[red]Scan cancelled.[/red]")
        sys.exit(0)

    # Parse modules
    if full or modules == "all":
        module_list = ["recon", "crawl", "sqli", "xss", "cmdi", "idor", "auth"]
    else:
        module_list = [m.strip() for m in modules.split(",")]

    # Parse cookies
    cookies = {}
    for c in cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k] = v

    output_formats = [f.strip() for f in output.split(",")]

    async def run():
        from core.config import ScanConfig
        from core.session import ScanSession
        from recon.engine import ReconEngine
        from crawler.engine import CrawlerEngine
        from scanner.sqli import SQLiScanner
        from scanner.scanners import XSSScanner, CMDiScanner, IDORScanner, AuthScanner
        from ai_engine.engine import AIEngine
        from risk_engine.scorer import RiskScorer
        from reporter.generator import ReportGenerator
        from core.models import ScanResult, ScanStatus
        import time as time_mod

        config = ScanConfig(
            target=target, depth=depth, threads=threads,
            modules=module_list, output_formats=output_formats,
            auth_token=auth_token, cookies=cookies,
        )

        result = ScanResult(
            target=target, status=ScanStatus.RUNNING,
            started_at=__import__("datetime").datetime.utcnow(),
        )

        start = time_mod.time()

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, style="cyan", complete_style="green"),
            TextColumn("[cyan]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            overall = progress.add_task("[cyan]Overall Progress", total=100)

            async with ScanSession(
                rate_limit=threads, timeout=config.timeout,
                cookies=cookies,
            ) as session:

                # Recon
                if "recon" in module_list:
                    task = progress.add_task("[blue]  🔭 Reconnaissance", total=1)
                    recon_engine = ReconEngine(session, config)
                    result.recon = await recon_engine.run(target)
                    progress.update(task, advance=1, description="[green]  ✅ Reconnaissance")
                    progress.update(overall, advance=20)
                    if not quiet and result.recon:
                        _print_recon_summary(result.recon)

                # Crawl
                if "crawl" in module_list:
                    task = progress.add_task("[blue]  🕷️  Crawling", total=1)
                    crawler = CrawlerEngine(session, config)
                    result.endpoints = await crawler.crawl(target)
                    progress.update(task, advance=1, description=f"[green]  ✅ Crawling ({len(result.endpoints)} endpoints)")
                    progress.update(overall, advance=15)

                # AI Planning
                task = progress.add_task("[blue]  🧠 AI Attack Planning", total=1)
                ai_engine = AIEngine()
                result.attack_vectors = await ai_engine.plan_attacks(result.endpoints, result.recon)
                progress.update(task, advance=1, description=f"[green]  ✅ AI Planning ({len(result.attack_vectors)} vectors)")
                progress.update(overall, advance=5)

                # Vulnerability Scanning
                scanner_configs = [
                    ("sqli",     "💉 SQL Injection",     SQLiScanner),
                    ("xss",      "📜 XSS",               XSSScanner),
                    ("cmdi",     "⚡ Cmd Injection",     CMDiScanner),
                    ("idor",     "🔑 IDOR",               IDORScanner),
                    ("auth",     "🔐 Authentication",     AuthScanner),
                ]

                per_scanner_pct = 40 // len([s for s in scanner_configs if s[0] in module_list]) or 1
                for mod_name, display_name, ScannerClass in scanner_configs:
                    if mod_name not in module_list:
                        continue
                    task = progress.add_task(f"[blue]  {display_name}", total=1)
                    scanner = ScannerClass(session, config)
                    vulns = await scanner.scan(result.endpoints, result.attack_vectors)
                    result.vulnerabilities.extend(vulns)
                    progress.update(task, advance=1,
                        description=f"[green]  ✅ {display_name} ({len(vulns)} found)")
                    progress.update(overall, advance=per_scanner_pct)

                # Risk Scoring
                task = progress.add_task("[blue]  📊 Risk Scoring", total=1)
                scorer = RiskScorer()
                result.vulnerabilities = scorer.score_all(result.vulnerabilities)
                progress.update(task, advance=1, description="[green]  ✅ Risk Scoring")
                progress.update(overall, advance=5)

                # Reporting
                task = progress.add_task("[blue]  📄 Generating Reports", total=1)
                reporter = ReportGenerator(output_dir)
                report_paths = await reporter.generate_all(result)
                progress.update(task, advance=1, description="[green]  ✅ Reports Generated")
                progress.update(overall, completed=100)

        result.duration_seconds = time_mod.time() - start
        result.status = ScanStatus.COMPLETED

        # Final summary
        _print_final_summary(result, report_paths)

    asyncio.run(run())


def _print_recon_summary(recon):
    """Print recon findings as a rich table."""
    table = Table(title="🔭 Reconnaissance Results", box=box.ROUNDED,
                  border_style="blue", title_style="bold cyan")
    table.add_column("Item", style="cyan", min_width=20)
    table.add_column("Value", style="white")

    if recon.subdomains:
        table.add_row("Subdomains", f"{len(recon.subdomains)} found: " + ", ".join(recon.subdomains[:5]))
    if recon.technologies:
        table.add_row("Technologies", ", ".join(recon.technologies))
    if recon.ip_addresses:
        table.add_row("IP Addresses", ", ".join(recon.ip_addresses[:5]))
    if recon.server_info:
        server = recon.server_info.get("server", "Unknown")
        table.add_row("Server", server or "Not disclosed")
        for header in ["x_frame", "hsts", "csp"]:
            val = recon.server_info.get(header, "MISSING")
            color = "green" if val != "MISSING" else "red"
            table.add_row(header.upper().replace("_", "-"), f"[{color}]{val}[/{color}]")

    console.print()
    console.print(table)


def _print_final_summary(result, report_paths: dict):
    """Print the final scan summary."""
    console.print()
    console.rule("[bold cyan]Scan Complete", style="cyan")
    console.print()

    # Risk gauge
    risk_colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
                   "LOW": "cyan", "NONE": "green"}
    risk_color = risk_colors.get(result.overall_risk, "white")
    console.print(
        Panel(
            f"[bold {risk_color}]{result.overall_risk} RISK[/bold {risk_color}]\n"
            f"[dim]Target: {result.target} | Duration: {result.duration_seconds:.1f}s[/dim]",
            border_style=risk_color,
        )
    )
    console.print()

    # Vulnerability breakdown table
    if result.vulnerabilities:
        table = Table(
            title=f"🐛 {len(result.vulnerabilities)} Vulnerabilities Found",
            box=box.ROUNDED, border_style="cyan", title_style="bold",
        )
        table.add_column("Severity", min_width=12)
        table.add_column("Count", justify="right")
        table.add_column("Sample Finding")

        for sev_val, color in [("critical","red"),("high","orange1"),("medium","yellow"),("low","cyan")]:
            matching = [v for v in result.vulnerabilities if v.severity.value == sev_val]
            if matching:
                table.add_row(
                    f"[bold {color}]{sev_val.upper()}[/bold {color}]",
                    f"[bold {color}]{len(matching)}[/bold {color}]",
                    matching[0].title[:60],
                )
        console.print(table)
    else:
        console.print("[bold green]✅ No vulnerabilities detected.[/bold green]")

    # Report paths
    console.print()
    console.print("[bold]📄 Reports saved:[/bold]")
    for fmt, path in report_paths.items():
        console.print(f"  [cyan]{fmt:10}[/cyan] → {path}")
    console.print()


@cli.command()
@click.option("--target", "-t", required=True, help="Target domain for recon only")
def recon(target):
    """Run reconnaissance only (no vulnerability scanning)."""
    print_banner()

    async def run():
        from core.config import ScanConfig
        from core.session import ScanSession
        from recon.engine import ReconEngine

        config = ScanConfig(target=target)
        async with ScanSession() as session:
            with console.status("[cyan]Running reconnaissance...[/cyan]"):
                engine = ReconEngine(session, config)
                result = await engine.run(target)
            _print_recon_summary(result)

    asyncio.run(run())


@cli.command()
@click.argument("report_path")
def view(report_path):
    """Open a scan report in the browser."""
    import webbrowser
    path = Path(report_path)
    if not path.exists():
        console.print(f"[red]Report not found: {report_path}[/red]")
        sys.exit(1)
    webbrowser.open(f"file://{path.absolute()}")
    console.print(f"[green]Opening {path.name} in browser...[/green]")


@cli.command()
def serve():
    """Start the API server and open the dashboard."""
    import uvicorn
    console.print("[cyan]Starting AI Bug Bounty Scanner API...[/cyan]")
    console.print("[green]Dashboard: http://localhost:3000[/green]")
    console.print("[green]API docs:   http://localhost:8000/api/docs[/green]")
    uvicorn.run("core.api:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    cli()
