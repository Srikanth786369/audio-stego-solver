"""
Audio Stego Solver - Main CLI entry point.
Rich CLI with Click commands for scanning audio files.
"""

import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .config import Config, generate_default_config
from .logger import setup_logger
from .scanner import AudioStegoScanner, SUPPORTED_FORMATS
from .utils import human_size

console = Console()

BANNER = """
╔═══════════════════════════════════════════════════╗
║          Audio Stego Solver v{version:<18} ║
║   Automated Audio Steganography Analysis Tool     ║
╚═══════════════════════════════════════════════════╝
""".format(version=__version__)


def print_banner():
    console.print(
        Panel(
            Text(BANNER.strip(), style="bold cyan", justify="center"),
            border_style="cyan",
            expand=False,
        )
    )


@click.group()
@click.version_option(version=__version__, prog_name="audio-stego")
def cli():
    """Audio Stego Solver - Automated steganography analysis for CTF audio files."""
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    default=None,
    help="Output directory (default: results/)",
    metavar="DIR",
)
@click.option(
    "--config", "-c",
    default=None,
    help="Path to config.ini file",
    metavar="FILE",
    type=click.Path(),
)
@click.option(
    "--workers", "-w",
    default=None,
    type=int,
    help="Number of parallel workers (default: 8)",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose/debug output",
)
@click.option(
    "--no-plugins",
    is_flag=True,
    default=False,
    help="Skip plugin execution",
)
@click.option(
    "--timeout", "-t",
    default=None,
    type=int,
    help="Per-tool timeout in seconds (default: 60)",
)
def scan(
    target: str,
    output: Optional[str],
    config: Optional[str],
    workers: Optional[int],
    verbose: bool,
    no_plugins: bool,
    timeout: Optional[int],
):
    """Scan an audio FILE or DIRECTORY for steganographic content.

    Examples:

    \b
      audio-stego scan challenge.wav
      audio-stego scan challenges/
      audio-stego scan challenge.wav --output results/ --verbose
      audio-stego scan challenge.wav --config custom.ini
    """
    print_banner()

    # Load configuration
    cfg = Config(config_file=config)

    # Override config with CLI options
    if output:
        cfg._config.set("general", "output_dir", output)
    if workers:
        cfg._config.set("general", "max_workers", str(workers))
    if verbose:
        cfg._config.set("general", "verbose", "true")
    if timeout:
        cfg._config.set("general", "timeout", str(timeout))
    if no_plugins:
        cfg._config.set("analysis", "run_plugins", "false")

    # Set up global logging
    setup_logger(
        log_dir=cfg.log_dir,
        log_file="commands.log",
        verbose=verbose,
    )

    target_path = Path(target)

    if target_path.is_dir():
        _scan_directory(target_path, cfg)
    elif target_path.is_file():
        _scan_file(target_path, cfg)
    else:
        console.print(f"[red]Error: Target not found: {target}[/red]")
        sys.exit(1)


def _scan_file(path: Path, cfg: Config):
    """Scan a single audio file. Plugins (if enabled via config/--no-plugins)
    already run as part of scanner.scan()'s own pipeline — do not run them
    again here."""
    ext = path.suffix.lower()
    if ext not in SUPPORTED_FORMATS:
        console.print(
            f"[yellow]Warning: '{ext}' may not be fully supported.\n"
            f"Supported formats: {', '.join(sorted(SUPPORTED_FORMATS))}[/yellow]"
        )
        if not click.confirm("Continue anyway?", default=True):
            return

    console.print(f"[bold green]Scanning:[/bold green] {path}")
    console.print(f"[dim]Size: {human_size(path.stat().st_size)}[/dim]\n")

    try:
        scanner = AudioStegoScanner(cfg, console=console)
        scanner.scan(str(path))

    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        if cfg.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _scan_directory(directory: Path, cfg: Config):
    """Scan all audio files in a directory."""
    audio_files = []
    for ext in SUPPORTED_FORMATS:
        audio_files.extend(directory.rglob(f"*{ext}"))
        audio_files.extend(directory.rglob(f"*{ext.upper()}"))

    # Deduplicate
    audio_files = sorted(set(audio_files))

    if not audio_files:
        console.print(
            f"[yellow]No supported audio files found in {directory}[/yellow]\n"
            f"Supported: {', '.join(sorted(SUPPORTED_FORMATS))}"
        )
        return

    console.print(
        f"[bold green]Found {len(audio_files)} audio file(s) in {directory}[/bold green]\n"
    )

    results_summary = []
    for i, audio_path in enumerate(audio_files, 1):
        console.rule(f"[bold cyan]File {i}/{len(audio_files)}: {audio_path.name}[/bold cyan]")
        try:
            scanner = AudioStegoScanner(cfg, console=console)
            results = scanner.scan(str(audio_path))

            flags = results.get("flags", {}).get("flags_found", [])
            results_summary.append({
                "file": audio_path.name,
                "flags": len(flags),
                "flag_values": [f.get("value", "") for f in flags[:3]],
            })
        except Exception as e:
            console.print(f"[red]Error scanning {audio_path.name}: {e}[/red]")
            results_summary.append({"file": audio_path.name, "flags": -1, "flag_values": []})

    # Print directory summary
    console.rule("[bold green]Directory Scan Complete[/bold green]")
    from rich.table import Table
    table = Table(title="Results Summary", show_header=True, header_style="bold cyan")
    table.add_column("File")
    table.add_column("Flags Found")
    table.add_column("Values")

    for entry in results_summary:
        flag_count = entry["flags"]
        if flag_count < 0:
            table.add_row(entry["file"], "[red]ERROR[/red]", "")
        elif flag_count > 0:
            table.add_row(
                entry["file"],
                f"[bold green]{flag_count}[/bold green]",
                "\n".join(entry["flag_values"]),
            )
        else:
            table.add_row(entry["file"], "[dim]0[/dim]", "")

    console.print(table)


@cli.command("gen-config")
@click.option(
    "--output", "-o",
    default="audio_stego.ini",
    help="Output config file path",
    metavar="FILE",
)
def gen_config(output: str):
    """Generate a default configuration file."""
    path = generate_default_config(output)
    console.print(f"[green]Default config written to: {path}[/green]")


@cli.command("list-plugins")
def list_plugins():
    """List all available plugins."""
    try:
        from .plugins.manager import PluginManager
        cfg = Config()
        pm = PluginManager(cfg)
        plugins = pm.discover()

        if not plugins:
            console.print("[yellow]No plugins found.[/yellow]")
            return

        from rich.table import Table
        table = Table(title="Available Plugins", header_style="bold cyan")
        table.add_column("Name")
        table.add_column("Version")
        table.add_column("Author")
        table.add_column("Description")
        table.add_column("Dependencies")
        table.add_column("File Types")

        for p in plugins:
            meta = p.metadata()
            table.add_row(
                meta["name"], meta["version"], meta["author"], meta["description"],
                ", ".join(meta["dependencies"]) or "-",
                ", ".join(meta["supported_file_types"]),
            )

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error listing plugins: {e}[/red]")


@cli.command("plugins")
@click.pass_context
def plugins_alias(ctx):
    """Alias for list-plugins."""
    ctx.invoke(list_plugins)


@cli.command()
def doctor():
    """Check environment health: required tools and optional Python packages."""
    from .utils import tool_available
    from rich.table import Table

    required_tools = ["file", "exiftool", "mediainfo", "ffprobe", "ffmpeg", "strings"]
    optional_tools = [
        "xxd", "hexdump", "binwalk", "foremost", "scalpel", "steghide", "stegseek",
        "tesseract", "zbarimg", "multimon-ng", "minimodem", "sox", "rx_sstv",
        "qsstv", "unzip", "unrar", "7z", "tar", "gzip",
    ]

    table = Table(title="Tool Health Check", header_style="bold cyan")
    table.add_column("Tool")
    table.add_column("Required")
    table.add_column("Status")
    all_required_ok = True
    for t in required_tools:
        ok = tool_available(t)
        all_required_ok = all_required_ok and ok
        table.add_row(t, "yes", "[green]OK[/green]" if ok else "[red]MISSING[/red]")
    for t in optional_tools:
        ok = tool_available(t)
        table.add_row(t, "no", "[green]OK[/green]" if ok else "[yellow]missing[/yellow]")
    console.print(table)

    pkg_table = Table(title="Python DSP Packages (optional)", header_style="bold cyan")
    pkg_table.add_column("Package")
    pkg_table.add_column("Status")
    for pkg in ("numpy", "scipy", "librosa", "soundfile", "matplotlib", "rich", "click"):
        try:
            import importlib.metadata
            try:
                version = importlib.metadata.version(pkg)
            except importlib.metadata.PackageNotFoundError:
                mod = __import__(pkg)
                version = getattr(mod, "__version__", "?")
            pkg_table.add_row(pkg, f"[green]OK[/green] ({version})")
        except ImportError:
            pkg_table.add_row(pkg, "[yellow]not installed[/yellow]")
    console.print(pkg_table)

    if all_required_ok:
        console.print("\n[green]All required tools are available.[/green]")
    else:
        console.print("\n[red]One or more required tools are missing — install them for full functionality.[/red]")
        sys.exit(1)


@cli.command()
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
def validate(target: str):
    """Validate TARGET's own file structure (magic bytes + real structural checks)."""
    from .utils import detect_file_type_by_magic
    from .validate import validate_embedded
    from .utils import read_bytes

    file_type = detect_file_type_by_magic(target)
    if file_type is None:
        console.print(f"[yellow]No known magic bytes matched at the start of {target}.[/yellow]")
        sys.exit(1)

    data = read_bytes(target, max_bytes=200 * 1024 * 1024)
    vr = validate_embedded(data, 0, file_type)

    console.print(f"[bold]File:[/bold] {target}")
    console.print(f"[bold]Detected type:[/bold] {file_type} -> reported as {vr.file_type}")
    console.print(f"[bold]Valid:[/bold] {'[green]yes[/green]' if vr.valid else '[red]no[/red]'}")
    console.print(f"[bold]Confidence:[/bold] {vr.confidence:.0%}  (evidence: {vr.evidence_level.value})")
    console.print(f"[bold]Reason:[/bold] {vr.reason}")
    if vr.false_positive_risk:
        console.print(f"[bold]False positive risk:[/bold] {vr.false_positive_risk}")
    if not vr.valid:
        sys.exit(1)


@cli.command()
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", default=None, help="Output directory for extraction artifacts")
def extract(target: str, output: Optional[str]):
    """Run only the extraction pipeline (no full scan) against TARGET."""
    from .artifact_store import ArtifactStore
    from .extraction import ExtractionAnalyzer
    from rich.table import Table

    cfg = Config()
    out_base = output or os.path.join(cfg.output_dir, Path(target).stem)
    store = ArtifactStore(out_base)
    ana = ExtractionAnalyzer(cfg, store)

    with console.status(f"Extracting from {target}..."):
        results = ana.run(target)

    s = results["summary"]
    table = Table(title="Extraction Results", header_style="bold cyan")
    table.add_column("Status")
    table.add_column("Count")
    for key in ("verified", "nested", "extracted", "recovered", "partial",
                "rejected", "false_positive", "corrupted", "unsupported", "skipped"):
        if s.get(key):
            table.add_row(key, str(s[key]))
    console.print(table)
    console.print(f"\n[bold]Artifacts written to:[/bold] {out_base}")


@cli.command()
@click.argument("text", required=False)
@click.option("--file", "file_path", type=click.Path(exists=True, dir_okay=False),
              help="Read TEXT from a file instead of the argument")
@click.option("--recursive/--no-recursive", default=True, help="Chain decodes (default: on)")
def decode(text: Optional[str], file_path: Optional[str], recursive: bool):
    """Try every supported blind-decodable encoding scheme (Base16/32/45/
    58/62/64/85, Binary, Octal, ROT13, Caesar (brute-forced), Atbash,
    Affine (brute-forced), Rail Fence (brute-forced), Bacon, Braille,
    Morse, URL, Quoted-Printable, UUEncode, XXEncode) against TEXT.
    JWT and Vigenere decoders exist in encoding_engine.py as library
    functions but require a key/aren't blind-guessable, so they aren't
    included in this automatic sweep."""
    from . import encoding_engine as ee

    if file_path:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    if not text:
        console.print("[red]Provide TEXT or --file[/red]")
        sys.exit(1)

    hits = ee.recursive_decode(text) if recursive else ee.decode_all(text)
    if not hits:
        console.print("[yellow]No scheme produced a plausible decode.[/yellow]")
        return

    from rich.table import Table
    table = Table(title="Decode Results", header_style="bold cyan")
    table.add_column("Scheme")
    table.add_column("Detail")
    table.add_column("Output")
    for hit in hits:
        table.add_row(hit.scheme, hit.reason, hit.output[:200])
    console.print(table)


@cli.command()
@click.argument("results_dir", type=click.Path(exists=True, file_okay=False))
def report(results_dir: str):
    """Print a summary of an existing scan's report.json."""
    import json as _json
    path = os.path.join(results_dir, "report.json")
    if not os.path.exists(path):
        console.print(f"[red]No report.json found in {results_dir}[/red]")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        data = _json.load(f)

    meta = data.get("meta", {})
    summary = data.get("summary", {})
    console.print(Panel(
        f"Tool: {meta.get('tool')} v{meta.get('version')}\n"
        f"File: {meta.get('audio_file')}\n"
        f"Generated: {meta.get('generated_at')}\n"
        f"Duration: {meta.get('elapsed_seconds')}s",
        title="Scan Report", border_style="cyan",
    ))
    console.print(f"Flags found: {summary.get('flags_found', 0)}")
    console.print(f"Total findings: {summary.get('total_findings', 0)}")
    for sev, count in summary.get("severity_counts", {}).items():
        if count:
            console.print(f"  {sev}: {count}")
    for flag in data.get("flags_found", [])[:10]:
        console.print(f"[bold red]FLAG:[/bold red] {flag.get('value', flag)}")


@cli.command()
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
def benchmark(target: str):
    """Run a full scan against TARGET and print a per-phase timing breakdown."""
    from rich.table import Table

    cfg = Config()
    scanner = AudioStegoScanner(cfg, console=console)
    results = scanner.scan(target)

    perf = results.get("_performance", {})
    phases = perf.get("phases", [])
    if not phases:
        console.print("[yellow]No timing data recorded.[/yellow]")
        return

    table = Table(title="Benchmark — Phase Timing", header_style="bold cyan")
    table.add_column("Phase")
    table.add_column("Seconds")
    total = sum(p["seconds"] for p in phases)
    for p in phases:
        table.add_row(p["phase"], f"{p['seconds']:.3f}")
    table.add_row("[bold]Total[/bold]", f"[bold]{total:.3f}[/bold]")
    console.print(table)


@cli.command()
@click.option("--output", "-o", default=None, help="Directory to remove (default: config output_dir)")
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation prompt")
def clean(output: Optional[str], yes: bool):
    """Remove a results/output directory. Destructive — asks for confirmation."""
    import shutil
    cfg = Config()
    target_dir = output or cfg.output_dir
    if not os.path.exists(target_dir):
        console.print(f"[yellow]{target_dir} does not exist — nothing to clean.[/yellow]")
        return
    if not yes and not click.confirm(f"Remove '{target_dir}' and everything under it?", default=False):
        console.print("Aborted.")
        return
    shutil.rmtree(target_dir)
    console.print(f"[green]Removed {target_dir}[/green]")


@cli.command()
@click.argument("results_dir", type=click.Path(exists=True, file_okay=False))
def verify(results_dir: str):
    """Re-hash extracted artifacts under RESULTS_DIR and confirm they still
    match the SHA256 recorded in report.json (chain-of-custody check)."""
    import hashlib
    import json as _json

    path = os.path.join(results_dir, "report.json")
    if not os.path.exists(path):
        console.print(f"[red]No report.json found in {results_dir}[/red]")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        data = _json.load(f)

    records = data.get("extraction_records", [])
    if not records:
        console.print("[yellow]No extraction records with SHA256 to verify in this report.[/yellow]")
        return

    mismatches = 0
    checked = 0
    for rec in records:
        sha = rec.get("sha256")
        out_path = rec.get("output_path")
        if not sha or not out_path or not os.path.exists(out_path):
            continue
        checked += 1
        h = hashlib.sha256()
        with open(out_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        if h.hexdigest() != sha:
            mismatches += 1
            console.print(f"[red]MISMATCH:[/red] {out_path} (recorded {sha[:16]}..., "
                          f"now {h.hexdigest()[:16]}...)")

    console.print(f"\nChecked {checked} artifact(s), {mismatches} mismatch(es).")
    if mismatches:
        sys.exit(1)


@cli.command()
@click.argument("results_dir", type=click.Path(exists=True, file_okay=False))
def stats(results_dir: str):
    """Print extraction/finding statistics from an existing scan's report.json."""
    import json as _json
    from rich.table import Table

    path = os.path.join(results_dir, "report.json")
    if not os.path.exists(path):
        console.print(f"[red]No report.json found in {results_dir}[/red]")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        data = _json.load(f)

    ext_summary = data.get("summary", {}).get("extraction_summary", {})
    table = Table(title="Extraction Statistics", header_style="bold cyan")
    table.add_column("Status")
    table.add_column("Count")
    for key, count in ext_summary.items():
        if count:
            table.add_row(key, str(count))
    console.print(table)

    records = data.get("extraction_records", [])
    if records:
        confidences = [r["confidence"] for r in records if r.get("confidence") is not None]
        if confidences:
            console.print(f"\nArtifacts: {len(records)}  "
                          f"Avg confidence: {sum(confidences)/len(confidences):.0%}  "
                          f"Max depth: {max(r.get('depth', 0) for r in records)}")


def main():
    """Entry point for the audio-stego CLI."""
    cli()


if __name__ == "__main__":
    main()
