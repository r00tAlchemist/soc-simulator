from __future__ import annotations
import sys
import json
import time
import random
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

import click

from models import Scenario, SiemAlert, WorldState
from world import build_world, apply_world_overrides
from generator import NormalActivityGenerator
from player import AttackScenarioPlayer
from session_builder import SessionBuilder
from scenario_loader import load_scenario
from exporter import Exporter
from scorer import Scorer

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _print_alert(alert: SiemAlert, world: WorldState, first_event_time: str) -> None:
    w = world.__dict__
    try:
        summary = alert.summary.format(**w)
        description = alert.description.format(**w)
    except KeyError:
        summary = alert.summary
        description = alert.description

    sev = alert.severity.upper()
    W = 72
    inner = W - 4
    sep = "+" + "-" * (W - 2) + "+"

    def row(text: str) -> str:
        return f"| {text:<{inner}} |"

    print()
    print(sep)
    print(row(f"SIEM ALERT  [{sev}]  —  Rule: {alert.rule_id}"))
    print(row(f"Triggered: {first_event_time}"))
    print("|" + "-" * (W - 2) + "|")
    for line in _wrap(summary, inner):
        print(row(line))
    if description:
        print(row(""))
        for line in _wrap(description, inner):
            print(row(line))
    print(sep)
    print()


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + (1 if current else 0) <= width:
            current = f"{current} {word}" if current else word
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


@click.command()
@click.option("--scenario", default=None, hidden=True, help="Force a specific scenario (dev use)")
@click.option("--logs", default=1000, show_default=True, help="Target number of log entries")
@click.option("--output", default="session.csv", show_default=True, help="Output file path")
@click.option("--format", "fmt", default="html", type=click.Choice(["csv", "ndjson", "html"]), show_default=True)
@click.option("--seed", default=None, type=int, help="Random seed for reproducibility")
def main(scenario: str | None, logs: int, output: str, fmt: str, seed: int | None) -> None:
    try:
        _run(scenario, logs, output, fmt, seed)
    except (ValueError, FileNotFoundError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nAborted.", err=True)
        sys.exit(1)


def _run(scenario_name: str | None, target_logs: int, output: str, fmt: str, seed: int | None) -> None:
    scenarios_dir = Path(__file__).parent / "scenarios"

    if scenario_name:
        scenario_path = scenarios_dir / f"{scenario_name}.yml"
        if not scenario_path.exists():
            available = [p.stem for p in scenarios_dir.glob("*.yml")]
            raise FileNotFoundError(
                f"Scenario not found: {scenario_name}\nAvailable: {available}"
            )
    else:
        all_scenarios = list(scenarios_dir.glob("*.yml"))
        if not all_scenarios:
            raise FileNotFoundError(f"No scenario files found in {scenarios_dir}")
        rng = random.Random(seed)
        scenario_path = rng.choice(all_scenarios)

    scenario: Scenario = load_scenario(scenario_path)
    world = build_world(seed)
    apply_world_overrides(world, scenario.world_overrides)

    today = datetime.now().replace(hour=9, minute=0, second=0, microsecond=0)
    start_time = today
    end_time = today.replace(hour=11, minute=0)

    gen = NormalActivityGenerator(world, start_time, end_time)
    normal_logs = gen.generate(target_logs)

    player = AttackScenarioPlayer(scenario, world)
    attack_logs = player.play(inject_start=start_time)

    builder = SessionBuilder()
    merged, inject_start = builder.build(normal_logs, attack_logs, start_time, end_time)

    output_path = Path(output)
    if fmt == "html" and not output_path.suffix:
        output_path = output_path.with_suffix(".html")
    elif fmt == "html" and output_path.suffix != ".html":
        output_path = output_path.with_suffix(".html")

    # Resolve alert text and triggered time before export
    alert_rule = alert_summary = alert_description = alert_severity = alert_triggered = ""
    if scenario.meta.alert:
        trigger_events = [e for e in merged if e._phase_id]
        first_ts = (
            min(e.timestamp for e in trigger_events).strftime("%H:%M:%S")
            if trigger_events else merged[0].timestamp.strftime("%H:%M:%S")
        )
        alert = scenario.meta.alert
        w = world.__dict__
        try:
            alert_summary = alert.summary.format(**w)
            alert_description = alert.description.format(**w)
        except KeyError:
            alert_summary = alert.summary
            alert_description = alert.description
        alert_rule = alert.rule_id
        alert_severity = alert.severity
        alert_triggered = first_ts

    exporter = Exporter()
    if fmt == "csv":
        exporter.to_csv(merged, output_path)
    elif fmt == "ndjson":
        exporter.to_ndjson(merged, output_path)
    else:
        exporter.to_html(
            merged, output_path,
            alert_rule=alert_rule,
            alert_severity=alert_severity,
            alert_summary=alert_summary,
            alert_description=alert_description,
            alert_triggered=alert_triggered,
        )

    if scenario.meta.alert:
        _print_alert(scenario.meta.alert, world, alert_triggered)

    exporter.to_terminal(merged, head=20)
    click.echo(f"\nLog file: {output_path}  ({len(merged)} events total)")

    click.echo("")
    t_start = time.monotonic()
    raw = click.prompt("0 = FP  /  1 = INCIDENT").strip()
    while raw not in ("0", "1"):
        click.echo("Enter 0 (FP) or 1 (INCIDENT)")
        raw = click.prompt("0 = FP  /  1 = INCIDENT").strip()
    answer = "FP" if raw == "0" else "INCIDENT"

    time_taken = time.monotonic() - t_start

    scorer = Scorer()
    result = scorer.score(answer, [], scenario, merged, time_taken)

    sessions_dir = Path(__file__).parent / "sessions"
    sessions_dir.mkdir(exist_ok=True)
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = scenario_path.stem
    session_file = sessions_dir / f"{safe_name}_{ts_str}.json"
    session_file.write_text(json.dumps(result.to_json(), indent=2))
    click.echo(f"Session saved to {session_file}")


if __name__ == "__main__":
    main()
