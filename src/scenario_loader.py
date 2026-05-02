from __future__ import annotations
from pathlib import Path
import yaml
from models import Scenario, ScenarioMeta, MitreTechnique, PhaseDefinition, SiemAlert


def load_scenario(path: Path) -> Scenario:
    raw = yaml.safe_load(path.read_text())

    if "meta" not in raw:
        raise ValueError(f"Scenario {path} missing 'meta' section")

    m = raw["meta"]
    for f in ("name", "difficulty", "answer"):
        if f not in m:
            raise ValueError(f"Scenario {path} meta missing field: {f!r}")

    techniques = []
    for t in m.get("mitre_techniques", []):
        if isinstance(t, dict):
            techniques.append(MitreTechnique(id=t["id"], name=t.get("name", "")))
        elif isinstance(t, str):
            techniques.append(MitreTechnique(id=t, name=""))

    alert: SiemAlert | None = None
    if "alert" in m:
        a = m["alert"]
        alert = SiemAlert(
            rule_id=a.get("rule_id", "UNKNOWN_001"),
            severity=a.get("severity", "MEDIUM"),
            summary=a.get("summary", ""),
            description=a.get("description", ""),
        )

    meta = ScenarioMeta(
        name=m["name"],
        difficulty=m["difficulty"],
        answer=m["answer"],
        mitre_techniques=techniques,
        hint=m.get("hint", ""),
        alert=alert,
        scoring_correct_verdict=m.get("scoring_correct_verdict", 100),
        scoring_correct_technique=m.get("scoring_correct_technique", 50),
        scoring_time_bonus=m.get("scoring_time_bonus", True),
    )

    world_overrides = raw.get("world_overrides", {}) or {}

    phases: list[PhaseDefinition] = []
    for phase_id, pd in (raw.get("phases") or {}).items():
        if not isinstance(pd, dict):
            continue
        delay_raw = pd.get("delay_after_prev", [5, 30])
        delay = tuple(delay_raw) if isinstance(delay_raw, list) else (5, 30)

        phases.append(PhaseDefinition(
            id=phase_id,
            name=pd.get("name", phase_id),
            technique=pd.get("technique", ""),
            count=pd.get("count", 1),
            log_factory=pd["log_factory"],
            params=pd.get("params", {}) or {},
            spread_seconds=pd.get("spread_seconds", 60),
            delay_after_prev=delay,
        ))

    return Scenario(meta=meta, world_overrides=world_overrides, phases=phases)
