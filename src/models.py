from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import json


@dataclass
class LogEntry:
    timestamp: datetime
    source_type: str
    source_ip: str
    dest_host: str
    event_id: int
    user: str
    details: dict[str, Any]
    _is_attack: bool = False
    _phase_id: str = ""

    def to_csv_row(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_type": self.source_type,
            "event_id": self.event_id,
            "user": self.user,
            "source_ip": self.source_ip,
            "dest_host": self.dest_host,
            "details_json": json.dumps(self.details),
        }

    def to_json(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_type": self.source_type,
            "source_ip": self.source_ip,
            "dest_host": self.dest_host,
            "event_id": self.event_id,
            "user": self.user,
            "details": self.details,
            "_is_attack": self._is_attack,
            "_phase_id": self._phase_id,
        }

    def to_human_readable(self) -> str:
        ts = self.timestamp.strftime("%H:%M:%S")
        return f"[{ts}] {self.source_type:12s} EID={self.event_id:5d} user={self.user:20s} src={self.source_ip:15s} dst={self.dest_host}"


@dataclass
class WorldState:
    domain: str
    users: list[str]
    hosts: dict[str, str]
    subnets: dict[str, str]
    normal_user_agents: list[str]
    attacker_ip: str = ""
    inject_malicious_host: str = ""
    inject_malicious_user: str = ""

    def host_ip(self, hostname: str) -> str:
        return self.hosts.get(hostname, "10.0.0.1")


@dataclass
class MitreTechnique:
    id: str
    name: str

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"


@dataclass
class SiemAlert:
    rule_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    summary: str
    description: str = ""


@dataclass
class ScenarioMeta:
    name: str
    difficulty: str
    answer: str
    mitre_techniques: list[MitreTechnique]
    hint: str
    alert: SiemAlert | None = None
    scoring_correct_verdict: int = 100
    scoring_correct_technique: int = 50
    scoring_time_bonus: bool = True


@dataclass
class PhaseDefinition:
    id: str
    name: str
    technique: str
    count: int
    log_factory: str
    params: dict[str, Any]
    spread_seconds: int = 60
    delay_after_prev: tuple[int, int] = (5, 30)


@dataclass
class Scenario:
    meta: ScenarioMeta
    world_overrides: dict[str, Any]
    phases: list[PhaseDefinition]

    @property
    def is_clean(self) -> bool:
        return self.meta.answer == "FP"


@dataclass
class SessionResult:
    scenario_name: str
    true_answer: str
    user_answer: str
    is_correct: bool
    score: int
    time_taken_seconds: float
    phase_breakdown: list[dict[str, Any]]
    techniques_identified: list[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "true_answer": self.true_answer,
            "user_answer": self.user_answer,
            "is_correct": self.is_correct,
            "score": self.score,
            "time_taken_seconds": self.time_taken_seconds,
            "phase_breakdown": self.phase_breakdown,
            "techniques_identified": self.techniques_identified,
        }
