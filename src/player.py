from __future__ import annotations
import random
from datetime import datetime, timedelta
from models import LogEntry, Scenario, WorldState
from log_factories import resolve_factory


class AttackScenarioPlayer:
    def __init__(self, scenario: Scenario, world: WorldState):
        self.scenario = scenario
        self.world = world

    def play(self, inject_start: datetime) -> list[LogEntry]:
        logs: list[LogEntry] = []
        current_time = inject_start

        for phase in self.scenario.phases:
            world_dict = self.world.__dict__

            base_params: dict = {}
            list_params: dict = {}
            for k, v in phase.params.items():
                if isinstance(v, list):
                    list_params[k] = v
                elif isinstance(v, str):
                    try:
                        base_params[k] = v.format(**world_dict)
                    except KeyError:
                        base_params[k] = v
                else:
                    base_params[k] = v

            factory = resolve_factory(phase.log_factory)
            spread = phase.spread_seconds

            for i in range(phase.count):
                resolved_params = dict(base_params)
                for k, options in list_params.items():
                    chosen = random.choice(options)
                    try:
                        resolved_params[k] = chosen.format(**world_dict) if isinstance(chosen, str) else chosen
                    except KeyError:
                        resolved_params[k] = chosen

                offset = (spread / (phase.count - 1)) * i if phase.count > 1 else 0
                ts = current_time + timedelta(seconds=offset + random.uniform(-2, 2))
                entry = factory(ts, self.world, resolved_params)
                entry._is_attack = not self.scenario.is_clean
                entry._phase_id = phase.id
                logs.append(entry)

            delay = random.randint(*phase.delay_after_prev)
            current_time += timedelta(seconds=spread + delay)

        return logs
