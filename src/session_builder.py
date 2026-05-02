from __future__ import annotations
import random
from datetime import datetime, timedelta
from models import LogEntry


class SessionBuilder:
    def build(
        self,
        normal: list[LogEntry],
        attack: list[LogEntry],
        start_time: datetime,
        end_time: datetime,
    ) -> tuple[list[LogEntry], datetime]:
        margin = timedelta(minutes=15)
        inject_start = start_time + margin + timedelta(
            seconds=random.uniform(0, (end_time - start_time - 2 * margin).total_seconds())
        )

        if attack:
            attack_base = min(e.timestamp for e in attack)
            delta = inject_start - attack_base
            for entry in attack:
                entry.timestamp = entry.timestamp + delta

        merged = sorted(normal + attack, key=lambda e: e.timestamp)
        return merged, inject_start
