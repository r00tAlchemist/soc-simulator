from __future__ import annotations
import random
from datetime import datetime, timedelta
from models import LogEntry, WorldState
from log_factories import windows_security, sysmon, proxy


class NormalActivityGenerator:
    def __init__(self, world: WorldState, start_time: datetime, end_time: datetime):
        self.world = world
        self.start_time = start_time
        self.end_time = end_time
        self._span = (end_time - start_time).total_seconds()

    def _rand_ts(self) -> datetime:
        return self.start_time + timedelta(seconds=random.uniform(0, self._span))

    def generate(self, target_count: int = 1000) -> list[LogEntry]:
        logs: list[LogEntry] = []
        world = self.world

        for user in world.users:
            t = self.start_time + timedelta(seconds=random.uniform(0, 300))
            while t < self.end_time:
                host = random.choice(list(world.hosts.keys()))
                logs.append(windows_security.successful_logon(t, world, {"user": user, "dest_host": host}))
                if random.random() < 0.03:
                    fail_t = t - timedelta(seconds=random.randint(1, 30))
                    logs.append(windows_security.failed_logon(fail_t, world, {"user": user, "dest_host": host}))
                t += timedelta(minutes=random.randint(5, 15))

        for host in list(world.hosts.keys()):
            t = self.start_time + timedelta(seconds=random.uniform(0, 180))
            while t < self.end_time:
                logs.append(sysmon.process_create(t, world, {"dest_host": host}))
                t += timedelta(minutes=random.randint(3, 7))

        t = self.start_time + timedelta(seconds=random.uniform(0, 240))
        while t < self.end_time:
            logs.append(sysmon.network_connect(t, world, {}))
            t += timedelta(minutes=random.randint(4, 8))

        t = self.start_time + timedelta(seconds=random.uniform(0, 60))
        while t < self.end_time:
            logs.append(sysmon.dns_query(t, world, {}))
            t += timedelta(minutes=random.randint(1, 3))

        t = self.start_time + timedelta(seconds=random.uniform(0, 480))
        while t < self.end_time:
            logs.append(sysmon.file_create(t, world, {}))
            t += timedelta(minutes=random.randint(8, 15))

        t = self.start_time + timedelta(seconds=random.uniform(0, 60))
        while t < self.end_time:
            logs.append(proxy.http_request(t, world, {}))
            t += timedelta(minutes=random.randint(1, 3))

        t = self.start_time + timedelta(seconds=random.uniform(0, 120))
        while t < self.end_time:
            logs.append(proxy.dns_lookup(t, world, {}))
            t += timedelta(minutes=random.randint(2, 5))

        t = self.start_time + timedelta(seconds=random.uniform(0, 180))
        while t < self.end_time:
            logs.append(windows_security.process_create(t, world, {}))
            t += timedelta(minutes=random.randint(3, 6))

        for user in random.sample(world.users, min(10, len(world.users))):
            t = self.start_time + timedelta(minutes=random.randint(30, 90))
            while t < self.end_time:
                host = random.choice(list(world.hosts.keys()))
                logs.append(windows_security.logoff(t, world, {"user": user, "dest_host": host}))
                t += timedelta(minutes=random.randint(10, 25))

        for _ in range(random.randint(2, 5)):
            logs.append(windows_security.account_added_to_group(self._rand_ts(), world, {}))

        if random.random() < 0.4:
            logs.append(windows_security.log_cleared(self._rand_ts(), world, {}))

        for _ in range(random.randint(3, 6)):
            logs.append(windows_security.scheduled_task_created(self._rand_ts(), world, {}))

        logs.sort(key=lambda e: e.timestamp)

        if len(logs) > target_count:
            attack_logs = [l for l in logs if l._is_attack]
            normal_logs = [l for l in logs if not l._is_attack]
            keep = random.sample(normal_logs, min(target_count - len(attack_logs), len(normal_logs)))
            logs = sorted(attack_logs + keep, key=lambda e: e.timestamp)

        return logs
