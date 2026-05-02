from __future__ import annotations
import random
from datetime import datetime
from models import LogEntry, WorldState


def _resolve(params: dict, world: WorldState) -> tuple[str, str, str]:
    user = params.get("target_user") or params.get("user") or random.choice(world.users)
    host = params.get("dest_host") or params.get("host") or random.choice(list(world.hosts.keys()))
    src_ip = params.get("source_ip") or world.host_ip(host)
    return user, host, src_ip


def failed_logon(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    return LogEntry(
        timestamp=timestamp,
        source_type="Windows-Security",
        source_ip=src_ip,
        dest_host=host,
        event_id=4625,
        user=user,
        details={
            "auth_package": "NTLM",
            "failure_reason": "Unknown user name or bad password",
            "sub_status": "0xC000006A",
            "logon_type": 3,
            "workstation_name": random.choice(list(world.hosts.keys())),
        },
    )


def successful_logon(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    return LogEntry(
        timestamp=timestamp,
        source_type="Windows-Security",
        source_ip=src_ip,
        dest_host=host,
        event_id=4624,
        user=user,
        details={
            "auth_package": random.choice(["Kerberos", "NTLM"]),
            "logon_type": random.choice([2, 3, 10]),
            "logon_id": hex(random.randint(0x10000, 0xFFFFFF)),
        },
    )


def logoff(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    return LogEntry(
        timestamp=timestamp,
        source_type="Windows-Security",
        source_ip=src_ip,
        dest_host=host,
        event_id=4634,
        user=user,
        details={"logon_type": 3, "logon_id": hex(random.randint(0x10000, 0xFFFFFF))},
    )


def process_create(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    commands = [
        "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        "C:\\Windows\\System32\\cmd.exe /c ipconfig /all",
        "C:\\Program Files\\Windows Defender\\MpCmdRun.exe -Scan -ScanType 1",
        "C:\\Windows\\System32\\tasklist.exe",
        "C:\\Windows\\System32\\net.exe use",
    ]
    cmd = params.get("command_line") or random.choice(commands)
    return LogEntry(
        timestamp=timestamp,
        source_type="Windows-Security",
        source_ip=src_ip,
        dest_host=host,
        event_id=4688,
        user=user,
        details={
            "new_process_name": cmd.split()[0] if cmd else "unknown",
            "command_line": cmd,
            "pid": random.randint(1000, 65535),
            "token_elevation_type": random.choice(["%%1936", "%%1937", "%%1938"]),
        },
    )


def account_added_to_group(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    groups = ["Administrators", "Remote Desktop Users", "Backup Operators", "Power Users"]
    return LogEntry(
        timestamp=timestamp,
        source_type="Windows-Security",
        source_ip=src_ip,
        dest_host=host,
        event_id=4732,
        user=user,
        details={
            "group_name": params.get("group_name") or random.choice(groups),
            "member_sid": f"S-1-5-21-{random.randint(100000,999999)}-{random.randint(100000,999999)}-{random.randint(1000,9999)}",
        },
    )


def log_cleared(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    return LogEntry(
        timestamp=timestamp,
        source_type="Windows-Security",
        source_ip=src_ip,
        dest_host=host,
        event_id=1102,
        user=user,
        details={"channel": "Security", "backup_path": ""},
    )


def scheduled_task_created(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    task_names = ["\\Microsoft\\Windows\\UpdateCheck", "\\Backup\\DailyBackup", "\\Maintenance\\CleanTemp"]
    task_name = params.get("task_name") or random.choice(task_names)
    xml = f'<Task><Actions><Exec><Command>C:\\Windows\\System32\\cmd.exe</Command></Exec></Actions><Triggers><TimeTrigger><StartBoundary>2024-01-01T00:00:00</StartBoundary></TimeTrigger></Triggers></Task>'
    return LogEntry(
        timestamp=timestamp,
        source_type="Windows-Security",
        source_ip=src_ip,
        dest_host=host,
        event_id=4698,
        user=user,
        details={"task_name": task_name, "task_content": params.get("task_content") or xml},
    )
