from __future__ import annotations
import random
import hashlib
from datetime import datetime
from models import LogEntry, WorldState


def _resolve(params: dict, world: WorldState) -> tuple[str, str, str]:
    user = params.get("target_user") or params.get("user") or random.choice(world.users)
    host = params.get("dest_host") or params.get("host") or random.choice(list(world.hosts.keys()))
    src_ip = params.get("source_ip") or world.host_ip(host)
    return user, host, src_ip


def _fake_sha256() -> str:
    return hashlib.sha256(random.randbytes(32)).hexdigest().upper()


def process_create(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    images = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\powershell.exe",
        "C:\\Windows\\System32\\wscript.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\explorer.exe",
    ]
    parents = [
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\services.exe",
    ]
    cmd = params.get("command_line")
    image = params.get("image") or random.choice(images)
    if not cmd:
        cmd = image
    return LogEntry(
        timestamp=timestamp,
        source_type="Sysmon",
        source_ip=src_ip,
        dest_host=host,
        event_id=1,
        user=user,
        details={
            "image": image,
            "command_line": cmd,
            "parent_image": params.get("parent_image") or random.choice(parents),
            "sha256": _fake_sha256(),
            "pid": random.randint(1000, 65535),
        },
    )


def network_connect(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    dest_ip = params.get("dest_ip") or f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    dest_port = params.get("dest_port") or random.choice([80, 443, 8080, 445, 135, 3389])
    return LogEntry(
        timestamp=timestamp,
        source_type="Sysmon",
        source_ip=src_ip,
        dest_host=host,
        event_id=3,
        user=user,
        details={
            "protocol": "tcp",
            "source_port": random.randint(49152, 65535),
            "dest_ip": dest_ip,
            "dest_port": dest_port,
        },
    )


def dns_query(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    domains = [
        "windowsupdate.microsoft.com",
        "ctldl.windowsupdate.com",
        "login.microsoftonline.com",
        "www.google.com",
        "ocsp.digicert.com",
    ]
    query_name = params.get("query_name") or random.choice(domains)
    result_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return LogEntry(
        timestamp=timestamp,
        source_type="Sysmon",
        source_ip=src_ip,
        dest_host=host,
        event_id=22,
        user=user,
        details={
            "query_name": query_name,
            "query_results": f"type: 1 {result_ip}",
        },
    )


def file_create(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    filenames = [
        "C:\\Users\\Public\\Downloads\\update.exe",
        "C:\\Temp\\tmp_install.msi",
        "C:\\Windows\\Temp\\svchost32.exe",
    ]
    fname = params.get("target_filename") or params.get("file") or random.choice(filenames)
    
    if len(fname) < 3 or fname[1:3] != ":\\":
        fname = f"C:\\Users\\{user}\\Downloads\\{fname}"
    return LogEntry(
        timestamp=timestamp,
        source_type="Sysmon",
        source_ip=src_ip,
        dest_host=host,
        event_id=11,
        user=user,
        details={
            "target_filename": fname,
            "image": params.get("image") or "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        },
    )
