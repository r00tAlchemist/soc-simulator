from __future__ import annotations
from typing import Callable
from datetime import datetime

from models import LogEntry, WorldState
from log_factories import windows_security, sysmon, proxy

_REGISTRY: dict[str, Callable] = {
    "failed_logon": windows_security.failed_logon,
    "successful_logon": windows_security.successful_logon,
    "logoff": windows_security.logoff,
    "process_create": windows_security.process_create,
    "account_added_to_group": windows_security.account_added_to_group,
    "log_cleared": windows_security.log_cleared,
    "scheduled_task_created": windows_security.scheduled_task_created,
    "sysmon.process_create": sysmon.process_create,
    "sysmon.network_connect": sysmon.network_connect,
    "sysmon.dns_query": sysmon.dns_query,
    "sysmon.file_create": sysmon.file_create,
    "proxy.http_request": proxy.http_request,
    "proxy.dns_lookup": proxy.dns_lookup,
    "proxy.web_attack": proxy.web_attack,
    "proxy.web_scan": proxy.web_scan,
}


def resolve_factory(name: str) -> Callable[[datetime, WorldState, dict], LogEntry]:
    if name not in _REGISTRY:
        raise ValueError(f"Unknown log factory: {name!r}. Available: {list(_REGISTRY.keys())}")
    return _REGISTRY[name]


def list_factories() -> list[str]:
    return list(_REGISTRY.keys())
