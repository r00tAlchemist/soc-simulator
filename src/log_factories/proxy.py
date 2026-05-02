from __future__ import annotations
import random
from datetime import datetime
from urllib.parse import urlparse
from models import LogEntry, WorldState


def _resolve(params: dict, world: WorldState) -> tuple[str, str, str]:
    user = params.get("target_user") or params.get("user") or random.choice(world.users)
    host = params.get("dest_host") or params.get("host") or random.choice(list(world.hosts.keys()))
    src_ip = params.get("source_ip") or world.host_ip(host)
    return user, host, src_ip


def http_request(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    urls = [
        "http://windowsupdate.microsoft.com/v11/wuauth",
        "https://login.microsoftonline.com/oauth2/token",
        "http://ocsp.digicert.com/MFIwTzBNMEswSTAJBgUrDgMCGgUABBS",
        "https://www.google.com/generate_204",
        "https://clients2.google.com/service/update2",
    ]
    url = params.get("url") or random.choice(urls)
    parsed = urlparse(url)
    dest_host = parsed.netloc or host
    method = params.get("method") or random.choice(["GET", "GET", "GET", "POST"])
    ua = params.get("user_agent") or params.get("ua") or random.choice(world.normal_user_agents)
    status = params.get("status_code") or random.choice([200, 200, 200, 304, 403])
    return LogEntry(
        timestamp=timestamp,
        source_type="Proxy",
        source_ip=src_ip,
        dest_host=dest_host,
        event_id=0,
        user=user,
        details={
            "method": method,
            "url": url,
            "status_code": status,
            "bytes_sent": random.randint(200, 2000),
            "bytes_received": random.randint(500, 50000),
            "user_agent": ua,
            "proxy_action": "allowed",
        },
    )


def dns_lookup(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    user, host, src_ip = _resolve(params, world)
    domains = [
        "windowsupdate.microsoft.com",
        "login.microsoftonline.com",
        "www.google.com",
        "ocsp.digicert.com",
        "clients2.google.com",
    ]
    query_name = params.get("query_name") or random.choice(domains)
    result_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return LogEntry(
        timestamp=timestamp,
        source_type="DNS",
        source_ip=src_ip,
        dest_host=host,
        event_id=0,
        user=user,
        details={
            "query_name": query_name,
            "query_type": "A",
            "result": result_ip,
            "rcode": "NOERROR",
        },
    )


_SQLI_PAYLOADS = [
    "/login.php?user=admin'--&pass=x",
    "/products?id=1+UNION+SELECT+1,username,password+FROM+users--",
    "/search?q=%27+OR+1=1--",
    "/api/item?id=1;SELECT+SLEEP(5)--",
    "/index.php?page=1'+AND+1=2+UNION+SELECT+table_name+FROM+information_schema.tables--",
    "/user?id=1+AND+EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
]

_SCAN_PATHS = [
    "/.env", "/admin/", "/wp-admin/", "/phpmyadmin/", "/.git/config",
    "/api/swagger.json", "/actuator/env", "/console", "/manager/html",
    "/.well-known/security.txt", "/server-status", "/xmlrpc.php",
]


def web_attack(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    """HTTP log with SQLi/web exploitation payload."""
    user, host, src_ip = _resolve(params, world)
    base = params.get("url") or f"http://{host}"
    parsed = urlparse(base)
    dest_host = parsed.netloc or host
    payload = random.choice(_SQLI_PAYLOADS)
    url = base.rstrip("/") + payload
    status = params.get("status_code") or random.choice([200, 500, 500, 403])
    ua = params.get("user_agent") or params.get("ua") or random.choice([
        "sqlmap/1.7.12#stable (https://sqlmap.org)",
        "python-requests/2.31.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
    ])
    return LogEntry(
        timestamp=timestamp,
        source_type="Proxy",
        source_ip=src_ip,
        dest_host=dest_host,
        event_id=0,
        user=user,
        details={
            "method": "GET",
            "url": url,
            "status_code": status,
            "bytes_sent": random.randint(150, 600),
            "bytes_received": random.randint(200, 8000),
            "user_agent": ua,
            "proxy_action": "allowed",
            "attack_signature": "sql_injection",
        },
    )


def web_scan(timestamp: datetime, world: WorldState, params: dict) -> LogEntry:
    """HTTP log simulating automated vulnerability scanning."""
    user, host, src_ip = _resolve(params, world)
    base = params.get("url") or f"http://{host}"
    parsed = urlparse(base)
    dest_host = parsed.netloc or host
    path = random.choice(_SCAN_PATHS)
    url = f"{parsed.scheme}://{dest_host}{path}"
    status = random.choice([404, 404, 200, 403, 301])
    ua = params.get("user_agent") or params.get("ua") or random.choice([
        "Nikto/2.1.6",
        "masscan/1.3.2",
        "WPScan v3.8.25",
        "Nmap Scripting Engine",
        "DirBuster-1.0-RC1",
    ])
    return LogEntry(
        timestamp=timestamp,
        source_type="Proxy",
        source_ip=src_ip,
        dest_host=dest_host,
        event_id=0,
        user=user,
        details={
            "method": "GET",
            "url": url,
            "status_code": status,
            "bytes_sent": random.randint(100, 400),
            "bytes_received": random.randint(0, 1000),
            "user_agent": ua,
            "proxy_action": "allowed",
            "attack_signature": "web_scan",
        },
    )
