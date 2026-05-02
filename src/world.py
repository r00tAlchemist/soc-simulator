from __future__ import annotations
import random
from faker import Faker
from models import WorldState


def build_world(seed: int | None = None, n_users: int = 20, n_workstations: int = 15, n_servers: int = 5) -> WorldState:
    rng = random.Random(seed)
    fake = Faker()
    if seed is not None:
        Faker.seed(seed)

    tld = "local"
    company = fake.company().split()[0].lower().replace(",", "").replace(".", "")
    domain = f"{company}.{tld}"

    x = rng.randint(10, 200)
    subnets = {
        "servers": f"10.{x}.1.0/24",
        "workstations": f"10.{x}.2.0/24",
    }

    hosts: dict[str, str] = {}
    server_names = ["DC01", "SRV02", "FS01"] + [f"SRV{i:02d}" for i in range(3, n_servers + 1)]
    for i, name in enumerate(server_names[:n_servers]):
        hosts[name] = f"10.{x}.1.{10 + i}"

    for i in range(1, n_workstations + 1):
        hosts[f"WS{i:03d}"] = f"10.{x}.2.{10 + i}"

    users: list[str] = []
    seen: set[str] = set()
    while len(users) < n_users - 3:
        fn = fake.first_name().lower()
        ln = fake.last_name().lower()
        uname = f"{fn}.{ln}"
        if uname not in seen:
            seen.add(uname)
            users.append(uname)

    users += ["svc_backup", "svc_scanner", "svc_deploy"]

    normal_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    ]

    return WorldState(
        domain=domain,
        users=users,
        hosts=hosts,
        subnets=subnets,
        normal_user_agents=normal_user_agents,
    )


def apply_world_overrides(world: WorldState, overrides: dict) -> None:
    for key, value in overrides.items():
        if key == "attacker_ip":
            world.attacker_ip = value
        elif key == "inject_malicious_host":
            world.inject_malicious_host = value
            if value not in world.hosts:
                world.hosts[value] = f"10.0.99.{random.randint(10, 250)}"
        elif key == "inject_malicious_user":
            world.inject_malicious_user = value
            if value not in world.users:
                world.users.append(value)
        else:
            setattr(world, key, value)
