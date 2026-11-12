"""Generate a synthetic Windows Security log with benign noise plus attack scenarios.

Scenarios: brute force -> success (jsmith), password spray (10 users from one IP),
off-hours RDP, lockout, new account + admin group add, explicit creds, log cleared.
All IPs use documentation ranges (RFC 5737) and fake users.
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)
BASE = datetime(2026, 11, 3, 8, 0, tzinfo=timezone.utc)
USERS = ["jsmith", "adoe", "mlee", "rpatel", "kchen", "tbrown", "slopez", "nkim", "pwang", "ojones"]
HOST = "WS-FIN-01.corp.local"
events = []


def ev(eid, t, **kw):
    events.append({"EventID": eid, "TimeCreated": t.isoformat().replace("+00:00", "Z"),
                   "Computer": kw.pop("Computer", HOST), **kw})


# benign workday logons
for day in range(3):
    for u in USERS:
        t = BASE + timedelta(days=day, minutes=random.randint(0, 90))
        ev(4624, t, TargetUserName=u, TargetDomainName="CORP", IpAddress=f"10.10.1.{random.randint(10, 60)}",
           LogonType=random.choice([2, 3]), WorkstationName=f"WS-{u.upper()}")
        if random.random() < 0.3:  # a typo now and then
            ev(4625, t - timedelta(seconds=20), TargetUserName=u, IpAddress="10.10.1.20", LogonType=3,
               Status="0xC000006A")

# 1) brute force against jsmith then success  (T1110.001 -> T1078)
t = BASE + timedelta(days=1, hours=5, minutes=3)
for i in range(18):
    ev(4625, t + timedelta(seconds=12 * i), TargetUserName="jsmith", TargetDomainName="CORP",
       IpAddress="203.0.113.45", LogonType=3, Status="0xC000006A", WorkstationName="KALI")
ev(4624, t + timedelta(minutes=4), TargetUserName="jsmith", TargetDomainName="CORP",
   IpAddress="203.0.113.45", LogonType=3, WorkstationName="KALI")

# 2) password spray from one IP across 10 users (T1110.003)
t = BASE + timedelta(days=2, hours=2, minutes=10)
for i, u in enumerate(USERS):
    ev(4625, t + timedelta(seconds=30 * i), TargetUserName=u, IpAddress="198.51.100.23", LogonType=3,
       Status="0xC000006A", WorkstationName="-")

# 3) off-hours RDP (T1021.001)
ev(4624, BASE + timedelta(days=2, hours=15, minutes=41), TargetUserName="adoe", IpAddress="192.0.2.77",
   LogonType=10, WorkstationName="UNKNOWN-PC")

# 4) lockout
ev(4740, BASE + timedelta(days=1, hours=5, minutes=8), TargetUserName="mlee", WorkstationName="WS-FIN-01",
   Computer="DC01.corp.local")

# 5) persistence: new account + added to Administrators (T1136, T1098)
t = BASE + timedelta(days=1, hours=5, minutes=20)
ev(4720, t, TargetUserName="svc_backup2", SubjectUserName="jsmith", Computer="DC01.corp.local")
ev(4732, t + timedelta(seconds=40), TargetUserName="Administrators", SubjectUserName="jsmith",
   Computer="DC01.corp.local")

# 6) explicit credentials for several accounts (T1078/T1550)
for i, u in enumerate(["administrator", "svc_sql", "rpatel"]):
    ev(4648, t + timedelta(minutes=2, seconds=15 * i), SubjectUserName="jsmith", TargetUserName=u,
       IpAddress="-")

# 7) anti-forensics: log cleared (T1070.001)
ev(1102, t + timedelta(minutes=9), SubjectUserName="jsmith")

events.sort(key=lambda e: e["TimeCreated"])
out = Path(__file__).resolve().parents[1] / "data" / "sample_security_events.json"
out.write_text(json.dumps(events, indent=1))
print(f"wrote {len(events)} events -> {out}")
