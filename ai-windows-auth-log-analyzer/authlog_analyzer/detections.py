"""Detection rules for Windows authentication activity, mapped to MITRE ATT&CK."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import timedelta

from .parsers import Event

SEVERITY_POINTS = {"low": 10, "medium": 25, "high": 50, "critical": 80}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    mitre: list[str]
    description: str
    user: str = ""
    src_ip: str = ""
    host: str = ""
    count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Config:
    brute_force_threshold: int = 10
    brute_force_window_min: int = 5
    spray_user_threshold: int = 5
    spray_window_min: int = 10
    success_after_fail_min: int = 5
    work_start_hour: int = 7
    work_end_hour: int = 20
    admin_accounts: set[str] = field(default_factory=lambda: {"administrator", "admin"})


def _window_hits(events: list[Event], minutes: int):
    """Yield, for every event, the slice of events within *minutes* before it (sorted input)."""
    span = timedelta(minutes=minutes)
    j = 0
    for i in range(len(events)):
        while events[i].time - events[j].time > span:
            j += 1
        yield events[j:i + 1]


def _evidence(events: list[Event], n: int = 5) -> list[str]:
    return [f"{e.time.isoformat()} EID {e.event_id} user={e.user or '-'} ip={e.src_ip or '-'} "
            f"host={e.computer or '-'} logon_type={e.logon_type}" for e in events[:n]]


def _finding(rule_id, title, severity, mitre, desc, evs, **kw) -> Finding:
    return Finding(rule_id, title, severity, mitre, desc, count=len(evs),
                   first_seen=evs[0].time.isoformat(), last_seen=evs[-1].time.isoformat(),
                   evidence=_evidence(evs), **kw)


def brute_force(events, cfg):
    by_user = defaultdict(list)
    for e in events:
        if e.event_id == 4625 and e.user:
            by_user[e.user].append(e)
    for user, evs in by_user.items():
        best = max(_window_hits(evs, cfg.brute_force_window_min), key=len, default=[])
        if len(best) >= cfg.brute_force_threshold:
            ips = sorted({e.src_ip for e in best if e.src_ip})
            yield _finding("AUTH-001", "Brute-force against a single account", "high", ["T1110.001"],
                           f"{len(best)} failed logons for '{user}' within {cfg.brute_force_window_min} min "
                           f"from {', '.join(ips) or 'unknown source'}.", best, user=user,
                           src_ip=",".join(ips), host=best[0].computer)


def password_spray(events, cfg):
    by_ip = defaultdict(list)
    for e in events:
        if e.event_id == 4625 and e.src_ip:
            by_ip[e.src_ip].append(e)
    for ip, evs in by_ip.items():
        best, best_users = [], set()
        for win in _window_hits(evs, cfg.spray_window_min):
            users = {e.user for e in win}
            if len(users) > len(best_users):
                best, best_users = win, users
        if len(best_users) >= cfg.spray_user_threshold:
            yield _finding("AUTH-002", "Password spraying from one source", "high", ["T1110.003"],
                           f"{ip} failed against {len(best_users)} different accounts within "
                           f"{cfg.spray_window_min} min: {', '.join(sorted(best_users))}.",
                           best, src_ip=ip)  # targets aren't suspects, so they don't get risk points


def success_after_failures(events, cfg):
    fails = defaultdict(list)
    for e in events:
        key = (e.user, e.src_ip)
        if e.event_id == 4625:
            fails[key].append(e)
        elif e.event_id == 4624 and e.user and key in fails:
            recent = [f for f in fails[key] if e.time - f.time <= timedelta(minutes=10)]
            if len(recent) >= cfg.success_after_fail_min:
                yield _finding("AUTH-003", "Successful logon after repeated failures", "critical",
                               ["T1110", "T1078"],
                               f"'{e.user}' logged on from {e.src_ip or 'unknown'} after {len(recent)} "
                               "failures in 10 min - likely compromised credentials.",
                               recent + [e], user=e.user, src_ip=e.src_ip, host=e.computer)
                fails[key] = []


def off_hours_remote_logon(events, cfg):
    for e in events:
        if e.event_id == 4624 and e.logon_type in (3, 10) and e.user and not e.user.endswith("$"):
            h = e.time.hour
            if h < cfg.work_start_hour or h >= cfg.work_end_hour:
                mitre = ["T1078", "T1021.001"] if e.logon_type == 10 else ["T1078"]
                kind = "RDP" if e.logon_type == 10 else "network"
                yield _finding("AUTH-004", f"Off-hours {kind} logon", "medium", mitre,
                               f"'{e.user}' {kind} logon at {e.time:%H:%M} UTC from {e.src_ip or 'unknown'}.",
                               [e], user=e.user, src_ip=e.src_ip, host=e.computer)


def account_lockout(events, cfg):
    for e in events:
        if e.event_id == 4740:
            yield _finding("AUTH-005", "Account locked out", "medium", ["T1110"],
                           f"'{e.user}' was locked out (caller {e.workstation or 'unknown'}).",
                           [e], user=e.user, host=e.computer)


def explicit_credentials(events, cfg):
    by_subject = defaultdict(list)
    for e in events:
        if e.event_id == 4648 and e.subject_user:
            by_subject[e.subject_user].append(e)
    for subj, evs in by_subject.items():
        targets = {e.user for e in evs}
        if len(targets) >= 3:
            yield _finding("AUTH-006", "Explicit credentials used for many accounts", "high",
                           ["T1078", "T1550"],
                           f"'{subj}' used explicit credentials (runas/lateral movement) for "
                           f"{len(targets)} accounts.", evs, user=subj, host=evs[0].computer)


def account_changes(events, cfg):
    for e in events:
        if e.event_id == 4720:
            yield _finding("AUTH-007", "New local/domain account created", "medium", ["T1136"],
                           f"'{e.subject_user or 'unknown'}' created account '{e.user}'.", [e],
                           user=e.user, host=e.computer)
        elif e.event_id in (4728, 4732, 4756):
            yield _finding("AUTH-008", "Account added to a privileged group", "high", ["T1098"],
                           f"'{e.subject_user or 'unknown'}' added a member to privileged group "
                           f"'{e.raw.get('TargetUserName', e.user)}' (EID {e.event_id}).", [e],
                           user=e.subject_user, host=e.computer)


def log_cleared(events, cfg):
    for e in events:
        if e.event_id == 1102:
            yield _finding("AUTH-009", "Security log cleared", "critical", ["T1070.001"],
                           f"Security event log cleared by '{e.subject_user or 'unknown'}'.", [e],
                           user=e.subject_user, host=e.computer)


RULES = [brute_force, password_spray, success_after_failures, off_hours_remote_logon,
         account_lockout, explicit_credentials, account_changes, log_cleared]


def run_all(events: list[Event], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    findings = [f for rule in RULES for f in rule(events, cfg)]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda f: (order[f.severity], f.first_seen))


def entity_risk(findings: list[Finding]) -> list[dict]:
    """Aggregate a 0-100 risk score per user and per source IP."""
    scores: dict[tuple[str, str], dict] = {}
    for f in findings:
        for kind, values in (("user", f.user), ("ip", f.src_ip)):
            for v in filter(None, values.split(",")):
                s = scores.setdefault((kind, v), {"type": kind, "entity": v, "score": 0, "rules": set()})
                s["score"] += SEVERITY_POINTS[f.severity]
                s["rules"].add(f.rule_id)
    out = []
    for s in scores.values():
        s["score"] = min(100, s["score"])
        s["rules"] = sorted(s["rules"])
        out.append(s)
    return sorted(out, key=lambda s: -s["score"])
