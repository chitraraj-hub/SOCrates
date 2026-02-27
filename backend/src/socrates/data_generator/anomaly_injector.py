# backend/src/socrates/data_generator/anomaly_injector.py

from datetime import datetime, timedelta
from typing import List
import numpy as np
import pytz

from socrates.data_generator.company_profile import UserProfile
from socrates.data_generator.normal_traffic import LogEntry, _sample_dst_ip

C2_DOMAINS = [
    "malware-c2.ru",
    "botnet-cmd.cn",
    "evil-update.net",
    "payload-drop.xyz",
    "c2-handler.io",
]

# Each profile: (name, interval_seconds, jitter_seconds, num_days)
# Designed to test different tiers of detection difficulty
BEACON_PROFILES = [
    ("obvious",  300,  4,  5),    # every 5 min,  very low jitter  → all 3 methods
    ("subtle",   1800, 45, 5),    # every 30 min, moderate jitter  → maybe 1-2 methods
    ("fast",     60,   3,  3),    # every 1 min,  low jitter       → interval + iqr
]


def inject_beaconing(
    logs:      List[LogEntry],
    user:      UserProfile,
    rng:       np.random.Generator,
    start_day: datetime,
    profile:   tuple,
) -> List[LogEntry]:
    """
    Inject a beaconing pattern for one user based on a profile.
    profile = (name, interval_seconds, jitter_seconds, num_days)
    """
    name, interval_seconds, jitter_seconds, num_days = profile
    injected  = []
    c2_domain = str(rng.choice(C2_DOMAINS))

    current = start_day.replace(hour=0, minute=5, second=0, microsecond=0)
    end     = start_day + timedelta(days=num_days)

    while current < end:
        ts = current + timedelta(
            seconds=float(rng.normal(0, jitter_seconds))
        )
        injected.append(LogEntry(
            timestamp=        ts,
            username=         user.username,
            department=       user.department,
            src_ip=           user.src_ip,
            dst_ip=           _sample_dst_ip(rng),
            protocol=         "HTTP",
            http_method=      "GET",
            url=              f"{c2_domain}/check",
            status_code=      200,
            bytes_sent=       int(rng.normal(512, 30)),
            bytes_received=   int(rng.normal(128, 15)),
            action=           "Allowed",
            url_category=     "Unknown",
            threat_category=  "Malware",
            risk_score=       int(rng.integers(70, 90)),
            user_agent=       user.user_agents[0],
            is_anomaly=       True,
            anomaly_type=     f"beaconing_{name}",
            anomaly_severity= "high",
            tier_detection=   "tier1",
        ))
        current += timedelta(seconds=interval_seconds)

    print(
        f"[anomaly_injector] Beaconing ({name:<8}): "
        f"{len(injected):>5} entries → {user.username} → {c2_domain} "
        f"(every {interval_seconds}s, jitter {jitter_seconds}s)"
    )
    return logs + injected


def inject_anomalies(
    logs:   List[LogEntry],
    users:  List[UserProfile],
    config: dict,
    seed:   int = 42,
) -> List[LogEntry]:
    if not config["anomalies"]["enabled"]:
        return logs

    rng = np.random.default_rng(seed + 1)
    tz  = pytz.timezone(config["company"]["timezone"])

    num_days  = config["company"]["num_days"]
    start_day = datetime.now(tz).replace(
        hour=0, minute=0, second=0, microsecond=0
    ) - timedelta(days=num_days - 4)

    if config["anomalies"]["scenarios"].get("beaconing"):
        # Need at least 3 users for 3 profiles
        for i, profile in enumerate(BEACON_PROFILES):
            if i >= len(users):
                break
            logs = inject_beaconing(logs, users[i], rng, start_day, profile)

    logs.sort(key=lambda x: x.timestamp)

    anomaly_count = sum(1 for l in logs if l.is_anomaly)
    print(
        f"[anomaly_injector] {anomaly_count:,} anomalies / "
        f"{len(logs):,} total ({anomaly_count/len(logs)*100:.1f}%)"
    )
    return logs