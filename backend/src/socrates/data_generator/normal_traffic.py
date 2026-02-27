# backend/src/socrates/data_generator/normal_traffic.py

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List
import numpy as np
import pytz

from socrates.data_generator.company_profile import UserProfile

# ---------------------------------------------------------------------------
# LogEntry — the atomic unit of data flowing through SOCrates
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    # Identity
    timestamp:        datetime
    username:         str
    department:       str
    src_ip:           str
    dst_ip:           str

    # Request
    protocol:         str
    http_method:      str
    url:              str

    # Response
    status_code:      int
    bytes_sent:       int
    bytes_received:   int

    # Classification
    action:           str       # "Allowed" / "Blocked"
    url_category:     str
    threat_category:  str
    risk_score:       int       # 0-100
    user_agent:       str

    # Anomaly metadata — empty for normal traffic, set by anomaly_injector
    is_anomaly:       bool = False
    anomaly_type:     str  = ""
    anomaly_severity: str  = ""
    tier_detection:   str  = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
HTTP_METHOD_WEIGHTS = [0.70, 0.20, 0.07, 0.03]

PROTOCOLS = ["HTTPS", "HTTP"]
PROTOCOL_WEIGHTS = [0.85, 0.15]

NORMAL_STATUS_CODES = [200, 200, 200, 200, 301, 302, 304, 404, 403]
NORMAL_STATUS_WEIGHTS = [0.65, 0.10, 0.05, 0.05, 0.05, 0.04, 0.03, 0.02, 0.01]

NORMAL_THREAT_CATEGORY = "None"
NORMAL_RISK_SCORE_RANGE = (0, 20)  # low risk for normal traffic


def _sample_timestamp(
    rng: np.random.Generator,
    date: datetime,
    work_start: int,
    work_end: int,
    jitter_minutes: int,
) -> datetime:
    """
    Sample a realistic timestamp within a user's work hours with jitter.
    80% of traffic during work hours, 20% slightly outside.
    """
    if rng.random() < 0.80:
        # Core work hours with gaussian jitter on start/end
        start_jitter = int(rng.normal(0, jitter_minutes))
        end_jitter = int(rng.normal(0, jitter_minutes))
        start_minute = work_start * 60 + start_jitter
        end_minute = work_end * 60 + end_jitter
    else:
        # Occasional off-hours — early morning or evening
        if rng.random() < 0.5:
            start_minute = (work_start - 2) * 60
            end_minute = work_start * 60
        else:
            start_minute = work_end * 60
            end_minute = (work_end + 2) * 60

    start_minute = max(0, start_minute)
    end_minute = min(23 * 60 + 59, end_minute)

    if end_minute <= start_minute:
        end_minute = start_minute + 60

    minute_of_day = int(rng.integers(start_minute, end_minute))
    hour = minute_of_day // 60
    minute = minute_of_day % 60
    second = int(rng.integers(0, 60))

    return date.replace(hour=hour, minute=minute, second=second)


def _sample_domain_and_url(
    rng: np.random.Generator,
    user: UserProfile,
) -> tuple[str, str]:
    """
    Sample a domain from user's common domains with a long tail
    for occasional new/random domains (realistic browsing behavior).
    """
    # 90% from known domains, 10% from random plausible domains
    if rng.random() < 0.90:
        domain = str(rng.choice(user.common_domains))
    else:
        # Occasional benign unknown domain
        tlds = [".com", ".io", ".net", ".org", ".co"]
        domain = fake_domain(rng) + str(rng.choice(tlds))

    paths = ["/", "/home", "/dashboard", "/api/data", "/search",
             "/login", "/profile", "/settings", "/docs", "/index.html"]
    path = str(rng.choice(paths))
    url = f"{domain}{path}"

    return domain, url


def fake_domain(rng: np.random.Generator) -> str:
    """Generate a plausible-looking random domain name."""
    prefixes = ["app", "my", "get", "use", "try", "go", "web", "cloud"]
    words = ["task", "flow", "sync", "hub", "base", "link", "core", "data"]
    return str(rng.choice(prefixes)) + str(rng.choice(words))


def _sample_dst_ip(rng: np.random.Generator) -> str:
    """Generate a realistic public destination IP."""
    return f"{rng.integers(1,223)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"


# ---------------------------------------------------------------------------
# Main generation function
# ---------------------------------------------------------------------------

def generate_traffic(
    users: List[UserProfile],
    config: dict,
    seed: int = 42,
) -> List[LogEntry]:
    """
    Generate normal baseline traffic for all users across num_days.
    Returns a flat list of LogEntry objects sorted by timestamp.
    """
    rng = np.random.default_rng(seed)

    num_days = config["company"]["num_days"]
    tz = pytz.timezone(config["company"]["timezone"])

    # Start date: num_days ago from today
    start_date = datetime.now(tz).replace(
        hour=0, minute=0, second=0, microsecond=0
    ) - timedelta(days=num_days)

    all_logs: List[LogEntry] = []

    for user in users:
        for day_offset in range(num_days):
            current_date = start_date + timedelta(days=day_offset)

            # Skip weekends — 20% chance of light weekend activity
            if current_date.weekday() >= 5:
                if rng.random() > 0.20:
                    continue

            # Sample number of requests for this user on this day
            num_requests = max(
                10,
                int(rng.normal(
                    user.avg_requests_per_day,
                    user.avg_requests_per_day * 0.20
                ))
            )

            for _ in range(num_requests):
                timestamp = _sample_timestamp(
                    rng,
                    current_date,
                    user.work_hours_start,
                    user.work_hours_end,
                    user.work_hour_jitter,
                )

                domain, url = _sample_domain_and_url(rng, user)

                protocol = str(rng.choice(PROTOCOLS, p=PROTOCOL_WEIGHTS))
                http_method = str(rng.choice(HTTP_METHODS, p=HTTP_METHOD_WEIGHTS))
                status_code = int(rng.choice(NORMAL_STATUS_CODES, p=NORMAL_STATUS_WEIGHTS))

                bytes_sent = max(100, int(rng.normal(
                    user.avg_bytes_sent / user.avg_requests_per_day,
                    user.avg_bytes_sent / user.avg_requests_per_day * 0.30
                )))
                bytes_received = max(500, int(rng.normal(
                    user.avg_bytes_received / user.avg_requests_per_day,
                    user.avg_bytes_received / user.avg_requests_per_day * 0.30
                )))

                url_category = str(rng.choice(user.url_categories))
                user_agent = str(rng.choice(user.user_agents))

                log = LogEntry(
                    timestamp=timestamp,
                    username=user.username,
                    department=user.department,
                    src_ip=user.src_ip,
                    dst_ip=_sample_dst_ip(rng),
                    protocol=protocol,
                    http_method=http_method,
                    url=url,
                    status_code=status_code,
                    bytes_sent=bytes_sent,
                    bytes_received=bytes_received,
                    action="Allowed",
                    url_category=url_category,
                    threat_category=NORMAL_THREAT_CATEGORY,
                    risk_score=int(rng.integers(
                        NORMAL_RISK_SCORE_RANGE[0],
                        NORMAL_RISK_SCORE_RANGE[1]
                    )),
                    user_agent=user_agent,
                )
                all_logs.append(log)

    # Sort chronologically
    all_logs.sort(key=lambda x: x.timestamp)
    print(f"[normal_traffic] Generated {len(all_logs):,} baseline log entries")
    return all_logs