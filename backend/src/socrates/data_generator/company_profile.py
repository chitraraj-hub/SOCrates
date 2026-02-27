# backend/src/socrates/data_generator/company_profile.py

from dataclasses import dataclass
from typing import List
import numpy as np
from faker import Faker

fake = Faker()

DEPARTMENTS = {
    "Engineering": {
        "domains": [
            "github.com", "stackoverflow.com", "aws.amazon.com",
            "slack.com", "jira.atlassian.com", "npmjs.com",
        ],
        "url_categories": ["Development", "Technology", "Cloud Services"],
        "work_hours": (8, 19),
        "avg_requests_per_day": 300,
        "avg_bytes_sent": 50_000,
        "avg_bytes_received": 800_000,
        "user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/122.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/122.0.0.0",
        ],
    },
    "Finance": {
        "domains": [
            "quickbooks.intuit.com", "chase.com",
            "slack.com", "office365.com", "expensify.com",
        ],
        "url_categories": ["Finance", "Banking", "Business"],
        "work_hours": (8, 17),
        "avg_requests_per_day": 200,
        "avg_bytes_sent": 30_000,
        "avg_bytes_received": 600_000,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
        ],
    },
}

US_LOCATIONS = ["New York, US", "San Francisco, US", "Chicago, US"]


@dataclass
class UserProfile:
    username:              str
    department:            str
    src_ip:                str
    location:              str
    work_hours_start:      int
    work_hours_end:        int
    work_hour_jitter:      int
    avg_requests_per_day:  int
    avg_bytes_sent:        int
    avg_bytes_received:    int
    common_domains:        List[str]
    url_categories:        List[str]
    user_agents:           List[str]
    is_anomaly_target:     bool = False
    anomaly_scenario:      str  = ""


def build_company(config: dict, seed: int = 42) -> List[UserProfile]:
    rng = np.random.default_rng(seed)
    fake.seed_instance(seed)

    num_users    = config["company"]["num_users"]
    dept_names   = list(DEPARTMENTS.keys())
    users        = []

    for i in range(num_users):
        dept_name = dept_names[i % len(dept_names)]
        dept      = DEPARTMENTS[dept_name]

        users.append(UserProfile(
            username=             fake.user_name() + "@company.com",
            department=           dept_name,
            src_ip=               fake.ipv4_private(),
            location=             str(rng.choice(US_LOCATIONS)),
            work_hours_start=     dept["work_hours"][0],
            work_hours_end=       dept["work_hours"][1],
            work_hour_jitter=     30,
            avg_requests_per_day= max(50, int(rng.normal(dept["avg_requests_per_day"], 30))),
            avg_bytes_sent=       max(1000, int(rng.normal(dept["avg_bytes_sent"], 5000))),
            avg_bytes_received=   max(10_000, int(rng.normal(dept["avg_bytes_received"], 50_000))),
            common_domains=       dept["domains"],
            url_categories=       dept["url_categories"],
            user_agents=          dept["user_agents"],
        ))

    return users