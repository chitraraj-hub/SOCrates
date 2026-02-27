# backend/src/socrates/services/parser.py

import csv
from datetime import datetime
from typing import List
from socrates.data_generator.normal_traffic import LogEntry
import time

REQUIRED_COLUMNS = [
    "timestamp", "username", "department", "src_ip", "dst_ip",
    "protocol", "http_method", "url", "status_code",
    "bytes_sent", "bytes_received", "action", "url_category",
    "threat_category", "risk_score", "user_agent",
]

def parse_log_file(filepath: str) -> List[LogEntry]:
    """Parse CSV log file into a list of LogEntry objects."""
    start = time.monotonic()
    entries = []

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        missing = [c for c in REQUIRED_COLUMNS if c not in reader.fieldnames]
        if missing:
            raise ValueError(f"Missing required columns: {missing}")

        for row in reader:
            try:
                entries.append(LogEntry(
                    timestamp=       datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S"),
                    username=        row["username"],
                    department=      row["department"],
                    src_ip=          row["src_ip"],
                    dst_ip=          row["dst_ip"],
                    protocol=        row["protocol"],
                    http_method=     row["http_method"],
                    url=             row["url"],
                    status_code=     int(row["status_code"]),
                    bytes_sent=      int(row["bytes_sent"]),
                    bytes_received=  int(row["bytes_received"]),
                    action=          row["action"],
                    url_category=    row["url_category"],
                    threat_category= row["threat_category"],
                    risk_score=      int(row["risk_score"]),
                    user_agent=      row["user_agent"],
                ))
            except Exception:
                continue

    print(f"[parser] {len(entries):,} / {len(entries):,} rows parsed in {(time.monotonic()-start)*1000:.0f}ms")
    return entries