"""
Security Data Pipeline
-----------------------
Generates a synthetic dataset of network security flow logs, structured
similarly to the CICIDS2017 dataset (flow-based features + attack label).
This simulates: Firewall Logs, Auth Logs, Network Traffic, Endpoint Security.

In a production system this module would ingest from real sources
(Kafka, syslog, SIEM exports). Here we generate realistic synthetic
flows so the rest of the platform (detection, graph, copilot) has
something real to work with end-to-end.
"""

import csv
import random
import os
from datetime import datetime, timedelta

random.seed(42)

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "security_logs.csv")

# Simulated internal network / users
INTERNAL_IPS = [f"10.0.{random.randint(0,5)}.{i}" for i in range(1, 40)]
USERS = [f"user{i}" for i in range(1, 25)] + ["admin", "svc_backup", "svc_db"]
EXTERNAL_IPS = [f"185.220.{random.randint(0,255)}.{random.randint(1,255)}" for _ in range(30)]
COMMON_PORTS = [80, 443, 53, 22, 3389, 445, 21, 25, 3306, 5432]

ATTACK_TYPES = [
    "Normal Traffic",
    "Port Scanning",
    "Brute Force",
    "DDoS",
    "Data Exfiltration",
    "Malware C2",
]

# Weighted so normal traffic dominates but attacks are well represented
# (avoids the class-imbalance trap of the raw CICIDS file)
ATTACK_WEIGHTS = [55, 12, 12, 8, 7, 6]


def random_flow(base_time, flow_id):
    label = random.choices(ATTACK_TYPES, weights=ATTACK_WEIGHTS, k=1)[0]
    src_ip = random.choice(INTERNAL_IPS)
    user = random.choice(USERS)
    timestamp = base_time + timedelta(seconds=random.randint(0, 86400))

    if label == "Normal Traffic":
        dst_ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
        dst_port = random.choice(COMMON_PORTS)
        duration = random.randint(50, 500000)
        fwd_packets = random.randint(1, 40)
        bwd_packets = random.randint(0, 40)
        flow_bytes_s = round(random.uniform(50, 8000), 2)
        failed_logins = 0

    elif label == "Port Scanning":
        dst_ip = random.choice(INTERNAL_IPS)
        dst_port = random.randint(1, 65000)
        duration = random.randint(1, 200)  # very short flows
        fwd_packets = random.randint(1, 3)
        bwd_packets = 0
        flow_bytes_s = round(random.uniform(0.1, 50), 2)
        failed_logins = 0

    elif label == "Brute Force":
        dst_ip = random.choice(INTERNAL_IPS)
        dst_port = random.choice([22, 3389, 445, 21])
        duration = random.randint(100, 3000)
        fwd_packets = random.randint(5, 20)
        bwd_packets = random.randint(5, 20)
        flow_bytes_s = round(random.uniform(100, 2000), 2)
        failed_logins = random.randint(4, 25)

    elif label == "DDoS":
        dst_ip = random.choice(INTERNAL_IPS)
        dst_port = random.choice([80, 443])
        duration = random.randint(1, 50)
        fwd_packets = random.randint(50, 500)
        bwd_packets = random.randint(0, 5)
        flow_bytes_s = round(random.uniform(50000, 2000000), 2)
        failed_logins = 0
        src_ip = random.choice(EXTERNAL_IPS)  # DDoS usually external-origin

    elif label == "Data Exfiltration":
        dst_ip = random.choice(EXTERNAL_IPS)
        dst_port = random.choice([443, 22, 8080])
        duration = random.randint(5000, 900000)
        fwd_packets = random.randint(500, 5000)
        bwd_packets = random.randint(1, 20)
        flow_bytes_s = round(random.uniform(10000, 500000), 2)
        failed_logins = 0

    else:  # Malware C2
        dst_ip = random.choice(EXTERNAL_IPS)
        dst_port = random.choice([443, 8080, 4444, 6667])
        duration = random.randint(1000, 600000)
        fwd_packets = random.randint(10, 100)
        bwd_packets = random.randint(10, 100)
        flow_bytes_s = round(random.uniform(200, 5000), 2)
        failed_logins = 0

    return {
        "flow_id": flow_id,
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "user": user,
        "dst_port": dst_port,
        "flow_duration": duration,
        "fwd_packets": fwd_packets,
        "bwd_packets": bwd_packets,
        "flow_bytes_s": flow_bytes_s,
        "failed_logins": failed_logins,
        "attack_type": label,
    }


def generate(n_rows=8000, out_path=OUTPUT_PATH):
    base_time = datetime(2026, 8, 10, 0, 0, 0)
    fieldnames = [
        "flow_id", "timestamp", "src_ip", "dst_ip", "user", "dst_port",
        "flow_duration", "fwd_packets", "bwd_packets", "flow_bytes_s",
        "failed_logins", "attack_type",
    ]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i in range(n_rows):
            writer.writerow(random_flow(base_time, i))
    print(f"Generated {n_rows} flow logs -> {out_path}")


if __name__ == "__main__":
    generate()
