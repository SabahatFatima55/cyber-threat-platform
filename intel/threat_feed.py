"""
Threat Intelligence Feed Aggregation (Bonus Challenge)
------------------------------------------------------------
Simulates ingesting and aggregating multiple external threat-intel
feeds (AbuseIPDB, ThreatFox, a custom internal blocklist) into one
unified "known-bad" indicator list, then cross-references every flow
against it. In production this would be a scheduled job pulling live
feeds over HTTPS/STIX-TAXII and caching results in Redis; here it is a
static, clearly-labeled sample list so the platform runs fully offline
with zero external calls (this environment can't reach outside feed
providers).

Swap point for production: replace SAMPLE_FEED's static entries with
scheduled HTTP pulls from real feed APIs (AbuseIPDB, ThreatFox,
OTX/AlienVault), each tagged with its source and a fetched_at
timestamp, merged the same way.
"""

import pandas as pd

# Simulated aggregation of multiple external feeds. Structure mirrors what
# a real feed aggregator would produce after merging several sources.
SAMPLE_FEED = [
    {"indicator": "185.220.189.91", "type": "ip", "source": "AbuseIPDB", "category": "C2 Server"},
    {"indicator": "185.220.142.117", "type": "ip", "source": "ThreatFox", "category": "Malware C2"},
    {"indicator": "185.220.35.12", "type": "ip", "source": "Internal Blocklist", "category": "Known Bad Actor"},
    {"indicator": "185.220.125.42", "type": "ip", "source": "AbuseIPDB", "category": "Brute Force Source"},
    {"indicator": "185.220.172.27", "type": "ip", "source": "ThreatFox", "category": "Botnet Node"},
    {"indicator": "185.220.136.180", "type": "ip", "source": "OTX AlienVault", "category": "Known Bad Actor"},
    {"indicator": 4444, "type": "port", "source": "Internal Blocklist", "category": "Common C2 Port"},
    {"indicator": 6667, "type": "port", "source": "ThreatFox", "category": "IRC Botnet Port"},
]


def get_feed() -> pd.DataFrame:
    return pd.DataFrame(SAMPLE_FEED)


def enrich_with_feed(df: pd.DataFrame) -> pd.DataFrame:
    """Adds feed_match (bool) and feed_source columns to every flow."""
    feed = get_feed()
    ip_feed = {row["indicator"]: row for _, row in feed[feed["type"] == "ip"].iterrows()}
    port_feed = {row["indicator"]: row for _, row in feed[feed["type"] == "port"].iterrows()}

    def check(row):
        for ip_field in ("src_ip", "dst_ip"):
            if row.get(ip_field) in ip_feed:
                hit = ip_feed[row[ip_field]]
                return True, f"{hit['source']} ({hit['category']})"
        if row.get("dst_port") in port_feed:
            hit = port_feed[row["dst_port"]]
            return True, f"{hit['source']} ({hit['category']})"
        return False, ""

    results = df.apply(check, axis=1)
    df = df.copy()
    df["feed_match"] = [r[0] for r in results]
    df["feed_source"] = [r[1] for r in results]
    return df
