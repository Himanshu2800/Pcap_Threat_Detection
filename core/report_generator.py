"""
report_generator.py
Builds the JSON forensic report (summary + timeline) from analyzed
flows, enriching each suspicious flow's endpoints with GeoIP data.
Matches the shape of reports/sample_forensic_report.json.
"""

import json
import os
from collections import Counter

from core.geo_ip import lookup_ip


def _flow_events(analyzed_flows):
    """One timeline event per non-NORMAL flow, ordered by start time."""
    events = []
    for flow_key, data in analyzed_flows.items():
        if data["behavior"] == "NORMAL":
            continue

        src, dst, _sport, _dport, protocol = flow_key
        src_geo = lookup_ip(src)
        dst_geo = lookup_ip(dst)

        events.append({
            "time": data["start_time"],
            "source": src,
            "destination": dst,
            "protocol": protocol,
            "behavior": data["behavior"],
            "score": data["confidence"],
            "src_country": src_geo["country"],
            "src_city": src_geo["city"],
            "dst_country": dst_geo["country"],
            "dst_city": dst_geo["city"],
            "src_lat": src_geo["lat"],
            "src_lon": src_geo["lon"],
            "dst_lat": dst_geo["lat"],
            "dst_lon": dst_geo["lon"],
        })

    events.sort(key=lambda e: e["time"])
    return events


def build_report(analyzed_flows):
    """Return the report as a Python dict (summary + timeline)."""
    timeline = _flow_events(analyzed_flows)
    behavior_counts = Counter(e["behavior"] for e in timeline)

    return {
        "summary": {
            "total_events": len(timeline),
            "unique_behaviors": sorted(behavior_counts.keys()),
            "behavior_counts": dict(behavior_counts),
        },
        "timeline": timeline,
    }


def save_report(analyzed_flows, output_path="reports/forensic_report.json"):
    """Build the report and write it to disk as pretty-printed JSON."""
    report = build_report(analyzed_flows)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=4)
    return output_path
