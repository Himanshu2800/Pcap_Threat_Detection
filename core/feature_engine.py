"""
feature_engine.py
Derives rate/size features per flow (packets/sec, bytes/sec,
avg packet size) that threat_detector.py uses as anomaly signals.
"""


def extract_flow_features(flows):
    """Compute derived features for every flow produced by flow_manager."""
    featured_flows = {}
    for flow_key, data in flows.items():
        start = data["start_time"]
        end = data["end_time"]
        packets = data["packet_count"]
        bytes_total = data["total_bytes"]
        duration = end - start

        if duration <= 0:
            packets_per_sec = 0
            bytes_per_sec = 0
        else:
            packets_per_sec = packets / duration
            bytes_per_sec = bytes_total / duration

        avg_packet_size = bytes_total / packets if packets > 0 else 0

        featured_flows[flow_key] = {
            "start_time": start,
            "end_time": end,
            "duration": duration,
            "packet_count": packets,
            "total_bytes": bytes_total,
            "avg_packet_size": avg_packet_size,
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "timestamps": data.get("timestamps", []),
            "packet_sizes": data.get("packet_sizes", []),
        }
    return featured_flows
