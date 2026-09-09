"""
flow_manager.py
Groups individual packets into bidirectional-key flows
(src, dst, sport, dport, protocol) and tracks per-flow stats.
"""


def build_flows(parsed_packets):
    """Aggregate parsed packets into a dict keyed by 5-tuple flow key."""
    flows = {}
    for pkt in parsed_packets:
        flow_key = (
            pkt["src"],
            pkt["dst"],
            pkt["sport"],
            pkt["dport"],
            pkt["protocol"],
        )
        if flow_key not in flows:
            flows[flow_key] = {
                "start_time": pkt["time"],
                "end_time": pkt["time"],
                "packet_count": 0,
                "total_bytes": 0,
                "timestamps": [],
                "packet_sizes": [],
            }
        flow = flows[flow_key]
        flow["packet_count"] += 1
        flow["total_bytes"] += pkt["length"]
        flow["end_time"] = pkt["time"]
        flow["timestamps"].append(pkt["time"])
        flow["packet_sizes"].append(pkt["length"])

    return flows
