"""
threat_detector.py
Flags anomalous flows using robust (median/IQR) z-scores against the
capture's own baseline, then classifies each anomaly.

Two passes:
  1. analyze_behaviors()      - per-flow scoring (a single flow's own
                                 stats are enough): C2_SESSION, DDOS,
                                 C2_BEACON, POSSIBLE_EXFIL, ICMP_FLOOD,
                                 DNS_TUNNELING.
  2. detect_cross_flow_patterns() - patterns only visible across many
                                 flows from the same source: PORT_SCAN,
                                 BRUTE_FORCE. Run this second, on the
                                 output of analyze_behaviors().

Thresholds are heuristic, not learned - each is annotated with the
paper/technique it's loosely based on, since the point of this project
is transparent, explainable detection rather than a black-box model.
"""

from collections import defaultdict

import numpy as np


def compute_baselines(featured_flows):
    """Compute per-capture median/IQR baselines for each feature."""
    all_pps, all_bps, all_sz, all_dur = [], [], [], []

    for f in featured_flows.values():
        all_pps.append(f.get("packets_per_sec", 0))
        all_bps.append(f.get("bytes_per_sec", 0))
        all_sz.append(f.get("avg_packet_size", 0))
        all_dur.append(f.get("duration", 0))

    def robust(arr):
        a = np.array(arr, dtype=float)
        med = float(np.median(a))
        iqr = float(np.percentile(a, 75) - np.percentile(a, 25))
        return med, max(iqr, 1e-9)

    pps_med, pps_iqr = robust(all_pps)
    bps_med, bps_iqr = robust(all_bps)
    sz_med, sz_iqr = robust(all_sz)
    dur_med, dur_iqr = robust(all_dur)

    return {
        "pps_med": pps_med, "pps_iqr": pps_iqr,
        "bps_med": bps_med, "bps_iqr": bps_iqr,
        "sz_med": sz_med, "sz_iqr": sz_iqr,
        "dur_med": dur_med, "dur_iqr": dur_iqr,
    }


def rz(value, median, iqr):
    """Robust z-score: (value - median) / IQR."""
    return (value - median) / iqr


def analyze_behaviors(featured_flows):
    """Score and classify every flow, returning the same dict enriched
    with behavior/confidence/score fields. Single-flow patterns only -
    see detect_cross_flow_patterns() for scan/brute-force detection."""
    if not featured_flows:
        return {}

    B = compute_baselines(featured_flows)
    analyzed_flows = {}

    for flow_key, f in featured_flows.items():
        _src, _dst, sport, dport, protocol = flow_key

        pps = f.get("packets_per_sec", 0)
        bps = f.get("bytes_per_sec", 0)
        avg_sz = f.get("avg_packet_size", 0)
        dur = f.get("duration", 0)
        total_bytes = f.get("total_bytes", 0)
        packet_count = f.get("packet_count", 0)
        timestamps = f.get("timestamps", [])
        packet_sizes = f.get("packet_sizes", [])

        intervals = np.diff(timestamps) if len(timestamps) > 1 else np.array([0])
        jitter = float(np.std(intervals))
        sz_var = float(np.std(packet_sizes)) if len(packet_sizes) > 1 else 0

        z_pps = rz(pps, B["pps_med"], B["pps_iqr"])
        z_bps = rz(bps, B["bps_med"], B["bps_iqr"])
        z_sz = rz(avg_sz, B["sz_med"], B["sz_iqr"])
        z_dur = rz(dur, B["dur_med"], B["dur_iqr"])

        behavior = "NORMAL"
        confidence = 0.0
        scan_score = ddos_score = beacon_score = exfil_score = 0
        cv_passed = False

        if z_pps > 2:  # Chandola et al. - "Anomaly Detection: A Survey"
            scan_score += 2
        if z_sz < -1.5:  # Paxson - "Bro: A System for Detecting Network Intruders"
            scan_score += 2
        if z_dur < -1 and dur < B["dur_med"]:  # Paxson - "Bro"
            scan_score += 1

        if z_pps > 3:  # Mirkovic & Reiher - "A Taxonomy of DDoS Attacks"
            ddos_score += 2
        if z_bps > 3:  # Mirkovic & Reiher
            ddos_score += 2
        if z_sz < -1:  # Lakhina et al. - "Characterization of Network-Wide Anomalies"
            ddos_score += 1

        if len(intervals) > 3:
            mi = np.mean(intervals)
            si = np.std(intervals)
            if mi > 0:
                cv = si / mi
                if cv < 0.3:  # Ramachandran et al. - "Revealing Botnet Membership"
                    beacon_score += 3
                    cv_passed = True

        if cv_passed:
            if -1 < z_pps < 1 and pps > 0.001:
                beacon_score += 1
            if z_sz < 0:
                beacon_score += 1
            if z_dur > 0:
                beacon_score += 1
            if jitter < B["pps_iqr"] * 0.5:
                beacon_score += 1
            if sz_var < B.get("sz_iqr", 1e-9) * 0.5:
                beacon_score += 1

        # POSSIBLE_EXFIL: sustained, large, mostly-one-way transfer that
        # isn't fast/bursty enough to be a DDoS flood and isn't regular
        # enough to be a beacon - Lakhina et al. also flag this "heavy
        # hitter with long duration" shape as a distinct anomaly class.
        if z_bps > 2 and z_dur > 1 and total_bytes > 5_000_000 and not cv_passed:
            exfil_score += 3
        if z_pps < 1:  # slow trickle rather than a flood
            if z_bps > 2 and total_bytes > 5_000_000:
                exfil_score += 1

        # ICMP_FLOOD: classic ping-flood shape - a burst of ICMP packets
        # far above baseline rate. Kept protocol-specific instead of
        # falling through to the generic DDOS bucket, since "who's
        # ICMP-flooding whom" is more actionable in a report than a
        # generic label. cf. Kumar, "Smurf-based DDoS Attack Detection".
        #
        # Uses z_pps OR a fixed absolute rate (pps > 20): if the capture
        # also contains other bursty attack traffic (e.g. a port scan),
        # that traffic inflates the IQR used for z_pps and can mask a
        # flood that's still unambiguous in absolute terms.
        icmp_flood = protocol == "ICMP" and packet_count >= 10 and (z_pps > 3 or pps > 20)

        # DNS_TUNNELING: legitimate DNS queries/responses are small
        # (typically well under 200 bytes); C2/exfil-over-DNS encodes
        # data in query names or TXT records, inflating average packet
        # size and/or query volume on port 53. Heuristic per Farnham,
        # SANS "Detecting DNS Tunneling", and Born & Gustafson, "NgViz".
        is_dns = protocol == "UDP" and (sport == 53 or dport == 53)
        dns_tunneling = is_dns and packet_count >= 5 and (avg_sz > 200 or z_bps > 1.5)

        volume_anomaly = z_pps > 5 or z_bps > 5

        # Sommer & Paxson - "Outside the Closed World": priority ordering
        # to prevent overlap between threat categories. Protocol-specific
        # checks (ICMP/DNS) go first since they're more precise than the
        # generic volume-based buckets they'd otherwise fall into.
        if icmp_flood:
            behavior = "ICMP_FLOOD"
            # z_pps/6 and pps/100 are two different confidence scales
            # (relative vs. absolute) - take whichever fired the rule.
            confidence = round(min(max(z_pps / 6, pps / 100), 1.0), 2)

        elif dns_tunneling:
            behavior = "DNS_TUNNELING"
            confidence = round(min(max(avg_sz / 400, z_bps / 3), 1.0), 2)

        elif volume_anomaly and ddos_score < 3:
            behavior = "C2_SESSION"
            confidence = round(min((z_pps + z_bps) / 20, 1.0), 2)

        elif ddos_score >= 3:  # Mirkovic & Reiher
            behavior = "DDOS"
            confidence = round(min(ddos_score / 5, 1.0), 2)

        elif beacon_score >= 5 and cv_passed:  # Zeidanloo et al. - "Botnet Detection"
            behavior = "C2_BEACON"
            confidence = round(min(beacon_score / 7, 1.0), 2)

        elif exfil_score >= 3:
            behavior = "POSSIBLE_EXFIL"
            confidence = round(min(exfil_score / 4, 1.0), 2)

        analyzed_flows[flow_key] = {
            **f,
            "behavior": behavior,
            "confidence": confidence,
            "scan_score": scan_score,
            "ddos_score": ddos_score,
            "beacon_score": beacon_score,
            "exfil_score": exfil_score,
            "volume_anomaly": volume_anomaly,
            "jitter": round(jitter, 4),
            "size_variance": round(sz_var, 4),
            "z_pps": round(z_pps, 4),
            "z_bps": round(z_bps, 4),
        }

    return analyzed_flows


# --- Cross-flow patterns ----------------------------------------------
# Port scans and brute-force attempts don't show up in a single flow's
# stats - each individual probe/attempt looks like an unremarkable short
# connection. What gives them away is the *pattern across many flows*
# from the same source, so this runs as a second pass over flows that
# analyze_behaviors() left as NORMAL.

PORT_SCAN_MIN_TARGETS = 15   # distinct (dst, dport) pairs from one source
PORT_SCAN_MAX_PACKETS = 4    # a scan probe is short: SYN, maybe SYN-ACK/RST
BRUTE_FORCE_MIN_ATTEMPTS = 5  # repeated separate connections to same dst:port
BRUTE_FORCE_MAX_PACKETS = 10  # each attempt is a short handshake/auth try


def detect_cross_flow_patterns(analyzed_flows):
    """
    Second pass: relabels still-NORMAL flows that are part of a
    port scan or brute-force pattern from their source IP.

    Port scan heuristic follows the classic Snort/Bro portscan
    preprocessor idea: many distinct destination ports/hosts touched
    by one source, each with very few packets exchanged.

    Brute force heuristic: many separate connection attempts (each a
    distinct flow, since source port differs per attempt) at the SAME
    destination IP:port, each short - the shape of automated
    credential-stuffing tools like Hydra/Medusa.
    """
    by_src = defaultdict(list)
    for flow_key, data in analyzed_flows.items():
        if data["behavior"] != "NORMAL":
            continue  # don't override an existing classification
        by_src[flow_key[0]].append((flow_key, data))

    for _src, flows in by_src.items():
        # --- Port scan: many distinct (dst, dport) pairs, low packets ---
        tcp_flows = [
            (flow_key, data) for flow_key, data in flows
            if flow_key[4] == "TCP"
        ]
        targets = {(flow_key[1], flow_key[3]) for flow_key, _ in tcp_flows}
        is_scanning = len(targets) >= PORT_SCAN_MIN_TARGETS

        scanned_flow_keys = set()
        if is_scanning:
            scan_confidence = round(min(len(targets) / (PORT_SCAN_MIN_TARGETS * 2), 1.0), 2)
            for flow_key, data in tcp_flows:
                if data["packet_count"] <= PORT_SCAN_MAX_PACKETS:
                    data["behavior"] = "PORT_SCAN"
                    data["confidence"] = scan_confidence
                    scanned_flow_keys.add(flow_key)

        # --- Brute force: repeated attempts at the SAME dst:port ---
        attempts_by_dst_port = defaultdict(list)
        for flow_key, data in tcp_flows:
            if flow_key in scanned_flow_keys:
                continue  # already classified as part of a scan above
            attempts_by_dst_port[(flow_key[1], flow_key[3])].append((flow_key, data))

        for (_dst, _dport), attempt_flows in attempts_by_dst_port.items():
            if len(attempt_flows) < BRUTE_FORCE_MIN_ATTEMPTS:
                continue
            avg_packets = sum(d["packet_count"] for _, d in attempt_flows) / len(attempt_flows)
            if avg_packets > BRUTE_FORCE_MAX_PACKETS:
                continue  # too much data per attempt to be a login flood
            bf_confidence = round(min(len(attempt_flows) / (BRUTE_FORCE_MIN_ATTEMPTS * 2), 1.0), 2)
            for flow_key, data in attempt_flows:
                data["behavior"] = "BRUTE_FORCE"
                data["confidence"] = bf_confidence

    return analyzed_flows
