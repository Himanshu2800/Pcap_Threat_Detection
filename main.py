"""
PCAP Analysis Tool
Reads a packet capture, groups it into flows, and flags flows whose
behavior looks like C2 beaconing, DDoS, C2 sessions, or possible
data exfiltration - then writes a JSON forensic report.
"""

import argparse
import os
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from core.pcap_reader import load_pcap
from core.packet_analyzer import parse_packets
from core.flow_manager import build_flows
from core.feature_engine import extract_flow_features
from core.threat_detector import analyze_behaviors, detect_cross_flow_patterns
from core.report_generator import save_report


def parse_args():
    parser = argparse.ArgumentParser(description="PCAP network forensics analyzer")
    parser.add_argument(
        "pcap_path",
        nargs="?",
        help="Path to a .pcap/.pcapng file. If omitted, you'll be prompted.",
    )
    parser.add_argument(
        "-o", "--output",
        default="reports/forensic_report.json",
        help="Where to write the JSON report (default: %(default)s)",
    )
    return parser.parse_args()


def main():
    print("PCAP ANALYSIS TOOL\n")

    args = parse_args()
    pcap_path = args.pcap_path or input("Enter PCAP file path: ").strip()

    if not os.path.exists(pcap_path):
        print(" PCAP file not found!")
        return

    packets = load_pcap(pcap_path)
    if not packets:
        print(" No packets found!")
        return

    print(f" Total packets: {len(packets)}")

    parsed_packets = parse_packets(packets)
    flows = build_flows(parsed_packets)
    featured_flows = extract_flow_features(flows)
    analyzed_flows = analyze_behaviors(featured_flows)
    analyzed_flows = detect_cross_flow_patterns(analyzed_flows)

    print(f"\n Total flows: {len(flows)}")

    suspicious = [
        (k, v) for k, v in analyzed_flows.items()
        if v["behavior"] != "NORMAL"
    ]

    print(f" Suspicious flows: {len(suspicious)}\n")

    if suspicious:
        for flow_key, data in suspicious:
            print("ALERT")
            print(f"Flow: {flow_key}")
            print(f"Behavior: {data['behavior']} (confidence: {data['confidence']})")
            print()
    else:
        print(" No suspicious activity detected")

    report_path = save_report(analyzed_flows, args.output)
    print(f" Report written to {report_path}")


if __name__ == "__main__":
    main()
