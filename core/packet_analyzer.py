"""
packet_analyzer.py
Extracts the fields we care about (src/dst, ports, protocol, size,
timestamp) from each raw packet, dropping anything that isn't IP.
"""

import scapy.layers.inet


def parse_packets(packets):
    """Turn a scapy PacketList into a list of plain dicts."""
    parsed_packets = []

    for pkt in packets:
        if scapy.layers.inet.IP not in pkt:
            continue

        packet_info = {
            "time": float(pkt.time),
            "src": pkt[scapy.layers.inet.IP].src,
            "dst": pkt[scapy.layers.inet.IP].dst,
            "length": len(pkt),
        }

        if scapy.layers.inet.TCP in pkt:
            packet_info["protocol"] = "TCP"
            packet_info["sport"] = pkt[scapy.layers.inet.TCP].sport
            packet_info["dport"] = pkt[scapy.layers.inet.TCP].dport

        elif scapy.layers.inet.UDP in pkt:
            packet_info["protocol"] = "UDP"
            packet_info["sport"] = pkt[scapy.layers.inet.UDP].sport
            packet_info["dport"] = pkt[scapy.layers.inet.UDP].dport

        elif scapy.layers.inet.ICMP in pkt:
            packet_info["protocol"] = "ICMP"
            packet_info["sport"] = None
            packet_info["dport"] = None

        else:
            packet_info["protocol"] = "OTHER"
            packet_info["sport"] = None
            packet_info["dport"] = None

        parsed_packets.append(packet_info)

    return parsed_packets
