"""
pcap_reader.py
Loads packet captures from disk using scapy.
"""

from scapy.all import rdpcap
from scapy.error import Scapy_Exception


def load_pcap(pcap_path):
    """
    Read a .pcap / .pcapng file and return a scapy PacketList.

    Returns an empty list (instead of raising) if the file can't be
    parsed, so callers can treat "no packets" uniformly.
    """
    try:
        return rdpcap(pcap_path)
    except (Scapy_Exception, OSError, ValueError) as exc:
        print(f" Failed to read pcap file: {exc}")
        return []
