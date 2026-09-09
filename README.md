# PCAP Network Forensics Analyzer

A small pipeline that reads a packet capture, groups packets into flows,
computes per-flow traffic features, and flags flows whose behavior looks
anomalous - beaconing (C2), DDoS-style volume spikes, sustained C2
sessions, or possible data exfiltration. Findings are written out as a
JSON forensic report, with GeoIP context (country/city/lat/lon) on the
endpoints involved.

Built as a minor project for an MSc in Digital Forensics and Information
Security.

## How it works

```
main.py
  -> core/pcap_reader.py      load .pcap/.pcapng with scapy
  -> core/packet_analyzer.py  parse IP/TCP/UDP/ICMP fields per packet
  -> core/flow_manager.py     group packets into 5-tuple flows
  -> core/feature_engine.py   derive packets/sec, bytes/sec, avg size
  -> core/threat_detector.py  robust z-score anomaly scoring + classification
  -> core/geo_ip.py           GeoLite2 lookups for suspicious endpoints
  -> core/report_generator.py write reports/forensic_report.json
```

Detection is intentionally rule-based and explainable rather than a
black-box model - each threshold in `threat_detector.py` is commented
with the paper/technique it's loosely based on (Chandola et al., Paxson's
Bro, Mirkovic & Reiher's DDoS taxonomy, Ramachandran et al. on botnet
beaconing, Sommer & Paxson on avoiding overlapping classifications,
plus Farnham/SANS on DNS tunneling and the classic Snort portscan
preprocessor idea for scan detection).

It runs in two passes:

1. **Per-flow** (`analyze_behaviors`) - a single flow's own stats are
   enough to classify it: `C2_SESSION`, `DDOS`, `C2_BEACON`,
   `POSSIBLE_EXFIL`, `ICMP_FLOOD`, `DNS_TUNNELING`.
2. **Cross-flow** (`detect_cross_flow_patterns`) - patterns only
   visible across many flows from the same source: `PORT_SCAN`,
   `BRUTE_FORCE`. Runs second, on flows the first pass left `NORMAL`.

| Behavior | Idea |
|---|---|
| `C2_BEACON` | Regular, low-jitter check-ins to the same destination |
| `DDOS` | Sustained high packet/byte rate, small packets |
| `C2_SESSION` | Extreme volume spike not matching the DDoS shape |
| `POSSIBLE_EXFIL` | Large, sustained, mostly one-way transfer |
| `ICMP_FLOOD` | Burst of ICMP packets far above baseline (or a fixed absolute rate) |
| `DNS_TUNNELING` | Oversized and/or high-volume traffic on port 53 |
| `PORT_SCAN` | One source touching many distinct (dest, port) pairs with few packets each |
| `BRUTE_FORCE` | One source making many separate short connection attempts at the same dest:port |
| `NORMAL` | Everything else |

## Setup

```bash
pip install -r requirements.txt
```

### GeoIP database (optional but recommended)

GeoIP enrichment needs a local **GeoLite2-City.mmdb** file. It isn't
committed to this repo since MaxMind's license doesn't allow
redistributing the database itself. To get one:

1. Create a free account at https://www.maxmind.com/en/geolite2/signup
2. Download `GeoLite2-City.mmdb`
3. Place it in the project root (or point `GEOIP_DB_PATH` at it):

```bash
export GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb
```

If no database is found, the tool still runs fine - geo fields are just
reported as `"Unknown"`/`null`.

## Usage

```bash
python main.py sample_data/sample_capture.pcap
```

or run it without an argument and it'll prompt for a path:

```bash
python main.py
```

Optional output path:

```bash
python main.py sample_data/sample_capture.pcap -o reports/my_report.json
```

## Sample data

- `sample_data/sample_capture.pcap` - a small synthetic capture that
  exercises every rule: a beacon, a port scan, a brute-force attempt,
  an ICMP flood, and DNS tunneling. Good for a quick smoke test.
- `sample_data/sample_forensic_report.json` - an example report (from a
  larger, real capture) showing the full output shape, including
  GeoIP-enriched `C2_BEACON` and `POSSIBLE_EXFIL` events.

## Known limitations

- Thresholds are heuristic and tuned by eye, not learned from labeled
  traffic - expect false positives on unusual-but-legitimate traffic
  patterns (e.g. real-time video, health-check pings).
- The per-flow baseline (median/IQR) is computed across *all* flows in
  the capture, so a capture containing multiple simultaneous attacks
  can skew it - e.g. a port scan's very high per-flow packet rate can
  inflate the baseline enough to dilute a genuine ICMP flood's z-score.
  `ICMP_FLOOD` already has an absolute-rate fallback for this reason;
  the same caveat applies less defensively to the other z-score-based
  rules.
- `PORT_SCAN`/`BRUTE_FORCE` thresholds (15+ distinct targets / 5+
  attempts) are tuned for short captures - a long-running capture with
  naturally chatty hosts (e.g. a monitoring server) may need higher
  thresholds to avoid false positives.
- Flow keys are directional (`src, dst, sport, dport, proto`), so a
  single TCP connection with heavy asymmetric traffic shows up as two
  separate flow entries rather than one merged bidirectional flow.
- No IPv6 support yet - only `scapy.layers.inet` (IPv4) is parsed.
