"""
Network forensics - PCAP analysis, connection timeline, DNS analysis, threat hunting.

Uses:
  - scapy  (pip install scapy)     - packet parsing
  - dpkt   (pip install dpkt)      - fast PCAP reading fallback
  - pyshark (pip install pyshark)  - Wireshark/tshark wrapper (optional)
"""

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from src.utils.ioc_extractor import IOCExtractor, IOCBundle


@dataclass
class PacketSummary:
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    flags: str
    payload_preview: str


@dataclass
class ConnectionRecord:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int
    bytes_total: int
    first_seen: str
    last_seen: str
    dns_name: Optional[str] = None
    is_suspicious: bool = False
    suspicious_reason: str = ""


@dataclass
class DNSRecord:
    timestamp: str
    query_name: str
    query_type: str
    response_ips: List[str]
    src_ip: str


# Well-known suspicious ports / beaconing patterns
SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9001, 9030, 6667, 6666}
C2_BEACON_INTERVALS = [60, 120, 300, 600]  # seconds


class NetworkForensics:
    """
    Analyze PCAP files for suspicious network activity.

    Usage:
        nf = NetworkForensics("capture.pcap")
        summary = nf.analyze()
        suspicious = nf.find_suspicious_connections()
        iocs = nf.extract_network_iocs()
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = str(Path(pcap_path).resolve())
        self._ioc_extractor = IOCExtractor()
        self._packets: List[PacketSummary] = []
        self._connections: Dict[str, ConnectionRecord] = {}
        self._dns_records: List[DNSRecord] = []
        self._loaded = False

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> "NetworkForensics":
        """Parse the PCAP file and populate internal data structures."""
        try:
            self._load_with_scapy()
        except ImportError:
            try:
                self._load_with_dpkt()
            except ImportError:
                self._load_with_tshark()
        self._loaded = True
        return self

    def _load_with_scapy(self):
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR

        packets = rdpcap(self.pcap_path)
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()
            ip = pkt[IP]
            proto, sport, dport, flags = "OTHER", 0, 0, ""

            if pkt.haslayer(TCP):
                tcp = pkt["TCP"]
                proto, sport, dport = "TCP", tcp.sport, tcp.dport
                flags = str(tcp.flags)
            elif pkt.haslayer(UDP):
                udp = pkt["UDP"]
                proto, sport, dport = "UDP", udp.sport, udp.dport

            # DNS
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # query
                qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                resp_ips = []
                if pkt[DNS].ancount > 0:
                    an = pkt[DNS].an
                    while an:
                        if hasattr(an, "rdata"):
                            resp_ips.append(str(an.rdata))
                        an = an.payload if hasattr(an, "payload") else None
                self._dns_records.append(DNSRecord(
                    timestamp=ts, query_name=qname, query_type="A",
                    response_ips=resp_ips, src_ip=ip.src
                ))

            payload = bytes(pkt.payload)[:100].decode(errors="replace") if pkt.payload else ""
            summary = PacketSummary(
                timestamp=ts, src_ip=ip.src, dst_ip=ip.dst,
                src_port=sport, dst_port=dport, protocol=proto,
                length=len(pkt), flags=flags, payload_preview=payload
            )
            self._packets.append(summary)
            self._update_connection(summary)

    def _load_with_dpkt(self):
        import dpkt
        import socket

        with open(self.pcap_path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)

            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    proto, sport, dport = "OTHER", 0, 0

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        proto, sport, dport = "TCP", ip.data.sport, ip.data.dport
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        proto, sport, dport = "UDP", ip.data.sport, ip.data.dport

                    timestamp = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                    summary = PacketSummary(
                        timestamp=timestamp, src_ip=src, dst_ip=dst,
                        src_port=sport, dst_port=dport, protocol=proto,
                        length=len(buf), flags="", payload_preview=""
                    )
                    self._packets.append(summary)
                    self._update_connection(summary)
                except Exception:
                    continue

    def _load_with_tshark(self):
        """Fallback: use tshark CLI to export JSON."""
        import subprocess
        result = subprocess.run(
            ["tshark", "-r", self.pcap_path, "-T", "json", "-e", "ip.src",
             "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
             "-e", "udp.srcport", "-e", "udp.dstport", "-e", "frame.time_epoch",
             "-e", "frame.len", "-E", "header=y"],
            capture_output=True, text=True
        )
        try:
            data = json.loads(result.stdout)
            for pkt in data:
                layers = pkt.get("_source", {}).get("layers", {})
                summary = PacketSummary(
                    timestamp=layers.get("frame.time_epoch", [""])[0],
                    src_ip=layers.get("ip.src", [""])[0],
                    dst_ip=layers.get("ip.dst", [""])[0],
                    src_port=int(layers.get("tcp.srcport", layers.get("udp.srcport", [0]))[0] or 0),
                    dst_port=int(layers.get("tcp.dstport", layers.get("udp.dstport", [0]))[0] or 0),
                    protocol="TCP" if "tcp.srcport" in layers else "UDP",
                    length=int(layers.get("frame.len", [0])[0] or 0),
                    flags="", payload_preview=""
                )
                self._packets.append(summary)
                self._update_connection(summary)
        except (json.JSONDecodeError, KeyError):
            pass

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """Return a high-level summary of network activity."""
        if not self._loaded:
            self.load()

        top_talkers = Counter(
            f"{p.src_ip}:{p.src_port}" for p in self._packets
        ).most_common(10)
        top_destinations = Counter(
            f"{p.dst_ip}:{p.dst_port}" for p in self._packets
        ).most_common(10)
        protocols = Counter(p.protocol for p in self._packets)
        suspicious = self.find_suspicious_connections()

        return {
            "total_packets": len(self._packets),
            "total_connections": len(self._connections),
            "dns_queries": len(self._dns_records),
            "suspicious_connections": len(suspicious),
            "top_talkers": dict(top_talkers),
            "top_destinations": dict(top_destinations),
            "protocol_breakdown": dict(protocols),
        }

    def find_suspicious_connections(self) -> List[ConnectionRecord]:
        """Flag connections to/from suspicious ports or with unusual characteristics."""
        if not self._loaded:
            self.load()
        suspicious = []
        for conn in self._connections.values():
            if conn.dst_port in SUSPICIOUS_PORTS:
                conn.is_suspicious = True
                conn.suspicious_reason = f"Known C2/malware port: {conn.dst_port}"
                suspicious.append(conn)
            elif conn.bytes_total > 100 * 1024 * 1024:  # >100MB exfil
                conn.is_suspicious = True
                conn.suspicious_reason = f"Large data transfer: {conn.bytes_total / 1024 / 1024:.1f} MB"
                suspicious.append(conn)
        return suspicious

    def extract_network_iocs(self) -> IOCBundle:
        """Extract IP, domain, and URL IOCs from DNS records and payloads."""
        if not self._loaded:
            self.load()
        text_data = " ".join(
            [r.query_name for r in self._dns_records] +
            [p.payload_preview for p in self._packets]
        )
        return self._ioc_extractor.extract(text_data)

    def export_connections_csv(self, output_path: str) -> str:
        """Export all connection records to CSV."""
        import csv
        if not self._loaded:
            self.load()
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "Src IP", "Dst IP", "Dst Port", "Protocol",
                "Packets", "Bytes", "First Seen", "Last Seen",
                "DNS Name", "Suspicious", "Reason"
            ])
            for conn in self._connections.values():
                writer.writerow([
                    conn.src_ip, conn.dst_ip, conn.dst_port, conn.protocol,
                    conn.packet_count, conn.bytes_total,
                    conn.first_seen, conn.last_seen,
                    conn.dns_name or "", conn.is_suspicious, conn.suspicious_reason
                ])
        return output_path

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _update_connection(self, pkt: PacketSummary):
        key = f"{pkt.src_ip}:{pkt.dst_ip}:{pkt.dst_port}:{pkt.protocol}"
        if key not in self._connections:
            self._connections[key] = ConnectionRecord(
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port, protocol=pkt.protocol,
                packet_count=1, bytes_total=pkt.length,
                first_seen=pkt.timestamp, last_seen=pkt.timestamp,
            )
        else:
            conn = self._connections[key]
            conn.packet_count += 1
            conn.bytes_total += pkt.length
            conn.last_seen = pkt.timestamp
