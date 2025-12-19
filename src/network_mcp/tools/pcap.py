"""Pcap analysis tools using scapy.

These tools provide smart analysis of packet captures, doing heavy processing
server-side and returning structured summaries optimized for LLM consumption.
"""

import ast
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Callable

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, rdpcap
from scapy.layers.inet import ICMP

from network_mcp.config import get_config, validate_pcap_file_path, validate_scapy_filter
from network_mcp.models.responses import (
    AnalyzeThroughputResult,
    Conversation,
    CustomFilterResult,
    DnsAnalysisResult,
    FilteredPacket,
    FilterPacketsResult,
    PcapSummaryResult,
    ProtocolHierarchyResult,
    TcpIssue,
    TcpIssuesResult,
    ThroughputConversation,
)


def _get_protocol_name(packet) -> str:
    """Get human-readable protocol name from packet."""
    if TCP in packet:
        # Check for common application protocols by port
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if 80 in (sport, dport) or 8080 in (sport, dport):
            return "HTTP"
        if 443 in (sport, dport) or 8443 in (sport, dport):
            return "HTTPS/TLS"
        if 22 in (sport, dport):
            return "SSH"
        if 21 in (sport, dport):
            return "FTP"
        if 25 in (sport, dport) or 587 in (sport, dport):
            return "SMTP"
        if 23 in (sport, dport):
            return "Telnet"
        if 3389 in (sport, dport):
            return "RDP"
        return "TCP"
    if UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        if DNS in packet:
            return "DNS"
        if 67 in (sport, dport) or 68 in (sport, dport):
            return "DHCP"
        if 123 in (sport, dport):
            return "NTP"
        if 161 in (sport, dport) or 162 in (sport, dport):
            return "SNMP"
        if 514 in (sport, dport):
            return "Syslog"
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if IP in packet:
        return "IP (other)"
    return "Other"


def _format_timestamp(ts) -> str:
    """Format packet timestamp as ISO string.

    Args:
        ts: Timestamp (float, int, or scapy EDecimal)
    """
    return datetime.fromtimestamp(float(ts)).isoformat()


def _guard_pcap_path(file_path: str) -> tuple[bool, str, str | None]:
    """Validate and normalize pcap file path access."""
    allowed, resolved, error = validate_pcap_file_path(file_path)
    return allowed, (resolved or file_path), error


def pcap_summary(
    file_path: str,
    max_packets: int = 100000,
) -> PcapSummaryResult:
    """Get a high-level summary of a packet capture file.

    Analyzes the pcap and returns key statistics including packet count,
    duration, protocol breakdown, and top talkers.

    Args:
        file_path: Path to the pcap/pcapng file
        max_packets: Maximum packets to analyze (default: 100000)

    Returns:
        PcapSummaryResult with capture statistics and summary
    """
    allowed, resolved_path, error = _guard_pcap_path(file_path)
    if not allowed:
        return PcapSummaryResult(
            success=False,
            file_path=file_path,
            packet_count=0,
            summary=f"Access denied: {error}",
        )
    file_path = resolved_path

    if not os.path.exists(file_path):
        return PcapSummaryResult(
            success=False,
            file_path=file_path,
            packet_count=0,
            summary=f"File not found: {file_path}",
        )

    try:
        packets = rdpcap(file_path, count=max_packets)
    except Exception as e:
        return PcapSummaryResult(
            success=False,
            file_path=file_path,
            packet_count=0,
            summary=f"Failed to read pcap file: {str(e)}",
        )

    if not packets:
        return PcapSummaryResult(
            success=True,
            file_path=file_path,
            packet_count=0,
            summary="Pcap file is empty (no packets)",
        )

    # Collect statistics
    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    tcp_issues = defaultdict(int)

    start_time = None
    end_time = None

    for pkt in packets:
        # Track timestamps
        if hasattr(pkt, "time"):
            if start_time is None or pkt.time < start_time:
                start_time = pkt.time
            if end_time is None or pkt.time > end_time:
                end_time = pkt.time

        # Protocol breakdown
        proto = _get_protocol_name(pkt)
        protocols[proto] += 1

        # IP statistics
        if IP in pkt:
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1

        # Quick TCP issue detection
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x04:  # RST
                tcp_issues["resets"] += 1
            if hasattr(pkt[TCP], "options"):
                for opt in pkt[TCP].options:
                    if opt[0] == "SAck":
                        tcp_issues["sack"] += 1

    # Calculate duration
    duration = None
    if start_time and end_time:
        duration = float(end_time - start_time)

    # Get file size
    file_size = os.path.getsize(file_path)

    # Top talkers
    top_talkers = [{"ip": ip, "packets": count} for ip, count in src_ips.most_common(5)]
    top_destinations = [{"ip": ip, "packets": count} for ip, count in dst_ips.most_common(5)]

    # Build summary
    summary_parts = [f"Pcap contains {len(packets)} packets"]
    if duration:
        summary_parts.append(f"spanning {duration:.2f} seconds")

    top_proto = protocols.most_common(3)
    if top_proto:
        proto_str = ", ".join(f"{p[0]} ({p[1]})" for p in top_proto)
        summary_parts.append(f"Top protocols: {proto_str}")

    if top_talkers:
        summary_parts.append(
            f"Top source: {top_talkers[0]['ip']} ({top_talkers[0]['packets']} pkts)"
        )

    if tcp_issues:
        issue_str = ", ".join(f"{k}: {v}" for k, v in tcp_issues.items())
        summary_parts.append(f"TCP issues detected: {issue_str}")

    return PcapSummaryResult(
        success=True,
        file_path=file_path,
        packet_count=len(packets),
        capture_duration_seconds=duration,
        start_time=_format_timestamp(start_time) if start_time else None,
        end_time=_format_timestamp(end_time) if end_time else None,
        file_size_bytes=file_size,
        protocols=dict(protocols),
        top_talkers=top_talkers,
        top_destinations=top_destinations,
        unique_src_ips=len(src_ips),
        unique_dst_ips=len(dst_ips),
        tcp_issues_summary=dict(tcp_issues) if tcp_issues else None,
        summary=". ".join(summary_parts),
    )


def get_conversations(
    file_path: str,
    max_packets: int = 100000,
    top_n: int = 20,
) -> list[Conversation]:
    """Extract network conversations/flows from a pcap file.

    A conversation is a bidirectional flow between two endpoints.

    Args:
        file_path: Path to the pcap/pcapng file
        max_packets: Maximum packets to analyze (default: 100000)
        top_n: Return top N conversations by packet count (default: 20)

    Returns:
        List of Conversation objects sorted by packet count
    """
    allowed, resolved_path, _ = _guard_pcap_path(file_path)
    if not allowed:
        return []
    file_path = resolved_path

    try:
        packets = rdpcap(file_path, count=max_packets)
    except Exception:
        return []

    # Track conversations
    convos = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "start_time": None,
            "end_time": None,
        }
    )

    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "IP"
        src_port = None
        dst_port = None

        if TCP in pkt:
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"

        # Create normalized key (smaller IP first for bidirectional)
        if src_port and dst_port:
            ep1 = (src_ip, src_port)
            ep2 = (dst_ip, dst_port)
        else:
            ep1 = (src_ip, 0)
            ep2 = (dst_ip, 0)

        if ep1 > ep2:
            ep1, ep2 = ep2, ep1

        key = (ep1, ep2, proto)

        convos[key]["packets"] += 1
        convos[key]["bytes"] += len(pkt)

        if hasattr(pkt, "time"):
            pkt_time = float(pkt.time)
            if convos[key]["start_time"] is None:
                convos[key]["start_time"] = pkt_time
            convos[key]["end_time"] = pkt_time

    # Convert to Conversation objects
    result = []
    for (ep1, ep2, proto), stats in convos.items():
        duration = None
        if stats["start_time"] and stats["end_time"]:
            duration = stats["end_time"] - stats["start_time"]

        result.append(
            Conversation(
                src_ip=ep1[0],
                src_port=ep1[1] if ep1[1] != 0 else None,
                dst_ip=ep2[0],
                dst_port=ep2[1] if ep2[1] != 0 else None,
                protocol=proto,
                packets=stats["packets"],
                bytes=stats["bytes"],
                start_time=stats["start_time"],
                duration_seconds=duration,
            )
        )

    # Sort by packet count and return top N
    result.sort(key=lambda c: c.packets, reverse=True)
    return result[:top_n]


def analyze_throughput(
    file_path: str,
    max_packets: int = 100000,
    top_n: int = 20,
    sort_by: str = "mbps_total",
) -> AnalyzeThroughputResult:
    """Calculate observed throughput per conversation from a pcap.

    This is an "observed" metric: it reports achieved throughput in the capture,
    not theoretical available bandwidth.
    """
    allowed, resolved_path, error = _guard_pcap_path(file_path)
    if not allowed:
        return AnalyzeThroughputResult(
            success=False,
            file_path=file_path,
            total_packets_scanned=0,
            conversations_analyzed=0,
            top_n=0,
            sort_by=sort_by,
            conversations=[],
            summary=f"Access denied: {error}",
        )
    file_path = resolved_path

    if not os.path.exists(file_path):
        return AnalyzeThroughputResult(
            success=False,
            file_path=file_path,
            total_packets_scanned=0,
            conversations_analyzed=0,
            top_n=0,
            sort_by=sort_by,
            conversations=[],
            summary=f"File not found: {file_path}",
        )

    try:
        packets = rdpcap(file_path, count=max_packets)
    except Exception as e:
        return AnalyzeThroughputResult(
            success=False,
            file_path=file_path,
            total_packets_scanned=0,
            conversations_analyzed=0,
            top_n=0,
            sort_by=sort_by,
            conversations=[],
            summary=f"Failed to read pcap file: {e}",
        )

    # Aggregate bidirectional conversations with per-direction byte counters.
    convos = defaultdict(
        lambda: {
            "packets_total": 0,
            "bytes_total": 0,
            "packets_ab": 0,
            "bytes_ab": 0,
            "packets_ba": 0,
            "bytes_ba": 0,
            "start_time": None,
            "end_time": None,
        }
    )

    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "IP"
        src_port = None
        dst_port = None

        if TCP in pkt:
            proto = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"

        if src_port is not None and dst_port is not None:
            ep_a = (src_ip, src_port)
            ep_b = (dst_ip, dst_port)
        else:
            ep_a = (src_ip, 0)
            ep_b = (dst_ip, 0)

        # Normalize ordering for stable conversation key.
        a = ep_a
        b = ep_b
        if a > b:
            a, b = b, a

        key = (a, b, proto)
        stats = convos[key]
        stats["packets_total"] += 1
        pkt_len = len(pkt)
        stats["bytes_total"] += pkt_len

        if ep_a == a and ep_b == b:
            stats["packets_ab"] += 1
            stats["bytes_ab"] += pkt_len
        else:
            stats["packets_ba"] += 1
            stats["bytes_ba"] += pkt_len

        if hasattr(pkt, "time"):
            ts = float(pkt.time)
            if stats["start_time"] is None or ts < stats["start_time"]:
                stats["start_time"] = ts
            if stats["end_time"] is None or ts > stats["end_time"]:
                stats["end_time"] = ts

    conversations: list[ThroughputConversation] = []
    for (a, b, proto), s in convos.items():
        start = s["start_time"]
        end = s["end_time"]
        duration = (
            float(end - start) if (start is not None and end is not None and end >= start) else None
        )
        if duration is not None and duration <= 0:
            duration = None

        # Decide dominant direction by bytes.
        if s["bytes_ab"] >= s["bytes_ba"]:
            src = a
            dst = b
            bytes_f = s["bytes_ab"]
            pkts_f = s["packets_ab"]
            bytes_r = s["bytes_ba"]
            pkts_r = s["packets_ba"]
        else:
            src = b
            dst = a
            bytes_f = s["bytes_ba"]
            pkts_f = s["packets_ba"]
            bytes_r = s["bytes_ab"]
            pkts_r = s["packets_ab"]

        def mbps(byte_count: int) -> float | None:
            if duration is None:
                return None
            return round((byte_count * 8.0) / duration / 1_000_000.0, 3)

        mbps_f = mbps(bytes_f)
        mbps_r = mbps(bytes_r)
        mbps_t = mbps(s["bytes_total"])

        src_port = None if src[1] == 0 else src[1]
        dst_port = None if dst[1] == 0 else dst[1]
        direction = f"{src[0]}:{src_port or 0} -> {dst[0]}:{dst_port or 0}"

        conversations.append(
            ThroughputConversation(
                src_ip=src[0],
                src_port=src_port,
                dst_ip=dst[0],
                dst_port=dst_port,
                protocol=proto,
                packets_total=s["packets_total"],
                bytes_total=s["bytes_total"],
                duration_seconds=duration,
                start_time=start,
                end_time=end,
                packets_forward=pkts_f,
                bytes_forward=bytes_f,
                packets_reverse=pkts_r,
                bytes_reverse=bytes_r,
                mbps_forward=mbps_f,
                mbps_reverse=mbps_r,
                mbps_total=mbps_t,
                direction=direction,
            )
        )

    sort_by_norm = sort_by.lower().strip()
    if sort_by_norm not in {"mbps_total", "bytes_total"}:
        sort_by_norm = "mbps_total"

    if sort_by_norm == "mbps_total":
        conversations.sort(key=lambda c: (c.mbps_total or 0.0, c.bytes_total), reverse=True)
    else:
        conversations.sort(key=lambda c: (c.bytes_total, c.packets_total), reverse=True)

    top = conversations[: max(0, int(top_n))]

    if top:
        top0 = top[0]
        if top0.mbps_total is not None and top0.duration_seconds is not None:
            top_desc = f"Top flow {top0.direction} at ~{top0.mbps_total} Mbps over {top0.duration_seconds:.2f}s"
        else:
            top_desc = f"Top flow {top0.direction} ({top0.bytes_total} bytes)"
        summary = f"Throughput analysis: {len(conversations)} conversations from {len(packets)} packets. {top_desc}"
    else:
        summary = f"Throughput analysis: 0 conversations from {len(packets)} packets"

    return AnalyzeThroughputResult(
        success=True,
        file_path=file_path,
        total_packets_scanned=len(packets),
        conversations_analyzed=len(conversations),
        top_n=len(top),
        sort_by=sort_by_norm,
        conversations=top,
        summary=summary,
    )


def find_tcp_issues(
    file_path: str,
    max_packets: int = 100000,
) -> TcpIssuesResult:
    """Analyze TCP packets for issues like retransmissions, resets, and problems.

    Detects common TCP issues that indicate network problems:
    - Retransmissions (packet loss)
    - RST packets (connection resets)
    - Zero window (buffer full)
    - Duplicate ACKs (potential loss)

    Args:
        file_path: Path to the pcap/pcapng file
        max_packets: Maximum packets to analyze (default: 100000)

    Returns:
        TcpIssuesResult with categorized issues and recommendations
    """
    allowed, resolved_path, error = _guard_pcap_path(file_path)
    if not allowed:
        return TcpIssuesResult(
            success=False,
            file_path=file_path,
            total_tcp_packets=0,
            issues=[],
            has_issues=False,
            summary=f"Access denied: {error}",
        )
    file_path = resolved_path

    if not os.path.exists(file_path):
        return TcpIssuesResult(
            success=False,
            file_path=file_path,
            total_tcp_packets=0,
            issues=[],
            has_issues=False,
            summary=f"File not found: {file_path}",
        )

    try:
        packets = rdpcap(file_path, count=max_packets)
    except Exception as e:
        return TcpIssuesResult(
            success=False,
            file_path=file_path,
            total_tcp_packets=0,
            issues=[],
            has_issues=False,
            summary=f"Failed to read pcap file: {str(e)}",
        )

    # Track TCP state per flow
    flows = defaultdict(
        lambda: {
            "seq_seen": set(),
            "last_seq": None,
            "last_ack": None,
            "ack_count": defaultdict(int),
        }
    )

    issues_count = defaultdict(lambda: {"count": 0, "flows": set()})
    total_tcp = 0

    for pkt in packets:
        if TCP not in pkt or IP not in pkt:
            continue

        total_tcp += 1
        src = f"{pkt[IP].src}:{pkt[TCP].sport}"
        dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"
        flow_key = tuple(sorted([src, dst]))
        flow = flows[flow_key]

        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        flags = pkt[TCP].flags

        # Check for RST
        if flags & 0x04:
            issues_count["reset"]["count"] += 1
            issues_count["reset"]["flows"].add(f"{src} -> {dst}")

        # Check for zero window
        if pkt[TCP].window == 0 and not (flags & 0x04):  # Not RST
            issues_count["zero_window"]["count"] += 1
            issues_count["zero_window"]["flows"].add(f"{src} -> {dst}")

        # Check for retransmissions (same seq seen before)
        if seq in flow["seq_seen"] and len(pkt[TCP].payload) > 0:
            issues_count["retransmission"]["count"] += 1
            issues_count["retransmission"]["flows"].add(f"{src} -> {dst}")
        else:
            flow["seq_seen"].add(seq)

        # Check for duplicate ACKs
        if ack > 0:
            flow["ack_count"][ack] += 1
            if flow["ack_count"][ack] == 3:  # Triple dup ACK
                issues_count["dup_ack"]["count"] += 1
                issues_count["dup_ack"]["flows"].add(f"{src} -> {dst}")

    # Build issue objects
    issues = []

    if issues_count["retransmission"]["count"] > 0:
        count = issues_count["retransmission"]["count"]
        severity = "high" if count > 100 else "medium" if count > 10 else "low"
        issues.append(
            TcpIssue(
                issue_type="retransmission",
                count=count,
                affected_flows=list(issues_count["retransmission"]["flows"])[:5],
                severity=severity,
                recommendation="Retransmissions indicate packet loss. Check for network congestion, faulty links, or interface errors along the path.",
            )
        )

    if issues_count["reset"]["count"] > 0:
        count = issues_count["reset"]["count"]
        severity = "medium" if count > 50 else "low"
        issues.append(
            TcpIssue(
                issue_type="reset",
                count=count,
                affected_flows=list(issues_count["reset"]["flows"])[:5],
                severity=severity,
                recommendation="TCP resets may indicate connection refusals, application crashes, or firewall interference.",
            )
        )

    if issues_count["zero_window"]["count"] > 0:
        count = issues_count["zero_window"]["count"]
        severity = "high" if count > 50 else "medium"
        issues.append(
            TcpIssue(
                issue_type="zero_window",
                count=count,
                affected_flows=list(issues_count["zero_window"]["flows"])[:5],
                severity=severity,
                recommendation="Zero window indicates receiver buffer is full. Check application performance or increase buffer sizes.",
            )
        )

    if issues_count["dup_ack"]["count"] > 0:
        count = issues_count["dup_ack"]["count"]
        severity = "medium" if count > 20 else "low"
        issues.append(
            TcpIssue(
                issue_type="duplicate_ack",
                count=count,
                affected_flows=list(issues_count["dup_ack"]["flows"])[:5],
                severity=severity,
                recommendation="Duplicate ACKs often precede retransmissions and indicate out-of-order delivery or packet loss.",
            )
        )

    # Build summary
    if not issues:
        summary = f"No TCP issues detected in {total_tcp} TCP packets"
    else:
        issue_summary = ", ".join(f"{i.count} {i.issue_type}s" for i in issues)
        high_severity = [i for i in issues if i.severity == "high"]
        if high_severity:
            summary = f"ATTENTION: High severity TCP issues detected. {issue_summary}. Immediate investigation recommended."
        else:
            summary = f"TCP issues detected in {total_tcp} packets: {issue_summary}"

    return TcpIssuesResult(
        success=True,
        file_path=file_path,
        total_tcp_packets=total_tcp,
        issues=issues,
        has_issues=len(issues) > 0,
        summary=summary,
    )


def analyze_dns_traffic(
    file_path: str,
    max_packets: int = 100000,
) -> DnsAnalysisResult:
    """Analyze DNS traffic in a packet capture.

    Extracts DNS queries and responses, identifies failures, and finds
    slow queries that may indicate DNS issues.

    Args:
        file_path: Path to the pcap/pcapng file
        max_packets: Maximum packets to analyze (default: 100000)

    Returns:
        DnsAnalysisResult with DNS traffic analysis
    """
    allowed, resolved_path, error = _guard_pcap_path(file_path)
    if not allowed:
        return DnsAnalysisResult(
            success=False,
            file_path=file_path,
            total_dns_packets=0,
            total_queries=0,
            total_responses=0,
            unique_domains=0,
            summary=f"Access denied: {error}",
        )
    file_path = resolved_path

    if not os.path.exists(file_path):
        return DnsAnalysisResult(
            success=False,
            file_path=file_path,
            total_dns_packets=0,
            total_queries=0,
            total_responses=0,
            unique_domains=0,
            summary=f"File not found: {file_path}",
        )

    try:
        packets = rdpcap(file_path, count=max_packets)
    except Exception as e:
        return DnsAnalysisResult(
            success=False,
            file_path=file_path,
            total_dns_packets=0,
            total_queries=0,
            total_responses=0,
            unique_domains=0,
            summary=f"Failed to read pcap file: {str(e)}",
        )

    # Track DNS statistics
    queries = {}  # query_id -> {name, type, time, client}
    domains = Counter()
    failed = []
    slow_queries = []
    total_queries = 0
    total_responses = 0
    total_dns = 0

    # DNS response codes
    rcodes = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }

    for pkt in packets:
        if DNS not in pkt:
            continue

        total_dns += 1
        dns_layer = pkt[DNS]

        # Query
        if dns_layer.qr == 0 and DNSQR in pkt:
            total_queries += 1
            qname = (
                pkt[DNSQR].qname.decode()
                if isinstance(pkt[DNSQR].qname, bytes)
                else str(pkt[DNSQR].qname)
            )
            qname = qname.rstrip(".")
            qtype = pkt[DNSQR].qtype

            domains[qname] += 1

            client_ip = pkt[IP].src if IP in pkt else "unknown"
            queries[dns_layer.id] = {
                "name": qname,
                "type": qtype,
                "time": float(pkt.time) if hasattr(pkt, "time") else None,
                "client": client_ip,
            }

        # Response
        elif dns_layer.qr == 1:
            total_responses += 1
            rcode = dns_layer.rcode
            rcode_name = rcodes.get(rcode, f"UNKNOWN({rcode})")

            # Match to query
            if dns_layer.id in queries:
                query = queries[dns_layer.id]
                response_time = None
                if query["time"] and hasattr(pkt, "time"):
                    response_time = (float(pkt.time) - query["time"]) * 1000  # ms

                # Track failures
                if rcode != 0:
                    failed.append(
                        {
                            "domain": query["name"],
                            "error": rcode_name,
                            "client": query["client"],
                        }
                    )

                # Track slow queries (>100ms)
                if response_time and response_time > 100:
                    slow_queries.append(
                        {
                            "domain": query["name"],
                            "response_time_ms": round(response_time, 2),
                            "client": query["client"],
                        }
                    )

    # Top queried domains
    top_domains = [{"domain": domain, "count": count} for domain, count in domains.most_common(10)]

    # Build summary
    summary_parts = [f"DNS analysis: {total_queries} queries, {total_responses} responses"]

    if failed:
        summary_parts.append(f"{len(failed)} failed queries (NXDOMAIN/SERVFAIL)")

    if slow_queries:
        summary_parts.append(f"{len(slow_queries)} slow queries (>100ms)")

    if top_domains:
        top = top_domains[0]
        summary_parts.append(f"Most queried: {top['domain']} ({top['count']} times)")

    return DnsAnalysisResult(
        success=True,
        file_path=file_path,
        total_dns_packets=total_dns,
        total_queries=total_queries,
        total_responses=total_responses,
        unique_domains=len(domains),
        top_queried_domains=top_domains,
        failed_queries=failed[:10],  # Limit to 10
        slow_queries=slow_queries[:10],  # Limit to 10
        summary=". ".join(summary_parts),
    )


def filter_packets(
    file_path: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
    custom_filter: Callable | None = None,
    max_packets: int = 100000,
    max_results: int = 100,
) -> FilterPacketsResult:
    """Filter packets from a pcap file based on criteria.

    Args:
        file_path: Path to the pcap/pcapng file
        src_ip: Filter by source IP address
        dst_ip: Filter by destination IP address
        protocol: Filter by protocol (TCP, UDP, ICMP, DNS)
        port: Filter by port (source or destination)
        custom_filter: Custom filter function taking packet, returning bool
        max_packets: Maximum packets to scan (default: 100000)
        max_results: Maximum matching packets to return (default: 100)

    Returns:
        FilterPacketsResult with matching packets
    """
    allowed, resolved_path, error = _guard_pcap_path(file_path)
    if not allowed:
        return FilterPacketsResult(
            success=False,
            file_path=file_path,
            filter_expression="",
            total_packets_scanned=0,
            matching_packets=0,
            packets=[],
            summary=f"Access denied: {error}",
        )
    file_path = resolved_path

    if not os.path.exists(file_path):
        return FilterPacketsResult(
            success=False,
            file_path=file_path,
            filter_expression="",
            total_packets_scanned=0,
            matching_packets=0,
            packets=[],
            summary=f"File not found: {file_path}",
        )

    try:
        packets = rdpcap(file_path, count=max_packets)
    except Exception as e:
        return FilterPacketsResult(
            success=False,
            file_path=file_path,
            filter_expression="",
            total_packets_scanned=0,
            matching_packets=0,
            packets=[],
            summary=f"Failed to read pcap file: {str(e)}",
        )

    # Build filter description
    filter_parts = []
    if src_ip:
        filter_parts.append(f"src={src_ip}")
    if dst_ip:
        filter_parts.append(f"dst={dst_ip}")
    if protocol:
        filter_parts.append(f"proto={protocol}")
    if port:
        filter_parts.append(f"port={port}")
    if custom_filter:
        filter_parts.append("custom_filter")

    filter_expr = " AND ".join(filter_parts) if filter_parts else "none"

    matching = []
    match_count = 0

    for i, pkt in enumerate(packets, 1):
        matches = True

        # Source IP filter
        if src_ip and matches:
            if IP in pkt:
                matches = pkt[IP].src == src_ip
            else:
                matches = False

        # Destination IP filter
        if dst_ip and matches:
            if IP in pkt:
                matches = pkt[IP].dst == dst_ip
            else:
                matches = False

        # Protocol filter
        if protocol and matches:
            proto_upper = protocol.upper()
            if proto_upper == "TCP":
                matches = TCP in pkt
            elif proto_upper == "UDP":
                matches = UDP in pkt
            elif proto_upper == "ICMP":
                matches = ICMP in pkt
            elif proto_upper == "DNS":
                matches = DNS in pkt
            else:
                matches = _get_protocol_name(pkt).upper() == proto_upper

        # Port filter
        if port and matches:
            if TCP in pkt:
                matches = pkt[TCP].sport == port or pkt[TCP].dport == port
            elif UDP in pkt:
                matches = pkt[UDP].sport == port or pkt[UDP].dport == port
            else:
                matches = False

        # Custom filter
        if custom_filter and matches:
            try:
                matches = custom_filter(pkt)
            except Exception:
                matches = False

        if matches:
            match_count += 1
            if len(matching) < max_results:
                # Build packet info
                src = dst = None
                proto = _get_protocol_name(pkt)

                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst

                # Build info string
                info_parts = [proto]
                if TCP in pkt:
                    info_parts.append(f"{pkt[TCP].sport} -> {pkt[TCP].dport}")
                    flags = []
                    if pkt[TCP].flags & 0x02:
                        flags.append("SYN")
                    if pkt[TCP].flags & 0x10:
                        flags.append("ACK")
                    if pkt[TCP].flags & 0x01:
                        flags.append("FIN")
                    if pkt[TCP].flags & 0x04:
                        flags.append("RST")
                    if flags:
                        info_parts.append(f"[{','.join(flags)}]")
                elif UDP in pkt:
                    info_parts.append(f"{pkt[UDP].sport} -> {pkt[UDP].dport}")
                elif DNS in pkt and DNSQR in pkt:
                    qname = (
                        pkt[DNSQR].qname.decode()
                        if isinstance(pkt[DNSQR].qname, bytes)
                        else str(pkt[DNSQR].qname)
                    )
                    info_parts.append(qname)

                matching.append(
                    FilteredPacket(
                        packet_number=i,
                        timestamp=float(pkt.time) if hasattr(pkt, "time") else 0,
                        src_ip=src,
                        dst_ip=dst,
                        protocol=proto,
                        length=len(pkt),
                        info=" ".join(info_parts),
                    )
                )

    summary = f"Filter '{filter_expr}': {match_count} packets matched out of {len(packets)} scanned"
    if match_count > max_results:
        summary += f" (showing first {max_results})"

    return FilterPacketsResult(
        success=True,
        file_path=file_path,
        filter_expression=filter_expr,
        total_packets_scanned=len(packets),
        matching_packets=match_count,
        packets=matching,
        summary=summary,
    )


def get_protocol_hierarchy(
    file_path: str,
    max_packets: int = 100000,
) -> ProtocolHierarchyResult:
    """Analyze protocol distribution in a packet capture.

    Provides a breakdown of protocols by packet count and bytes,
    similar to Wireshark's protocol hierarchy view.

    Args:
        file_path: Path to the pcap/pcapng file
        max_packets: Maximum packets to analyze (default: 100000)

    Returns:
        ProtocolHierarchyResult with protocol statistics
    """
    allowed, resolved_path, error = _guard_pcap_path(file_path)
    if not allowed:
        return ProtocolHierarchyResult(
            success=False,
            file_path=file_path,
            total_packets=0,
            total_bytes=0,
            hierarchy={},
            summary=f"Access denied: {error}",
        )
    file_path = resolved_path

    if not os.path.exists(file_path):
        return ProtocolHierarchyResult(
            success=False,
            file_path=file_path,
            total_packets=0,
            total_bytes=0,
            hierarchy={},
            summary=f"File not found: {file_path}",
        )

    try:
        packets = rdpcap(file_path, count=max_packets)
    except Exception as e:
        return ProtocolHierarchyResult(
            success=False,
            file_path=file_path,
            total_packets=0,
            total_bytes=0,
            hierarchy={},
            summary=f"Failed to read pcap file: {str(e)}",
        )

    # Track protocol stats
    proto_packets = Counter()
    proto_bytes = Counter()
    total_bytes = 0

    for pkt in packets:
        pkt_len = len(pkt)
        total_bytes += pkt_len
        proto = _get_protocol_name(pkt)
        proto_packets[proto] += 1
        proto_bytes[proto] += pkt_len

    # Build hierarchy
    total_pkts = len(packets)
    hierarchy = {}
    for proto, count in proto_packets.items():
        hierarchy[proto] = {
            "packets": count,
            "bytes": proto_bytes[proto],
            "packet_percent": round(count / total_pkts * 100, 2) if total_pkts > 0 else 0,
            "byte_percent": round(proto_bytes[proto] / total_bytes * 100, 2)
            if total_bytes > 0
            else 0,
        }

    # Top protocols
    top_protocols = [
        {
            "protocol": proto,
            "packets": count,
            "percent": round(count / total_pkts * 100, 1) if total_pkts > 0 else 0,
        }
        for proto, count in proto_packets.most_common(10)
    ]

    # Build summary
    if top_protocols:
        top_3 = top_protocols[:3]
        proto_summary = ", ".join(f"{p['protocol']} ({p['percent']}%)" for p in top_3)
        summary = f"Protocol breakdown of {total_pkts} packets: {proto_summary}"
    else:
        summary = "No packets found in capture"

    return ProtocolHierarchyResult(
        success=True,
        file_path=file_path,
        total_packets=total_pkts,
        total_bytes=total_bytes,
        hierarchy=hierarchy,
        top_protocols=top_protocols,
        summary=summary,
    )


def custom_scapy_filter(
    file_path: str,
    filter_expression: str,
    max_packets: int | None = None,
    max_results: int = 100,
) -> CustomFilterResult:
    """Execute a custom scapy filter expression on a pcap file.

    Allows advanced users to use scapy's packet filtering syntax for complex
    queries. The filter expression is validated for safety before execution.

    Supported filter syntax examples:
    - "TCP and IP.dst == '10.0.0.1'"
    - "UDP and DNS"
    - "TCP.flags.S == 1"  (SYN packets)
    - "IP.ttl < 64"
    - "len(packet) > 1000"

    Args:
        file_path: Path to the pcap/pcapng file
        filter_expression: Scapy-style filter expression
        max_packets: Maximum packets to scan (uses config default if None)
        max_results: Maximum matching packets to return (default: 100)

    Returns:
        CustomFilterResult with matching packets
    """
    allowed, resolved_path, error = _guard_pcap_path(file_path)
    if not allowed:
        return CustomFilterResult(
            success=False,
            file_path=file_path,
            filter_expression=filter_expression,
            total_packets_scanned=0,
            matching_packets=0,
            packets=[],
            error=f"Access denied: {error}",
            summary=f"Access denied: {error}",
        )
    file_path = resolved_path

    # Validate the filter expression for safety
    is_valid, error_msg = validate_scapy_filter(filter_expression)
    if not is_valid:
        return CustomFilterResult(
            success=False,
            file_path=file_path,
            filter_expression=filter_expression,
            total_packets_scanned=0,
            matching_packets=0,
            packets=[],
            error=error_msg,
            summary=f"Filter rejected: {error_msg}",
        )

    # Use config default if max_packets not specified
    if max_packets is None:
        config = get_config()
        max_packets = config.pcap.max_packets

    if not os.path.exists(file_path):
        return CustomFilterResult(
            success=False,
            file_path=file_path,
            filter_expression=filter_expression,
            total_packets_scanned=0,
            matching_packets=0,
            packets=[],
            error=f"File not found: {file_path}",
            summary=f"File not found: {file_path}",
        )

    try:
        packets = rdpcap(file_path, count=max_packets)
    except Exception as e:
        return CustomFilterResult(
            success=False,
            file_path=file_path,
            filter_expression=filter_expression,
            total_packets_scanned=0,
            matching_packets=0,
            packets=[],
            error=str(e),
            summary=f"Failed to read pcap file: {str(e)}",
        )

    # Build a safe filter function from the expression (AST-validated)
    def create_filter_func(expr: str):
        """Create a safe filter function from a restricted expression language."""
        expr = expr.strip()

        # Support shorthand like "IP.ttl < 64" -> "pkt[IP].ttl < 64"
        expr = re.sub(r"\b(packet)\b", "pkt", expr)
        expr = re.sub(r"\b(IP|TCP|UDP|ICMP|DNS)\.([A-Za-z_]\w*)\b", r"pkt[\1].\2", expr)

        safe_namespace = {
            "TCP": TCP,
            "UDP": UDP,
            "IP": IP,
            "ICMP": ICMP,
            "DNS": DNS,
            "DNSQR": DNSQR,
            "DNSRR": DNSRR,
            "len": len,
            "True": True,
            "False": False,
        }

        allowed_names = set(safe_namespace.keys()) | {"pkt"}

        allowed_nodes = (
            ast.Expression,
            ast.BoolOp,
            ast.BinOp,
            ast.UnaryOp,
            ast.Compare,
            ast.Call,
            ast.Name,
            ast.Load,
            ast.Constant,
            ast.Subscript,
            ast.Attribute,
            ast.List,
            ast.Tuple,
            ast.Slice,
            ast.And,
            ast.Or,
            ast.Not,
            ast.In,
            ast.NotIn,
            ast.Eq,
            ast.NotEq,
            ast.Lt,
            ast.LtE,
            ast.Gt,
            ast.GtE,
            ast.Is,
            ast.IsNot,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.Mod,
            ast.BitAnd,
            ast.BitOr,
            ast.BitXor,
            ast.LShift,
            ast.RShift,
        )

        class Validator(ast.NodeVisitor):
            def generic_visit(self, node):
                if not isinstance(node, allowed_nodes):
                    raise ValueError(f"Unsupported syntax: {type(node).__name__}")
                super().generic_visit(node)

            def visit_Name(self, node: ast.Name):
                if node.id not in allowed_names:
                    raise ValueError(f"Unknown/blocked name: {node.id}")

            def visit_Call(self, node: ast.Call):
                # Only allow:
                # - len(<expr>)
                # - pkt.haslayer(<Layer>)
                if isinstance(node.func, ast.Name) and node.func.id == "len":
                    if len(node.args) != 1 or node.keywords:
                        raise ValueError("len() must have exactly one positional argument")
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "haslayer":
                    if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "pkt"):
                        raise ValueError("haslayer() must be called as pkt.haslayer(...)")
                    if len(node.args) != 1 or node.keywords:
                        raise ValueError("pkt.haslayer() must have exactly one positional argument")
                else:
                    raise ValueError("Only len(...) and pkt.haslayer(...) calls are allowed")
                self.generic_visit(node)

        allowed_attrs = {
            # Common layer fields
            "src",
            "dst",
            "sport",
            "dport",
            "proto",
            "ttl",
            "id",
            "seq",
            "ack",
            "window",
            "chksum",
            "flags",
            "payload",
            # DNS
            "qname",
            "qtype",
            "rdata",
            "qr",
            "opcode",
            "rcode",
        }

        class StrictValidator(Validator):
            def visit_Attribute(self, node: ast.Attribute):
                # Block dunder traversal and restrict which fields can be read
                if node.attr.startswith("__"):
                    raise ValueError("Dunder attribute access is not allowed")
                if node.attr not in allowed_attrs:
                    raise ValueError(f"Unsupported attribute: {node.attr}")
                self.generic_visit(node)

            def visit_Subscript(self, node: ast.Subscript):
                # Only allow pkt[<Layer>] indexing
                if not (isinstance(node.value, ast.Name) and node.value.id == "pkt"):
                    raise ValueError("Only pkt[Layer] indexing is allowed")
                if not isinstance(node.slice, ast.Name) or node.slice.id not in {
                    "IP",
                    "TCP",
                    "UDP",
                    "ICMP",
                    "DNS",
                    "DNSQR",
                    "DNSRR",
                }:
                    raise ValueError("pkt[...] index must be a known layer name (e.g., TCP, IP)")
                self.generic_visit(node)

        tree = ast.parse(expr, mode="eval")
        StrictValidator().visit(tree)

        def _eval_node(node: ast.AST, local_ns: dict):
            if isinstance(node, ast.Expression):
                return _eval_node(node.body, local_ns)

            if isinstance(node, ast.Constant):
                return node.value

            if isinstance(node, ast.Name):
                return local_ns[node.id]

            if isinstance(node, ast.BoolOp):
                if isinstance(node.op, ast.And):
                    for v in node.values:
                        if not bool(_eval_node(v, local_ns)):
                            return False
                    return True
                if isinstance(node.op, ast.Or):
                    for v in node.values:
                        if bool(_eval_node(v, local_ns)):
                            return True
                    return False
                raise ValueError("Unsupported boolean operator")

            if isinstance(node, ast.UnaryOp):
                if isinstance(node.op, ast.Not):
                    return not bool(_eval_node(node.operand, local_ns))
                if isinstance(node.op, ast.UAdd):
                    return +_eval_node(node.operand, local_ns)
                if isinstance(node.op, ast.USub):
                    return -_eval_node(node.operand, local_ns)
                raise ValueError("Unsupported unary operator")

            if isinstance(node, ast.BinOp):
                left = _eval_node(node.left, local_ns)
                right = _eval_node(node.right, local_ns)
                op = node.op
                if isinstance(op, ast.Add):
                    return left + right
                if isinstance(op, ast.Sub):
                    return left - right
                if isinstance(op, ast.Mult):
                    return left * right
                if isinstance(op, ast.Div):
                    return left / right
                if isinstance(op, ast.Mod):
                    return left % right
                if isinstance(op, ast.BitAnd):
                    return left & right
                if isinstance(op, ast.BitOr):
                    return left | right
                if isinstance(op, ast.BitXor):
                    return left ^ right
                if isinstance(op, ast.LShift):
                    return left << right
                if isinstance(op, ast.RShift):
                    return left >> right
                raise ValueError("Unsupported binary operator")

            if isinstance(node, ast.Compare):
                left = _eval_node(node.left, local_ns)
                for op, comp in zip(node.ops, node.comparators, strict=False):
                    right = _eval_node(comp, local_ns)
                    ok = None
                    if isinstance(op, ast.In):
                        ok = left in right
                    elif isinstance(op, ast.NotIn):
                        ok = left not in right
                    elif isinstance(op, ast.Eq):
                        ok = left == right
                    elif isinstance(op, ast.NotEq):
                        ok = left != right
                    elif isinstance(op, ast.Lt):
                        ok = left < right
                    elif isinstance(op, ast.LtE):
                        ok = left <= right
                    elif isinstance(op, ast.Gt):
                        ok = left > right
                    elif isinstance(op, ast.GtE):
                        ok = left >= right
                    elif isinstance(op, ast.Is):
                        ok = left is right
                    elif isinstance(op, ast.IsNot):
                        ok = left is not right
                    else:
                        raise ValueError("Unsupported comparison operator")
                    if not ok:
                        return False
                    left = right
                return True

            if isinstance(node, ast.Subscript):
                value = _eval_node(node.value, local_ns)
                idx = _eval_node(node.slice, local_ns)
                return value[idx]

            if isinstance(node, ast.Attribute):
                value = _eval_node(node.value, local_ns)
                return getattr(value, node.attr)

            if isinstance(node, ast.Call):
                # Only allow:
                # - len(<expr>)
                # - pkt.haslayer(<Layer>)
                if isinstance(node.func, ast.Name) and node.func.id == "len":
                    return len(_eval_node(node.args[0], local_ns))
                if isinstance(node.func, ast.Attribute) and node.func.attr == "haslayer":
                    # Must be called as pkt.haslayer(Layer)
                    pkt_obj = _eval_node(node.func.value, local_ns)
                    layer = _eval_node(node.args[0], local_ns)
                    return bool(pkt_obj.haslayer(layer))
                raise ValueError("Unsupported call")

            raise ValueError(f"Unsupported syntax: {type(node).__name__}")

        def filter_func(pkt):
            local_ns = safe_namespace.copy()
            local_ns["pkt"] = pkt
            try:
                return bool(_eval_node(tree, local_ns))
            except Exception:
                return False

        return filter_func

    try:
        filter_func = create_filter_func(filter_expression)
    except Exception as e:
        return CustomFilterResult(
            success=False,
            file_path=file_path,
            filter_expression=filter_expression,
            total_packets_scanned=0,
            matching_packets=0,
            packets=[],
            error=f"Invalid filter expression: {str(e)}",
            summary=f"Invalid filter expression: {str(e)}",
        )

    matching = []
    match_count = 0

    for i, pkt in enumerate(packets, 1):
        try:
            if filter_func(pkt):
                match_count += 1
                if len(matching) < max_results:
                    # Build packet info
                    src = dst = None
                    proto = _get_protocol_name(pkt)

                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst

                    # Build info string
                    info_parts = [proto]
                    if TCP in pkt:
                        info_parts.append(f"{pkt[TCP].sport} -> {pkt[TCP].dport}")
                        flags = []
                        if pkt[TCP].flags & 0x02:
                            flags.append("SYN")
                        if pkt[TCP].flags & 0x10:
                            flags.append("ACK")
                        if pkt[TCP].flags & 0x01:
                            flags.append("FIN")
                        if pkt[TCP].flags & 0x04:
                            flags.append("RST")
                        if flags:
                            info_parts.append(f"[{','.join(flags)}]")
                    elif UDP in pkt:
                        info_parts.append(f"{pkt[UDP].sport} -> {pkt[UDP].dport}")
                    elif DNS in pkt and DNSQR in pkt:
                        qname = (
                            pkt[DNSQR].qname.decode()
                            if isinstance(pkt[DNSQR].qname, bytes)
                            else str(pkt[DNSQR].qname)
                        )
                        info_parts.append(qname)

                    matching.append(
                        FilteredPacket(
                            packet_number=i,
                            timestamp=float(pkt.time) if hasattr(pkt, "time") else 0,
                            src_ip=src,
                            dst_ip=dst,
                            protocol=proto,
                            length=len(pkt),
                            info=" ".join(info_parts),
                        )
                    )
        except Exception:
            # Skip packets that cause filter errors
            continue

    summary = f"Custom filter '{filter_expression}': {match_count} packets matched out of {len(packets)} scanned"
    if match_count > max_results:
        summary += f" (showing first {max_results})"

    return CustomFilterResult(
        success=True,
        file_path=file_path,
        filter_expression=filter_expression,
        total_packets_scanned=len(packets),
        matching_packets=match_count,
        packets=matching,
        summary=summary,
    )
