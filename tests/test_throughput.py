"""Unit tests for analyze_throughput."""

import os
import tempfile

from scapy.all import IP, TCP, Raw, wrpcap

from network_mcp.tools.pcap import analyze_throughput


def test_analyze_throughput_basic_direction_and_duration():
    # Create a tiny pcap with two packets 1s apart (A->B larger than B->A)
    a = "10.0.0.1"
    b = "10.0.0.2"
    p1 = IP(src=a, dst=b) / TCP(sport=12345, dport=443) / Raw(load=b"x" * 1000)
    p2 = IP(src=b, dst=a) / TCP(sport=443, dport=12345) / Raw(load=b"y" * 200)
    p1.time = 1.0
    p2.time = 2.0

    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, [p1, p2])
        result = analyze_throughput(path, top_n=5)
        assert result.success is True
        assert result.conversations_analyzed >= 1
        conv = result.conversations[0]
        # Dominant direction should be A -> B
        assert conv.src_ip == a
        assert conv.dst_ip == b
        assert conv.duration_seconds is not None
        assert 0.9 <= conv.duration_seconds <= 1.1
        assert conv.mbps_total is not None
        assert conv.bytes_total > 0
    finally:
        os.unlink(path)
