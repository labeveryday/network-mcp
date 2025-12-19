"""Tests for pcap analysis tools."""

import os
import tempfile

from scapy.all import IP, TCP, Raw, wrpcap

from network_mcp.tools.pcap import (
    analyze_dns_traffic,
    custom_scapy_filter,
    filter_packets,
    find_tcp_issues,
    get_conversations,
    get_protocol_hierarchy,
    pcap_summary,
)


class TestPcapSummary:
    """Tests for pcap_summary tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = pcap_summary(missing)
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_empty_file(self):
        """Test handling of empty file."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"")
            temp_path = f.name
        try:
            result = pcap_summary(temp_path)
            # Should fail to parse as valid pcap
            assert result.success is False
        finally:
            os.unlink(temp_path)


class TestGetConversations:
    """Tests for get_conversations tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = get_conversations(missing)
        assert result == []


class TestFindTcpIssues:
    """Tests for find_tcp_issues tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = find_tcp_issues(missing)
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = find_tcp_issues(missing)
        assert hasattr(result, "success")
        assert hasattr(result, "file_path")
        assert hasattr(result, "total_tcp_packets")
        assert hasattr(result, "issues")
        assert hasattr(result, "has_issues")
        assert hasattr(result, "summary")


class TestAnalyzeDnsTraffic:
    """Tests for analyze_dns_traffic tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = analyze_dns_traffic(missing)
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = analyze_dns_traffic(missing)
        assert hasattr(result, "success")
        assert hasattr(result, "total_dns_packets")
        assert hasattr(result, "total_queries")
        assert hasattr(result, "total_responses")
        assert hasattr(result, "unique_domains")


class TestFilterPackets:
    """Tests for filter_packets tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = filter_packets(missing)
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = filter_packets(missing, src_ip="10.0.0.1")
        assert hasattr(result, "success")
        assert hasattr(result, "filter_expression")
        assert hasattr(result, "total_packets_scanned")
        assert hasattr(result, "matching_packets")
        assert hasattr(result, "packets")


class TestGetProtocolHierarchy:
    """Tests for get_protocol_hierarchy tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = get_protocol_hierarchy(missing)
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = get_protocol_hierarchy(missing)
        assert hasattr(result, "success")
        assert hasattr(result, "total_packets")
        assert hasattr(result, "total_bytes")
        assert hasattr(result, "hierarchy")


class TestCustomScapyFilter:
    """Tests for custom_scapy_filter tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = custom_scapy_filter(missing, "TCP in pkt")
        assert result.success is False
        assert "not found" in result.summary.lower() or "not found" in (result.error or "").lower()

    def test_invalid_filter_blocked(self):
        """Test that dangerous filters are blocked."""
        allowed_missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = custom_scapy_filter(allowed_missing, "import os")
        assert result.success is False
        assert "blocked" in result.summary.lower() or "rejected" in result.summary.lower()

    def test_bitwise_filter_supported(self):
        """Bitwise operations (e.g., TCP flags) should be supported."""
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            # SYN packet (flags has 0x02 bit)
            p = (
                IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=12345, dport=80, flags="S")
                / Raw(load=b"x")
            )
            p.time = 1.0
            wrpcap(path, [p])

            result = custom_scapy_filter(path, "pkt[TCP].flags & 0x02")
            assert result.success is True
            assert result.matching_packets >= 1
        finally:
            os.unlink(path)

    def test_result_structure(self):
        """Test that result has correct structure."""
        missing = os.path.join(tempfile.gettempdir(), "network-mcp-does-not-exist.pcap")
        result = custom_scapy_filter(missing, "TCP in pkt")
        assert hasattr(result, "success")
        assert hasattr(result, "filter_expression")
        assert hasattr(result, "total_packets_scanned")
        assert hasattr(result, "matching_packets")
        assert hasattr(result, "packets")
        assert hasattr(result, "error")
