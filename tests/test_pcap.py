"""Tests for pcap analysis tools."""

import os
import tempfile

import pytest

from network_mcp.tools.pcap import (
    pcap_summary,
    get_conversations,
    find_tcp_issues,
    analyze_dns_traffic,
    filter_packets,
    get_protocol_hierarchy,
    custom_scapy_filter,
)


class TestPcapSummary:
    """Tests for pcap_summary tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        result = pcap_summary("/nonexistent/file.pcap")
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
        result = get_conversations("/nonexistent/file.pcap")
        assert result == []


class TestFindTcpIssues:
    """Tests for find_tcp_issues tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        result = find_tcp_issues("/nonexistent/file.pcap")
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        result = find_tcp_issues("/nonexistent/file.pcap")
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
        result = analyze_dns_traffic("/nonexistent/file.pcap")
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        result = analyze_dns_traffic("/nonexistent/file.pcap")
        assert hasattr(result, "success")
        assert hasattr(result, "total_dns_packets")
        assert hasattr(result, "total_queries")
        assert hasattr(result, "total_responses")
        assert hasattr(result, "unique_domains")


class TestFilterPackets:
    """Tests for filter_packets tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        result = filter_packets("/nonexistent/file.pcap")
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        result = filter_packets("/nonexistent/file.pcap", src_ip="10.0.0.1")
        assert hasattr(result, "success")
        assert hasattr(result, "filter_expression")
        assert hasattr(result, "total_packets_scanned")
        assert hasattr(result, "matching_packets")
        assert hasattr(result, "packets")


class TestGetProtocolHierarchy:
    """Tests for get_protocol_hierarchy tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        result = get_protocol_hierarchy("/nonexistent/file.pcap")
        assert result.success is False
        assert "not found" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        result = get_protocol_hierarchy("/nonexistent/file.pcap")
        assert hasattr(result, "success")
        assert hasattr(result, "total_packets")
        assert hasattr(result, "total_bytes")
        assert hasattr(result, "hierarchy")


class TestCustomScapyFilter:
    """Tests for custom_scapy_filter tool."""

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        result = custom_scapy_filter("/nonexistent/file.pcap", "TCP in pkt")
        assert result.success is False
        assert "not found" in result.summary.lower() or "not found" in (result.error or "").lower()

    def test_invalid_filter_blocked(self):
        """Test that dangerous filters are blocked."""
        result = custom_scapy_filter("/tmp/test.pcap", "import os")
        assert result.success is False
        assert "blocked" in result.summary.lower() or "rejected" in result.summary.lower()

    def test_result_structure(self):
        """Test that result has correct structure."""
        result = custom_scapy_filter("/nonexistent/file.pcap", "TCP in pkt")
        assert hasattr(result, "success")
        assert hasattr(result, "filter_expression")
        assert hasattr(result, "total_packets_scanned")
        assert hasattr(result, "matching_packets")
        assert hasattr(result, "packets")
        assert hasattr(result, "error")
