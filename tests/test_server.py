"""Tests for MCP server."""

import pytest

from network_mcp.server import mcp


class TestServerSetup:
    """Tests for server setup and tool registration."""

    def test_server_name(self):
        """Test server has correct name."""
        assert mcp.name == "Network Tools"

    def test_all_tools_registered(self):
        """Test all expected tools are registered."""
        tools = list(mcp._tool_manager._tools.keys())

        expected_tools = [
            # Diagnostics
            "capabilities",
            # External intel
            "rdap_lookup",
            "asn_lookup",
            # Connectivity tools
            "ping",
            "traceroute",
            "dns_lookup",
            "port_check",
            "mtr",
            # Batch tools
            "batch_ping",
            "batch_port_check",
            "batch_dns_lookup",
            # Local network info tools
            "get_interfaces",
            "get_routes",
            "get_dns_config",
            "get_arp_table",
            "get_connections",
            "get_public_ip",
            # Pcap tools
            "pcap_summary",
            "get_conversations",
            "find_tcp_issues",
            "analyze_dns_traffic",
            "filter_packets",
            "get_protocol_hierarchy",
            "custom_scapy_filter",
        ]

        for tool in expected_tools:
            assert tool in tools, f"Tool '{tool}' not registered"

    def test_tool_count(self):
        """Test expected number of tools."""
        tools = list(mcp._tool_manager._tools.keys())
        assert len(tools) == 24, f"Expected 24 tools, got {len(tools)}: {tools}"


class TestToolImports:
    """Test that all tools can be imported."""

    def test_connectivity_imports(self):
        """Test connectivity tool imports."""
        from network_mcp.tools.connectivity import (
            ping,
            traceroute,
            dns_lookup,
            port_check,
            mtr,
            batch_ping,
            batch_port_check,
            batch_dns_lookup,
        )

    def test_local_imports(self):
        """Test local network tool imports."""
        from network_mcp.tools.local import (
            get_interfaces,
            get_routes,
            get_dns_config,
            get_arp_table,
            get_connections,
            get_public_ip,
        )

    def test_pcap_imports(self):
        """Test pcap tool imports."""
        from network_mcp.tools.pcap import (
            pcap_summary,
            get_conversations,
            find_tcp_issues,
            analyze_dns_traffic,
            filter_packets,
            get_protocol_hierarchy,
            custom_scapy_filter,
        )

    def test_config_imports(self):
        """Test config imports."""
        from network_mcp.config import (
            Config,
            SecurityConfig,
            PcapConfig,
            get_config,
            load_config,
            validate_target,
            validate_scapy_filter,
        )

    def test_model_imports(self):
        """Test model imports."""
        from network_mcp.models.responses import (
            CapabilitiesResult,
            PingResult,
            TracerouteResult,
            DnsLookupResult,
            PortCheckResult,
            MtrResult,
            PcapSummaryResult,
            TcpIssuesResult,
            DnsAnalysisResult,
            FilterPacketsResult,
            ProtocolHierarchyResult,
            CustomFilterResult,
            BatchPingResult,
            BatchPortCheckResult,
            BatchDnsResult,
            PublicIpResult,
        )
