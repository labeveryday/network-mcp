"""Tests for MCP server."""

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
            # Planning (pure)
            "cidr_info",
            "ip_in_subnet",
            "subnet_split",
            "cidr_summarize",
            "check_overlaps",
            "validate_vlan_map",
            "find_vlan_for_ip",
            "ip_in_vlan",
            "plan_subnets",
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
            "analyze_throughput",
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
        assert len(tools) == 34, f"Expected 34 tools, got {len(tools)}: {tools}"


class TestToolImports:
    """Test that all tools can be imported."""

    def test_connectivity_imports(self):
        """Test connectivity tool imports."""

    def test_local_imports(self):
        """Test local network tool imports."""

    def test_pcap_imports(self):
        """Test pcap tool imports."""

    def test_config_imports(self):
        """Test config imports."""

    def test_model_imports(self):
        """Test model imports."""
