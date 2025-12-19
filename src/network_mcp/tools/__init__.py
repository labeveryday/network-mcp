"""Network tools for MCP server."""

from network_mcp.tools.connectivity import (
    batch_dns_lookup,
    batch_ping,
    batch_port_check,
    dns_lookup,
    mtr,
    ping,
    port_check,
    traceroute,
)
from network_mcp.tools.local import (
    get_arp_table,
    get_connections,
    get_dns_config,
    get_interfaces,
    get_routes,
)
from network_mcp.tools.pcap import (
    analyze_dns_traffic,
    custom_scapy_filter,
    filter_packets,
    find_tcp_issues,
    get_conversations,
    get_protocol_hierarchy,
    pcap_summary,
)

__all__ = [
    # Connectivity tools
    "ping",
    "traceroute",
    "dns_lookup",
    "port_check",
    "mtr",
    # Batch connectivity tools
    "batch_ping",
    "batch_port_check",
    "batch_dns_lookup",
    # Local network info tools
    "get_interfaces",
    "get_routes",
    "get_dns_config",
    "get_arp_table",
    "get_connections",
    # Pcap tools
    "pcap_summary",
    "get_conversations",
    "find_tcp_issues",
    "analyze_dns_traffic",
    "filter_packets",
    "get_protocol_hierarchy",
    "custom_scapy_filter",
]
