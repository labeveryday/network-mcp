"""Network tools for MCP server."""

from network_mcp.tools.capabilities import capabilities
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
from network_mcp.tools.external_intel import asn_lookup, rdap_lookup
from network_mcp.tools.local import (
    get_arp_table,
    get_connections,
    get_dns_config,
    get_interfaces,
    get_routes,
)
from network_mcp.tools.pcap import (
    analyze_dns_traffic,
    analyze_throughput,
    custom_scapy_filter,
    filter_packets,
    find_tcp_issues,
    get_conversations,
    get_protocol_hierarchy,
    pcap_summary,
)
from network_mcp.tools.planning import (
    check_overlaps,
    cidr_info,
    cidr_summarize,
    find_vlan_for_ip,
    ip_in_subnet,
    ip_in_vlan,
    plan_subnets,
    subnet_split,
    validate_vlan_map,
)

__all__ = [
    # Diagnostics
    "capabilities",
    # Planning (pure)
    "cidr_info",
    "ip_in_subnet",
    "subnet_split",
    "cidr_summarize",
    "check_overlaps",
    "validate_vlan_map",
    "ip_in_vlan",
    "find_vlan_for_ip",
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
    "analyze_throughput",
    "find_tcp_issues",
    "analyze_dns_traffic",
    "filter_packets",
    "get_protocol_hierarchy",
    "custom_scapy_filter",
]
