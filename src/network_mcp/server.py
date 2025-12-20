"""Network MCP Server - Main entry point using FastMCP.

This server exposes network diagnostic tools via the Model Context Protocol.
It can be run locally via stdio transport or deployed to AgentCore Runtime.
"""

from typing import Literal

from mcp.server import FastMCP

from network_mcp.tools.capabilities import capabilities as _capabilities
from network_mcp.tools.connectivity import (
    batch_dns_lookup as _batch_dns_lookup,
)
from network_mcp.tools.connectivity import (
    batch_ping as _batch_ping,
)
from network_mcp.tools.connectivity import (
    batch_port_check as _batch_port_check,
)
from network_mcp.tools.connectivity import (
    dns_lookup as _dns_lookup,
)
from network_mcp.tools.connectivity import (
    mtr as _mtr,
)
from network_mcp.tools.connectivity import (
    ping as _ping,
)
from network_mcp.tools.connectivity import (
    port_check as _port_check,
)
from network_mcp.tools.connectivity import (
    traceroute as _traceroute,
)
from network_mcp.tools.external_intel import asn_lookup as _asn_lookup
from network_mcp.tools.external_intel import rdap_lookup as _rdap_lookup
from network_mcp.tools.local import (
    get_arp_table as _get_arp_table,
)
from network_mcp.tools.local import (
    get_connections as _get_connections,
)
from network_mcp.tools.local import (
    get_dns_config as _get_dns_config,
)
from network_mcp.tools.local import (
    get_interfaces as _get_interfaces,
)
from network_mcp.tools.local import (
    get_public_ip as _get_public_ip,
)
from network_mcp.tools.local import (
    get_routes as _get_routes,
)
from network_mcp.tools.pcap import (
    analyze_dns_traffic as _analyze_dns_traffic,
)
from network_mcp.tools.pcap import (
    analyze_throughput as _analyze_throughput,
)
from network_mcp.tools.pcap import (
    custom_scapy_filter as _custom_scapy_filter,
)
from network_mcp.tools.pcap import (
    filter_packets as _filter_packets,
)
from network_mcp.tools.pcap import (
    find_tcp_issues as _find_tcp_issues,
)
from network_mcp.tools.pcap import (
    get_conversations as _get_conversations,
)
from network_mcp.tools.pcap import (
    get_protocol_hierarchy as _get_protocol_hierarchy,
)
from network_mcp.tools.pcap import (
    pcap_summary as _pcap_summary,
)
from network_mcp.tools.planning import (
    check_overlaps as _check_overlaps,
)
from network_mcp.tools.planning import (
    cidr_info as _cidr_info,
)
from network_mcp.tools.planning import (
    cidr_summarize as _cidr_summarize,
)
from network_mcp.tools.planning import (
    find_vlan_for_ip as _find_vlan_for_ip,
)
from network_mcp.tools.planning import (
    ip_in_subnet as _ip_in_subnet,
)
from network_mcp.tools.planning import (
    ip_in_vlan as _ip_in_vlan,
)
from network_mcp.tools.planning import (
    plan_subnets as _plan_subnets,
)
from network_mcp.tools.planning import (
    subnet_split as _subnet_split,
)
from network_mcp.tools.planning import (
    validate_vlan_map as _validate_vlan_map,
)

# Create FastMCP server
mcp = FastMCP(
    name="Network Tools",
    instructions="Network diagnostic tools for connectivity testing and pcap analysis. Use these tools to diagnose network issues, analyze packet captures, and verify connectivity.",
)


# =============================================================================
# Planning Tools (Pure CIDR/VLAN math)
# =============================================================================


@mcp.tool()
def cidr_info(cidr: str) -> dict:
    """CIDR primitives (IPv4/IPv6): mask, wildcard, usable range, counts.

    NOC use cases:
    - Validate the mask math in a change ticket
    - Quickly answer "what's the usable range for this VLAN subnet?"
    """
    result = _cidr_info(cidr)
    return result.model_dump()


@mcp.tool()
def ip_in_subnet(ip: str, cidr: str) -> dict:
    """Check if an IP is in a subnet and whether it is a usable host address.

    NOC use cases:
    - "Is this IP in this VLAN subnet?"
    - Catch network/broadcast mistakes (/24 .0 / .255) quickly
    """
    result = _ip_in_subnet(ip, cidr)
    return result.model_dump()


@mcp.tool()
def subnet_split(cidr: str, new_prefix: int | None = None, count: int | None = None) -> dict:
    """Split a CIDR into equal-size child subnets (by new_prefix or power-of-two count)."""
    result = _subnet_split(cidr, new_prefix=new_prefix, count=count)
    return result.model_dump()


@mcp.tool()
def cidr_summarize(cidrs: list[str]) -> dict:
    """Summarize/aggregate routes from a list of CIDRs (IPv4/IPv6 collapsed separately)."""
    result = _cidr_summarize(cidrs)
    return result.model_dump()


@mcp.tool()
def check_overlaps(cidrs: list[str]) -> dict:
    """Detect overlaps/containment between CIDRs (high-leverage sanity check)."""
    result = _check_overlaps(cidrs)
    return result.model_dump()


@mcp.tool()
def validate_vlan_map(vlan_map: dict) -> dict:
    """Validate a simple VLAN map (1 subnet per VLAN) and surface overlaps.

    Input formats supported:
    - Shorthand: {"10": "192.168.10.0/24"}
    - Structured: {"10": {"cidr": "192.168.10.0/24", "name": "Management"}}
    """
    result = _validate_vlan_map(vlan_map)
    return result.model_dump()


@mcp.tool()
def find_vlan_for_ip(ip: str, vlan_map: dict) -> dict:
    """Find which VLAN subnet(s) match an IP in a provided VLAN map.

    Tier 1 "hero tool":
    - "What VLAN does this IP belong to?"

    Example vlan_map:
    {"10": "192.168.10.0/24", "20": {"cidr": "192.168.20.0/24", "name": "Voice"}}
    """
    result = _find_vlan_for_ip(ip, vlan_map)
    return result.model_dump()


@mcp.tool()
def ip_in_vlan(ip: str, vlan_id: str | int, vlan_map: dict) -> dict:
    """Check if an IP belongs to a VLAN (1 subnet per VLAN) using a provided VLAN map.

    If it does NOT match, this tool will attempt a best-guess VLAN match to help Tier 1/2 triage.

    Example vlan_map:
    {"20": {"cidr": "10.10.20.0/24", "name": "Voice"}, "50": "10.10.50.0/24"}
    """
    result = _ip_in_vlan(ip, vlan_id, vlan_map)
    return result.model_dump()


@mcp.tool()
def plan_subnets(parent_cidr: str, requirements: list[dict]) -> dict:
    """Allocate VLAN subnets from a parent IPv4 block (deterministic, no network calls).

    Each requirement is 1 subnet per VLAN. Use either hosts (alias: needed_hosts) OR prefix (alias: desired_prefix).

    Example:
    parent_cidr="10.0.0.0/23"
    requirements=[
      {"vlan_id": 10, "name": "Users", "hosts": 120},
      {"vlan_id": 20, "name": "Voice", "hosts": 60},
      {"vlan_id": 30, "name": "Printers", "prefix": 26},
    ]
    """
    result = _plan_subnets(parent_cidr, requirements)
    return result.model_dump()


# =============================================================================
# Connectivity Tools
# =============================================================================


@mcp.tool()
def capabilities() -> dict:
    """Report server/runtime capabilities and dependency status.

    Use this tool first when running with local/smaller models so the agent can
    decide which tools will work (e.g., whether `mtr` is installed) and what
    security/pcap guardrails are active.
    """
    result = _capabilities()
    return result.model_dump()


@mcp.tool()
def rdap_lookup(query: str, timeout: int = 10) -> dict:
    """WHOIS-style lookup using RDAP (Registration Data Access Protocol).

    Use this to identify who owns an IP range or domain and to get registration metadata.
    """
    result = _rdap_lookup(query, timeout=timeout)
    return result.model_dump()


@mcp.tool()
def asn_lookup(ip: str, timeout: int = 5) -> dict:
    """Lookup origin ASN for an IP address (BGP origin intel).

    Use this to quickly identify the ASN and prefix associated with an external IP.
    """
    result = _asn_lookup(ip, timeout=timeout)
    return result.model_dump()


@mcp.tool()
def ping(
    target: str,
    count: int = 4,
    timeout: int = 5,
) -> dict:
    """Ping a host to check connectivity and measure latency.

    Use this tool to verify if a host is reachable and measure round-trip latency.
    Returns packet loss percentage and latency statistics (min/avg/max).

    Args:
        target: Hostname or IP address to ping (e.g., "google.com" or "8.8.8.8")
        count: Number of ICMP packets to send (default: 4)
        timeout: Timeout in seconds for each packet (default: 5)

    Returns:
        Ping results including success status, packet loss, and latency statistics
    """
    result = _ping(target, count=count, timeout=timeout)
    return result.model_dump()


@mcp.tool()
def traceroute(
    target: str,
    max_hops: int = 30,
    timeout: int = 5,
) -> dict:
    """Trace the network path to a destination, showing each hop.

    Use this tool to understand the network path between you and a target,
    identify where latency is introduced, or find where packets are being dropped.

    Args:
        target: Hostname or IP address to trace (e.g., "google.com")
        max_hops: Maximum number of hops to trace (default: 30)
        timeout: Timeout in seconds for each probe (default: 5)

    Returns:
        Path analysis with hop-by-hop details including IP, hostname, and latency
    """
    result = _traceroute(target, max_hops=max_hops, timeout=timeout)
    return result.model_dump()


@mcp.tool()
def dns_lookup(
    query: str,
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "ANY"] = "A",
    nameserver: str | None = None,
) -> dict:
    """Perform DNS lookup for a hostname or reverse lookup for an IP.

    Use this tool to resolve hostnames to IP addresses, find mail servers (MX),
    or perform reverse DNS lookups.

    Args:
        query: Hostname to lookup (e.g., "google.com") or IP for reverse lookup
        record_type: DNS record type - A, AAAA, CNAME, MX, TXT, NS, SOA, PTR (default: A)
        nameserver: Optional specific nameserver to query (e.g., "8.8.8.8")

    Returns:
        DNS records found with TTL and response time
    """
    result = _dns_lookup(query, record_type=record_type, nameserver=nameserver)
    return result.model_dump()


@mcp.tool()
def port_check(
    target: str,
    port: int,
    timeout: float = 5.0,
    grab_banner: bool = True,
) -> dict:
    """Check if a TCP port is open and optionally grab service banner.

    Use this tool to verify if a service is listening on a port, check firewall rules,
    or identify what service is running on a port.

    Args:
        target: Hostname or IP address to check
        port: TCP port number to check (1-65535)
        timeout: Connection timeout in seconds (default: 5)
        grab_banner: Whether to attempt to grab service banner (default: True)

    Returns:
        Port status (open/closed), response time, and optional service banner
    """
    result = _port_check(target, port=port, timeout=timeout, grab_banner=grab_banner)
    return result.model_dump()


@mcp.tool()
def mtr(
    target: str,
    count: int = 10,
    timeout: int = 5,
) -> dict:
    """Run MTR (My Traceroute) for detailed path analysis with statistics.

    MTR combines traceroute and ping to provide per-hop packet loss and latency
    statistics over multiple probes. Better than traceroute for diagnosing
    intermittent issues.

    Note: Requires MTR to be installed on the system.

    Args:
        target: Hostname or IP address to analyze
        count: Number of pings to send to each hop (default: 10)
        timeout: Timeout in seconds (default: 5)

    Returns:
        Per-hop statistics including packet loss percentage and latency
    """
    result = _mtr(target, count=count, timeout=timeout)
    return result.model_dump()


# =============================================================================
# Batch Connectivity Tools
# =============================================================================


@mcp.tool()
def batch_ping(
    targets: list[str],
    count: int = 4,
    timeout: int = 5,
    max_concurrent: int = 10,
) -> dict:
    """Ping multiple hosts concurrently for efficient connectivity testing.

    Use this tool when you need to check connectivity to multiple hosts at once.
    Results include per-target status and an overall summary. Targets are
    validated against the configured allowlist/blocklist.

    Args:
        targets: List of hostnames or IP addresses to ping
        count: Number of ICMP packets per target (default: 4)
        timeout: Timeout in seconds per packet (default: 5)
        max_concurrent: Maximum concurrent pings (default: 10)

    Returns:
        Batch results with per-target status, success/fail counts, and summary
    """
    result = _batch_ping(targets, count=count, timeout=timeout, max_concurrent=max_concurrent)
    return result.model_dump()


@mcp.tool()
def batch_port_check(
    target: str,
    ports: list[int],
    timeout: float = 2.0,
    max_concurrent: int = 20,
) -> dict:
    """Check multiple TCP ports on a single host concurrently.

    Use this tool to quickly scan multiple ports on a host, such as checking
    which common services are running. Returns open/closed status for each port.

    Args:
        target: Hostname or IP address to check
        ports: List of TCP port numbers to check (e.g., [22, 80, 443, 3306])
        timeout: Connection timeout per port in seconds (default: 2)
        max_concurrent: Maximum concurrent checks (default: 20)

    Returns:
        Batch results with per-port status, open/closed counts, and summary
    """
    result = _batch_port_check(target, ports=ports, timeout=timeout, max_concurrent=max_concurrent)
    return result.model_dump()


@mcp.tool()
def batch_dns_lookup(
    queries: list[str],
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS"] = "A",
) -> dict:
    """Perform DNS lookups for multiple hostnames at once.

    Use this tool when you need to resolve multiple hostnames or check DNS
    records for several domains efficiently.

    Args:
        queries: List of hostnames to lookup
        record_type: DNS record type for all queries (default: A)

    Returns:
        Batch results with per-query records, success/fail counts, and summary
    """
    result = _batch_dns_lookup(queries, record_type=record_type)
    return result.model_dump()


# =============================================================================
# Local Network Info Tools
# =============================================================================


@mcp.tool()
def get_interfaces() -> dict:
    """Get network interface information.

    Use this tool to list all network interfaces on the local system with their
    IP addresses, MAC addresses, and status. Works on Linux, macOS, and Windows.

    Returns:
        Interface list with IPs, MACs, status, and the default interface
    """
    result = _get_interfaces()
    return result.model_dump()


@mcp.tool()
def get_routes() -> dict:
    """Get the routing table.

    Use this tool to view the system's routing table including default gateway,
    destination networks, and associated interfaces. Works on Linux, macOS, and Windows.

    Returns:
        Routing table with destinations, gateways, interfaces, and default gateway
    """
    result = _get_routes()
    return result.model_dump()


@mcp.tool()
def get_dns_config() -> dict:
    """Get DNS configuration.

    Use this tool to view the configured DNS nameservers and search domains.
    Works on Linux, macOS, and Windows.

    Returns:
        DNS configuration with nameservers and search domains
    """
    result = _get_dns_config()
    return result.model_dump()


@mcp.tool()
def get_arp_table() -> dict:
    """Get the ARP table.

    Use this tool to view the ARP cache showing IP to MAC address mappings
    for hosts on the local network. Works on Linux, macOS, and Windows.

    Returns:
        ARP entries with IP addresses, MAC addresses, and states
    """
    result = _get_arp_table()
    return result.model_dump()


@mcp.tool()
def get_connections(
    protocol: str | None = None,
    state: str | None = None,
) -> dict:
    """Get active network connections.

    Use this tool to view active TCP/UDP connections including listening ports
    and established connections. Works on Linux, macOS, and Windows.

    Args:
        protocol: Filter by protocol (tcp, udp, or None for all)
        state: Filter by state (e.g., ESTABLISHED, LISTEN, or None for all)

    Returns:
        Connection list with local/remote addresses, states, and process info
    """
    result = _get_connections(protocol=protocol, state=state)
    return result.model_dump()


@mcp.tool()
def get_public_ip(timeout: int = 10) -> dict:
    """Get the public/external IP address.

    Use this tool to determine the public IP address as seen from the internet.
    This is useful for understanding NAT configuration or verifying external
    connectivity. Tries multiple services for reliability.

    Args:
        timeout: Timeout in seconds for each service request (default: 10)

    Returns:
        Public IP address and the service used to determine it
    """
    result = _get_public_ip(timeout=timeout)
    return result.model_dump()


# =============================================================================
# Pcap Analysis Tools
# =============================================================================


@mcp.tool()
def pcap_summary(
    file_path: str,
    max_packets: int = 100000,
) -> dict:
    """Get a high-level summary of a packet capture file.

    Use this tool to quickly understand what's in a pcap file without reading
    every packet. Returns protocol breakdown, top talkers, and basic statistics.

    Args:
        file_path: Path to the pcap or pcapng file
        max_packets: Maximum packets to analyze (default: 100000)

    Returns:
        Capture summary including packet count, duration, protocols, and top talkers
    """
    result = _pcap_summary(file_path, max_packets=max_packets)
    return result.model_dump()


@mcp.tool()
def get_conversations(
    file_path: str,
    max_packets: int = 100000,
    top_n: int = 20,
) -> list[dict]:
    """Extract network conversations/flows from a pcap file.

    Use this tool to see which hosts are communicating and how much data
    they're exchanging. Useful for identifying top bandwidth consumers.

    Args:
        file_path: Path to the pcap or pcapng file
        max_packets: Maximum packets to analyze (default: 100000)
        top_n: Return top N conversations by packet count (default: 20)

    Returns:
        List of conversations with source/dest, protocol, packets, and bytes
    """
    result = _get_conversations(file_path, max_packets=max_packets, top_n=top_n)
    return [c.model_dump() for c in result]


@mcp.tool()
def find_tcp_issues(
    file_path: str,
    max_packets: int = 100000,
) -> dict:
    """Analyze TCP packets for issues like retransmissions and resets.

    Use this tool to diagnose network problems. Detects:
    - Retransmissions (indicating packet loss)
    - TCP resets (connection problems)
    - Zero window (buffer exhaustion)
    - Duplicate ACKs (packet loss signals)

    Args:
        file_path: Path to the pcap or pcapng file
        max_packets: Maximum packets to analyze (default: 100000)

    Returns:
        TCP issues categorized by type with severity and recommendations
    """
    result = _find_tcp_issues(file_path, max_packets=max_packets)
    return result.model_dump()


@mcp.tool()
def analyze_dns_traffic(
    file_path: str,
    max_packets: int = 100000,
) -> dict:
    """Analyze DNS queries and responses in a packet capture.

    Use this tool to understand DNS activity including:
    - Most queried domains
    - Failed queries (NXDOMAIN, SERVFAIL)
    - Slow DNS responses (>100ms)

    Args:
        file_path: Path to the pcap or pcapng file
        max_packets: Maximum packets to analyze (default: 100000)

    Returns:
        DNS traffic analysis with top domains, failures, and slow queries
    """
    result = _analyze_dns_traffic(file_path, max_packets=max_packets)
    return result.model_dump()


@mcp.tool()
def filter_packets(
    file_path: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
    max_packets: int = 100000,
    max_results: int = 100,
) -> dict:
    """Filter packets from a pcap file based on criteria.

    Use this tool to extract specific packets matching your criteria.
    Multiple filters can be combined (AND logic).

    Args:
        file_path: Path to the pcap or pcapng file
        src_ip: Filter by source IP address
        dst_ip: Filter by destination IP address
        protocol: Filter by protocol (TCP, UDP, ICMP, DNS)
        port: Filter by port number (source or destination)
        max_packets: Maximum packets to scan (default: 100000)
        max_results: Maximum matching packets to return (default: 100)

    Returns:
        Matching packets with details (number, timestamp, IPs, protocol, info)
    """
    result = _filter_packets(
        file_path,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        port=port,
        max_packets=max_packets,
        max_results=max_results,
    )
    return result.model_dump()


@mcp.tool()
def get_protocol_hierarchy(
    file_path: str,
    max_packets: int = 100000,
) -> dict:
    """Analyze protocol distribution in a packet capture.

    Use this tool to see the breakdown of protocols by packet count and bytes.
    Similar to Wireshark's protocol hierarchy view.

    Args:
        file_path: Path to the pcap or pcapng file
        max_packets: Maximum packets to analyze (default: 100000)

    Returns:
        Protocol hierarchy with packet counts, bytes, and percentages
    """
    result = _get_protocol_hierarchy(file_path, max_packets=max_packets)
    return result.model_dump()


@mcp.tool()
def analyze_throughput(
    file_path: str,
    max_packets: int = 100000,
    top_n: int = 20,
    sort_by: Literal["mbps_total", "bytes_total"] = "mbps_total",
) -> dict:
    """Calculate observed throughput per conversation (Mbps) from a pcap file.

    This reports achieved throughput in the capture (not theoretical bandwidth).
    """
    result = _analyze_throughput(file_path, max_packets=max_packets, top_n=top_n, sort_by=sort_by)
    return result.model_dump()


@mcp.tool()
def custom_scapy_filter(
    file_path: str,
    filter_expression: str,
    max_packets: int = 100000,
    max_results: int = 100,
) -> dict:
    """Execute a custom scapy filter expression on a pcap file.

    Use this tool for advanced packet filtering using scapy's syntax.
    The filter is validated for safety before execution.

    Supported filter syntax examples:
    - "TCP in pkt and pkt[TCP].dport == 80" - HTTP traffic
    - "UDP in pkt and DNS in pkt" - DNS traffic
    - "pkt[IP].ttl < 64" - Packets with low TTL
    - "len(pkt) > 1000" - Large packets

    Args:
        file_path: Path to the pcap or pcapng file
        filter_expression: Scapy-style filter expression
        max_packets: Maximum packets to scan (default: 100000)
        max_results: Maximum matching packets to return (default: 100)

    Returns:
        Matching packets with details and filter summary
    """
    result = _custom_scapy_filter(
        file_path,
        filter_expression=filter_expression,
        max_packets=max_packets,
        max_results=max_results,
    )
    return result.model_dump()


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
