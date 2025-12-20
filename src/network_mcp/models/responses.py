"""Pydantic models for structured MCP tool responses.

All models include a 'summary' field with human-readable text for LLM consumption,
plus structured data for programmatic use.
"""

from pydantic import AliasChoices, BaseModel, Field, model_validator

# =============================================================================
# Common Models
# =============================================================================


class ErrorResponse(BaseModel):
    """Structured error response."""

    success: bool = False
    error_type: str = Field(
        description="Type of error (e.g., 'timeout', 'unreachable', 'invalid_input')"
    )
    message: str = Field(description="Human-readable error message")
    suggestion: str | None = Field(
        default=None, description="Suggested action to resolve the error"
    )


# =============================================================================
# Connectivity Tool Models
# =============================================================================


class PingResult(BaseModel):
    """Result from ping tool."""

    success: bool = Field(description="Whether ping was successful (at least one reply received)")
    target: str = Field(description="Target hostname or IP address")
    resolved_ip: str | None = Field(
        default=None, description="Resolved IP address if target was hostname"
    )
    packets_sent: int = Field(description="Number of ICMP packets sent")
    packets_received: int = Field(description="Number of ICMP replies received")
    packet_loss_percent: float = Field(description="Percentage of packets lost (0-100)")
    min_latency_ms: float | None = Field(
        default=None, description="Minimum round-trip time in milliseconds"
    )
    avg_latency_ms: float | None = Field(
        default=None, description="Average round-trip time in milliseconds"
    )
    max_latency_ms: float | None = Field(
        default=None, description="Maximum round-trip time in milliseconds"
    )
    stddev_latency_ms: float | None = Field(
        default=None, description="Standard deviation of RTT in milliseconds"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class TracerouteHop(BaseModel):
    """A single hop in a traceroute."""

    hop_number: int = Field(description="Hop number (1-based)")
    ip_address: str | None = Field(
        default=None, description="IP address of the hop (None if timeout)"
    )
    hostname: str | None = Field(default=None, description="Reverse DNS hostname if available")
    latency_ms: list[float] = Field(
        default_factory=list, description="RTT measurements for this hop"
    )
    avg_latency_ms: float | None = Field(default=None, description="Average latency for this hop")
    packet_loss: bool = Field(default=False, description="Whether any probes timed out at this hop")
    is_destination: bool = Field(
        default=False, description="Whether this hop is the final destination"
    )


class TracerouteResult(BaseModel):
    """Result from traceroute tool."""

    success: bool = Field(description="Whether traceroute completed successfully")
    target: str = Field(description="Target hostname or IP address")
    resolved_ip: str | None = Field(
        default=None, description="Resolved IP address if target was hostname"
    )
    hops: list[TracerouteHop] = Field(
        default_factory=list, description="List of hops along the path"
    )
    reached_destination: bool = Field(description="Whether the final destination was reached")
    total_hops: int = Field(description="Total number of hops to destination or max hops reached")
    issues_detected: list[str] = Field(
        default_factory=list, description="Any issues detected (high latency hops, packet loss)"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class DnsRecord(BaseModel):
    """A DNS record."""

    record_type: str = Field(description="DNS record type (A, AAAA, CNAME, MX, TXT, etc.)")
    value: str = Field(description="Record value")
    ttl: int | None = Field(default=None, description="Time to live in seconds")
    priority: int | None = Field(default=None, description="Priority for MX records")


class DnsLookupResult(BaseModel):
    """Result from DNS lookup tool."""

    success: bool = Field(description="Whether DNS lookup was successful")
    query: str = Field(description="The queried hostname or IP")
    query_type: str = Field(description="Type of query performed (forward or reverse)")
    records: list[DnsRecord] = Field(default_factory=list, description="DNS records found")
    response_time_ms: float | None = Field(
        default=None, description="DNS response time in milliseconds"
    )
    nameserver: str | None = Field(default=None, description="Nameserver used for query")
    summary: str = Field(description="Human-readable summary for the LLM")


class PortCheckResult(BaseModel):
    """Result from port check tool."""

    success: bool = Field(description="Whether the port check completed (not whether port is open)")
    target: str = Field(description="Target hostname or IP address")
    port: int = Field(description="Port number checked")
    is_open: bool = Field(description="Whether the port is open and accepting connections")
    response_time_ms: float | None = Field(
        default=None, description="Connection time in milliseconds"
    )
    banner: str | None = Field(default=None, description="Service banner if available")
    service_hint: str | None = Field(
        default=None, description="Guessed service based on port/banner"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class MtrHop(BaseModel):
    """A single hop in an MTR report."""

    hop_number: int = Field(description="Hop number (1-based)")
    ip_address: str | None = Field(default=None, description="IP address of the hop")
    hostname: str | None = Field(default=None, description="Reverse DNS hostname if available")
    loss_percent: float = Field(description="Packet loss percentage at this hop")
    sent: int = Field(description="Number of packets sent")
    received: int = Field(description="Number of packets received")
    best_ms: float | None = Field(default=None, description="Best (minimum) latency")
    avg_ms: float | None = Field(default=None, description="Average latency")
    worst_ms: float | None = Field(default=None, description="Worst (maximum) latency")
    stddev_ms: float | None = Field(default=None, description="Standard deviation of latency")


class MtrResult(BaseModel):
    """Result from MTR tool."""

    success: bool = Field(description="Whether MTR completed successfully")
    target: str = Field(description="Target hostname or IP address")
    resolved_ip: str | None = Field(
        default=None, description="Resolved IP address if target was hostname"
    )
    hops: list[MtrHop] = Field(default_factory=list, description="List of hops with statistics")
    report_cycles: int = Field(description="Number of report cycles (pings per hop)")
    reached_destination: bool = Field(description="Whether the final destination was reached")
    issues_detected: list[str] = Field(
        default_factory=list, description="Issues detected (high loss, latency spikes)"
    )
    summary: str = Field(description="Human-readable summary for the LLM")
    # Optional structured error metadata for automation (e.g., missing dependency, blocked by policy)
    error_type: str | None = Field(default=None, description="Machine-readable error type")
    suggestion: str | None = Field(
        default=None, description="Suggested action to resolve the error"
    )
    fallback: dict | None = Field(
        default=None,
        description="Optional fallback payload (e.g., traceroute/ping results) when MTR isn't available",
    )


# =============================================================================
# Capabilities / Diagnostics Models
# =============================================================================


class DependencyStatus(BaseModel):
    """Represents whether a given system dependency is available."""

    name: str = Field(description="Dependency name (e.g., 'mtr')")
    available: bool = Field(description="Whether dependency is available")
    path: str | None = Field(default=None, description="Resolved path to executable if available")
    note: str | None = Field(default=None, description="Optional note about usage/installation")


class CapabilitiesResult(BaseModel):
    """High-level runtime capabilities so agents can plan tool usage."""

    success: bool = Field(description="Whether capability detection completed successfully")
    server_version: str = Field(description="network-mcp version")
    platform: str = Field(description="Platform identifier (e.g., darwin/linux/windows)")
    python_version: str = Field(description="Python runtime version")
    dependencies: list[DependencyStatus] = Field(
        default_factory=list, description="Dependency statuses"
    )
    security: dict = Field(default_factory=dict, description="Active security policy summary")
    pcap: dict = Field(default_factory=dict, description="Active pcap policy summary")
    summary: str = Field(description="Human-readable summary for the LLM")


class RdapLookupResult(BaseModel):
    """Result from RDAP lookup (WHOIS-like)."""

    success: bool = Field(description="Whether lookup completed successfully")
    query: str = Field(description="Domain or IP queried")
    query_type: str = Field(description="ip or domain")
    rdap_url: str | None = Field(default=None, description="RDAP URL used")
    handle: str | None = Field(default=None, description="RDAP handle")
    name: str | None = Field(default=None, description="Name/description of the object")
    country: str | None = Field(default=None, description="Country code if available")
    start_address: str | None = Field(default=None, description="For IP queries: start of range")
    end_address: str | None = Field(default=None, description="For IP queries: end of range")
    asn_hint: str | None = Field(default=None, description="Optional ASN hint if present in RDAP")
    summary: str = Field(description="Human-readable summary for the LLM")
    error_type: str | None = Field(default=None, description="Machine-readable error type")
    suggestion: str | None = Field(
        default=None, description="Suggested action to resolve the error"
    )


class AsnLookupResult(BaseModel):
    """Result from ASN lookup for an IP."""

    success: bool = Field(description="Whether lookup completed successfully")
    ip: str = Field(description="IP address queried")
    asn: str | None = Field(default=None, description="Origin ASN")
    prefix: str | None = Field(default=None, description="Origin prefix")
    country: str | None = Field(default=None, description="Country code")
    registry: str | None = Field(default=None, description="Registry (e.g., arin, ripencc)")
    allocated: str | None = Field(default=None, description="Allocation date if available")
    as_name: str | None = Field(default=None, description="ASN name/description")
    summary: str = Field(description="Human-readable summary for the LLM")
    error_type: str | None = Field(default=None, description="Machine-readable error type")
    suggestion: str | None = Field(
        default=None, description="Suggested action to resolve the error"
    )


# =============================================================================
# Pcap Analysis Models
# =============================================================================


class Conversation(BaseModel):
    """A network conversation/flow between two endpoints."""

    src_ip: str = Field(description="Source IP address")
    src_port: int | None = Field(default=None, description="Source port (if applicable)")
    dst_ip: str = Field(description="Destination IP address")
    dst_port: int | None = Field(default=None, description="Destination port (if applicable)")
    protocol: str = Field(description="Protocol (TCP, UDP, ICMP, etc.)")
    packets: int = Field(description="Number of packets in this conversation")
    bytes: int = Field(description="Total bytes transferred")
    start_time: float | None = Field(default=None, description="Start timestamp of conversation")
    duration_seconds: float | None = Field(
        default=None, description="Duration of conversation in seconds"
    )


class ThroughputConversation(BaseModel):
    """Conversation augmented with observed throughput (Mbps) and directionality."""

    # Dominant direction endpoints (where most bytes were observed)
    src_ip: str = Field(description="Dominant-direction source IP address")
    src_port: int | None = Field(default=None, description="Dominant-direction source port")
    dst_ip: str = Field(description="Dominant-direction destination IP address")
    dst_port: int | None = Field(default=None, description="Dominant-direction destination port")
    protocol: str = Field(description="Protocol (TCP, UDP, ICMP, etc.)")

    packets_total: int = Field(description="Total packets in both directions")
    bytes_total: int = Field(description="Total bytes in both directions")

    duration_seconds: float | None = Field(
        default=None, description="Conversation duration in seconds"
    )
    start_time: float | None = Field(default=None, description="Start timestamp")
    end_time: float | None = Field(default=None, description="End timestamp")

    # Per-direction counters relative to the dominant direction
    packets_forward: int = Field(description="Packets in dominant direction (src -> dst)")
    bytes_forward: int = Field(description="Bytes in dominant direction (src -> dst)")
    packets_reverse: int = Field(description="Packets in reverse direction (dst -> src)")
    bytes_reverse: int = Field(description="Bytes in reverse direction (dst -> src)")

    mbps_forward: float | None = Field(default=None, description="Observed Mbps (src -> dst)")
    mbps_reverse: float | None = Field(default=None, description="Observed Mbps (dst -> src)")
    mbps_total: float | None = Field(
        default=None, description="Observed total Mbps (both directions)"
    )

    direction: str = Field(description="Dominant direction label, e.g. 'src:port -> dst:port'")


class AnalyzeThroughputResult(BaseModel):
    """Result from analyze_throughput tool."""

    success: bool = Field(description="Whether analysis completed successfully")
    file_path: str = Field(description="Path to the analyzed pcap file")
    total_packets_scanned: int = Field(description="Total packets scanned")
    conversations_analyzed: int = Field(description="Number of conversations analyzed")
    top_n: int = Field(description="Number of conversations returned")
    sort_by: str = Field(description="Sort key used (mbps_total or bytes_total)")
    conversations: list[ThroughputConversation] = Field(
        default_factory=list, description="Top conversations"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class TcpIssue(BaseModel):
    """A TCP issue detected in packet capture."""

    issue_type: str = Field(
        description="Type of issue (retransmission, reset, zero_window, out_of_order, dup_ack)"
    )
    count: int = Field(description="Number of occurrences")
    affected_flows: list[str] = Field(
        default_factory=list, description="Flows affected (src:port -> dst:port)"
    )
    severity: str = Field(description="Severity level (low, medium, high)")
    recommendation: str = Field(description="Recommendation to address the issue")


class PcapSummaryResult(BaseModel):
    """Summary result from pcap analysis."""

    success: bool = Field(description="Whether pcap was successfully parsed")
    file_path: str = Field(description="Path to the analyzed pcap file")
    packet_count: int = Field(description="Total number of packets")
    capture_duration_seconds: float | None = Field(default=None, description="Duration of capture")
    start_time: str | None = Field(default=None, description="Capture start time")
    end_time: str | None = Field(default=None, description="Capture end time")
    file_size_bytes: int | None = Field(default=None, description="Size of pcap file")
    protocols: dict[str, int] = Field(
        default_factory=dict, description="Protocol breakdown (protocol -> packet count)"
    )
    top_talkers: list[dict] = Field(
        default_factory=list, description="Top source IPs by packet count"
    )
    top_destinations: list[dict] = Field(
        default_factory=list, description="Top destination IPs by packet count"
    )
    unique_src_ips: int = Field(default=0, description="Number of unique source IPs")
    unique_dst_ips: int = Field(default=0, description="Number of unique destination IPs")
    tcp_issues_summary: dict[str, int] | None = Field(
        default=None, description="Summary of TCP issues if present"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class TcpIssuesResult(BaseModel):
    """Result from TCP issues analysis."""

    success: bool = Field(description="Whether analysis completed successfully")
    file_path: str = Field(description="Path to the analyzed pcap file")
    total_tcp_packets: int = Field(description="Total TCP packets analyzed")
    issues: list[TcpIssue] = Field(default_factory=list, description="List of issues detected")
    has_issues: bool = Field(description="Whether any issues were detected")
    summary: str = Field(description="Human-readable summary for the LLM")


class DnsQuery(BaseModel):
    """A DNS query from the capture."""

    query_name: str = Field(description="Queried domain name")
    query_type: str = Field(description="Query type (A, AAAA, MX, etc.)")
    response_code: str | None = Field(default=None, description="Response code if response found")
    response_ips: list[str] = Field(default_factory=list, description="Response IP addresses")
    response_time_ms: float | None = Field(
        default=None, description="Response time in milliseconds"
    )
    client_ip: str | None = Field(default=None, description="Client that made the query")


class DnsAnalysisResult(BaseModel):
    """Result from DNS traffic analysis."""

    success: bool = Field(description="Whether analysis completed successfully")
    file_path: str = Field(description="Path to the analyzed pcap file")
    total_dns_packets: int = Field(description="Total DNS packets found")
    total_queries: int = Field(description="Number of DNS queries")
    total_responses: int = Field(description="Number of DNS responses")
    unique_domains: int = Field(description="Number of unique domains queried")
    top_queried_domains: list[dict] = Field(
        default_factory=list, description="Most frequently queried domains"
    )
    failed_queries: list[dict] = Field(
        default_factory=list, description="Queries that failed (NXDOMAIN, etc.)"
    )
    slow_queries: list[dict] = Field(default_factory=list, description="Queries with high latency")
    summary: str = Field(description="Human-readable summary for the LLM")


class FilteredPacket(BaseModel):
    """A packet matching filter criteria."""

    packet_number: int = Field(description="Packet number in the capture")
    timestamp: float = Field(description="Packet timestamp")
    src_ip: str | None = Field(default=None, description="Source IP")
    dst_ip: str | None = Field(default=None, description="Destination IP")
    protocol: str = Field(description="Protocol")
    length: int = Field(description="Packet length")
    info: str = Field(description="Brief packet info/summary")


class FilterPacketsResult(BaseModel):
    """Result from packet filtering."""

    success: bool = Field(description="Whether filtering completed successfully")
    file_path: str = Field(description="Path to the analyzed pcap file")
    filter_expression: str = Field(description="Filter expression used")
    total_packets_scanned: int = Field(description="Total packets scanned")
    matching_packets: int = Field(description="Number of packets matching filter")
    packets: list[FilteredPacket] = Field(
        default_factory=list, description="Matching packets (limited)"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class ProtocolHierarchyResult(BaseModel):
    """Result from protocol hierarchy analysis."""

    success: bool = Field(description="Whether analysis completed successfully")
    file_path: str = Field(description="Path to the analyzed pcap file")
    total_packets: int = Field(description="Total packets analyzed")
    total_bytes: int = Field(description="Total bytes in capture")
    hierarchy: dict = Field(description="Protocol hierarchy tree with counts and percentages")
    top_protocols: list[dict] = Field(
        default_factory=list, description="Top protocols by packet count"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class CustomFilterResult(BaseModel):
    """Result from custom scapy filter execution."""

    success: bool = Field(description="Whether filter execution completed successfully")
    file_path: str = Field(description="Path to the analyzed pcap file")
    filter_expression: str = Field(description="The scapy filter expression used")
    total_packets_scanned: int = Field(description="Total packets scanned")
    matching_packets: int = Field(description="Number of packets matching filter")
    packets: list[FilteredPacket] = Field(
        default_factory=list, description="Matching packets (limited)"
    )
    error: str | None = Field(default=None, description="Error message if filter failed")
    summary: str = Field(description="Human-readable summary for the LLM")


# =============================================================================
# Batch Operation Models
# =============================================================================


class BatchPingTargetResult(BaseModel):
    """Result for a single target in a batch ping."""

    target: str = Field(description="Target hostname or IP")
    success: bool = Field(description="Whether ping was successful")
    packets_sent: int = Field(default=0, description="Packets sent")
    packets_received: int = Field(default=0, description="Packets received")
    packet_loss_percent: float = Field(default=100.0, description="Packet loss percentage")
    avg_latency_ms: float | None = Field(default=None, description="Average latency")
    error: str | None = Field(default=None, description="Error message if failed")


class BatchPingResult(BaseModel):
    """Result from batch ping operation."""

    success: bool = Field(description="Whether batch operation completed")
    total_targets: int = Field(description="Total targets pinged")
    successful: int = Field(description="Number of successful pings")
    failed: int = Field(description="Number of failed pings")
    results: list[BatchPingTargetResult] = Field(description="Individual target results")
    summary: str = Field(description="Human-readable summary for the LLM")


class BatchPortResult(BaseModel):
    """Result for a single port in a batch port check."""

    port: int = Field(description="Port number")
    is_open: bool = Field(description="Whether port is open")
    response_time_ms: float | None = Field(default=None, description="Response time if open")
    banner: str | None = Field(default=None, description="Service banner if available")
    service_hint: str | None = Field(default=None, description="Guessed service name")


class BatchPortCheckResult(BaseModel):
    """Result from batch port check operation."""

    success: bool = Field(description="Whether batch operation completed")
    target: str = Field(description="Target hostname or IP")
    total_ports: int = Field(description="Total ports checked")
    open_ports: int = Field(description="Number of open ports")
    closed_ports: int = Field(description="Number of closed ports")
    results: list[BatchPortResult] = Field(description="Individual port results")
    summary: str = Field(description="Human-readable summary for the LLM")


class BatchDnsTargetResult(BaseModel):
    """Result for a single query in batch DNS lookup."""

    query: str = Field(description="The queried hostname")
    success: bool = Field(description="Whether lookup was successful")
    records: list[DnsRecord] = Field(default_factory=list, description="Records found")
    error: str | None = Field(default=None, description="Error message if failed")


class BatchDnsResult(BaseModel):
    """Result from batch DNS lookup operation."""

    success: bool = Field(description="Whether batch operation completed")
    record_type: str = Field(description="DNS record type queried")
    total_queries: int = Field(description="Total queries made")
    successful: int = Field(description="Number of successful lookups")
    failed: int = Field(description="Number of failed lookups")
    results: list[BatchDnsTargetResult] = Field(description="Individual query results")
    summary: str = Field(description="Human-readable summary for the LLM")


# =============================================================================
# Local Network Info Models
# =============================================================================


class NetworkInterface(BaseModel):
    """A network interface."""

    name: str = Field(description="Interface name (e.g., eth0, en0, Ethernet)")
    status: str = Field(description="Interface status (up, down)")
    mac_address: str | None = Field(default=None, description="MAC address")
    ipv4_addresses: list[str] = Field(default_factory=list, description="IPv4 addresses")
    ipv6_addresses: list[str] = Field(default_factory=list, description="IPv6 addresses")
    netmask: str | None = Field(default=None, description="Network mask")
    broadcast: str | None = Field(default=None, description="Broadcast address")
    mtu: int | None = Field(default=None, description="Maximum transmission unit")


class InterfacesResult(BaseModel):
    """Result from get_interfaces tool."""

    success: bool = Field(description="Whether operation completed successfully")
    interfaces: list[NetworkInterface] = Field(
        default_factory=list, description="List of network interfaces"
    )
    default_interface: str | None = Field(
        default=None, description="Name of default/primary interface"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class Route(BaseModel):
    """A routing table entry."""

    destination: str = Field(description="Destination network/host")
    gateway: str | None = Field(default=None, description="Gateway address")
    netmask: str | None = Field(default=None, description="Network mask")
    interface: str | None = Field(default=None, description="Interface name")
    metric: int | None = Field(default=None, description="Route metric")
    flags: str | None = Field(default=None, description="Route flags")


class RoutesResult(BaseModel):
    """Result from get_routes tool."""

    success: bool = Field(description="Whether operation completed successfully")
    routes: list[Route] = Field(default_factory=list, description="List of routes")
    default_gateway: str | None = Field(default=None, description="Default gateway address")
    summary: str = Field(description="Human-readable summary for the LLM")


class DnsConfigResult(BaseModel):
    """Result from get_dns_config tool."""

    success: bool = Field(description="Whether operation completed successfully")
    nameservers: list[str] = Field(default_factory=list, description="Configured DNS servers")
    search_domains: list[str] = Field(default_factory=list, description="DNS search domains")
    summary: str = Field(description="Human-readable summary for the LLM")


class ArpEntry(BaseModel):
    """An ARP table entry."""

    ip_address: str = Field(description="IP address")
    mac_address: str | None = Field(default=None, description="MAC address")
    interface: str | None = Field(default=None, description="Interface name")
    state: str | None = Field(default=None, description="Entry state (e.g., REACHABLE, STALE)")


class ArpTableResult(BaseModel):
    """Result from get_arp_table tool."""

    success: bool = Field(description="Whether operation completed successfully")
    entries: list[ArpEntry] = Field(default_factory=list, description="ARP table entries")
    summary: str = Field(description="Human-readable summary for the LLM")


class Connection(BaseModel):
    """An active network connection."""

    protocol: str = Field(description="Protocol (TCP, UDP)")
    local_address: str = Field(description="Local address")
    local_port: int = Field(description="Local port")
    remote_address: str | None = Field(default=None, description="Remote address")
    remote_port: int | None = Field(default=None, description="Remote port")
    state: str | None = Field(
        default=None, description="Connection state (e.g., ESTABLISHED, LISTEN)"
    )
    pid: int | None = Field(default=None, description="Process ID")
    process_name: str | None = Field(default=None, description="Process name")


class ConnectionsResult(BaseModel):
    """Result from get_connections tool."""

    success: bool = Field(description="Whether operation completed successfully")
    connections: list[Connection] = Field(default_factory=list, description="Active connections")
    listening_count: int = Field(default=0, description="Number of listening ports")
    established_count: int = Field(default=0, description="Number of established connections")
    summary: str = Field(description="Human-readable summary for the LLM")


class PublicIpResult(BaseModel):
    """Result from get_public_ip tool."""

    success: bool = Field(description="Whether operation completed successfully")
    public_ip: str | None = Field(default=None, description="Public/external IP address")
    service_used: str | None = Field(
        default=None, description="Service used to determine public IP"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


# =============================================================================
# Planning / CIDR Math Models (Pure)
# =============================================================================


class CidrInfoResult(BaseModel):
    """CIDR primitives (IPv4/IPv6)."""

    success: bool = Field(description="Whether parsing succeeded")
    cidr_input: str = Field(description="CIDR string provided by the caller")
    cidr_normalized: str | None = Field(default=None, description="Normalized CIDR (strict=False)")
    ip_version: int | None = Field(default=None, description="4 or 6")
    prefix_length: int | None = Field(default=None, description="Prefix length")
    network_address: str | None = Field(default=None, description="Network address")
    broadcast_address: str | None = Field(default=None, description="Broadcast address (IPv4 only)")
    netmask: str | None = Field(default=None, description="Netmask")
    wildcard_mask: str | None = Field(default=None, description="Wildcard mask (IPv4 only)")
    total_addresses: int | None = Field(default=None, description="Total addresses in prefix")
    usable_host_addresses: int | None = Field(
        default=None,
        description="Usable host addresses (IPv4 excludes network/broadcast; /31 special)",
    )
    first_usable: str | None = Field(default=None, description="First usable address in range")
    last_usable: str | None = Field(default=None, description="Last usable address in range")
    notes: list[str] = Field(default_factory=list, description="Notes about semantics/edge cases")
    summary: str = Field(description="Human-readable summary for the LLM")


class IpInSubnetResult(BaseModel):
    """Check whether an IP is in a subnet and whether it's a usable host address."""

    success: bool = Field(description="Whether parsing succeeded")
    ip_input: str = Field(description="IP string provided by the caller")
    ip_normalized: str | None = Field(default=None, description="Normalized IP")
    cidr_input: str = Field(description="CIDR string provided by the caller")
    cidr_normalized: str | None = Field(default=None, description="Normalized CIDR")
    in_subnet: bool = Field(description="Whether the IP is in the subnet (range membership)")
    is_usable_host: bool = Field(
        description="Whether the IP is a usable host address (IPv4 excludes network/broadcast for /0-/30)"
    )
    reason_code: str = Field(description="Machine-readable reason code")
    special_ip: str | None = Field(
        default=None, description="If in_subnet but not usable: 'network' or 'broadcast'"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class SubnetSplitResult(BaseModel):
    """Split a parent CIDR into equal-size child subnets."""

    success: bool = Field(description="Whether split succeeded")
    parent_cidr: str = Field(description="Parent CIDR")
    child_prefix: int | None = Field(default=None, description="Child prefix length")
    count: int | None = Field(default=None, description="Number of child subnets returned")
    subnets: list[str] = Field(default_factory=list, description="Child subnets")
    summary: str = Field(description="Human-readable summary for the LLM")


class CidrSummarizeVersionResult(BaseModel):
    """Summarization result for a single IP version."""

    input_count: int = Field(description="How many valid CIDRs were provided for this version")
    summarized: list[str] = Field(default_factory=list, description="Collapsed CIDRs")


class CidrSummarizeResult(BaseModel):
    """Aggregate and collapse CIDRs."""

    success: bool = Field(description="Whether all CIDRs were valid")
    input_cidrs: list[str] = Field(default_factory=list, description="Original input")
    invalid_cidrs: list[str] = Field(default_factory=list, description="CIDRs ignored as invalid")
    ipv4: CidrSummarizeVersionResult = Field(description="IPv4 summary")
    ipv6: CidrSummarizeVersionResult = Field(description="IPv6 summary")
    notes: list[str] = Field(default_factory=list, description="Notes about mixed inputs, etc.")
    summary: str = Field(description="Human-readable summary for the LLM")


class OverlapConflict(BaseModel):
    """Represents an overlap/containment relationship between two CIDRs."""

    a: str = Field(description="First CIDR")
    b: str = Field(description="Second CIDR")
    relationship: str = Field(description="Relationship: equal|contains|contained_by|overlaps")
    overlap_cidr: str | None = Field(
        default=None,
        description="The overlapped block when trivially representable (often the smaller CIDR)",
    )


class CheckOverlapsResult(BaseModel):
    """Detect overlaps in a set of CIDRs."""

    success: bool = Field(description="Whether all CIDRs were valid")
    input_cidrs: list[str] = Field(default_factory=list, description="Original input")
    invalid_cidrs: list[str] = Field(default_factory=list, description="CIDRs ignored as invalid")
    overlaps: list[OverlapConflict] = Field(default_factory=list, description="Overlaps found")
    summary: str = Field(description="Human-readable summary for the LLM")


class VlanMatch(BaseModel):
    """A VLAN match for an IP (1 subnet per VLAN)."""

    vlan_id: str = Field(description="VLAN ID")
    name: str | None = Field(default=None, description="Optional VLAN name")
    cidr: str = Field(description="VLAN subnet CIDR")


class VlanMatchResult(BaseModel):
    """Find VLAN(s) for an IP from a provided VLAN map."""

    success: bool = Field(description="Whether VLAN map parsed without errors")
    ip_input: str = Field(description="IP string provided by the caller")
    ip_normalized: str | None = Field(default=None, description="Normalized IP")
    match_type: str = Field(description="ONE_MATCH|NO_MATCH|MULTIPLE_MATCHES")
    matches: list[VlanMatch] = Field(default_factory=list, description="Matching VLANs")
    summary: str = Field(description="Human-readable summary for the LLM")


class IpInVlanResult(BaseModel):
    """Check if an IP belongs to a specific VLAN (1 subnet per VLAN)."""

    success: bool = Field(description="Whether VLAN map parsed without errors")
    ip_input: str = Field(description="IP string provided by the caller")
    ip_normalized: str | None = Field(default=None, description="Normalized IP")
    vlan_id: str = Field(description="VLAN ID")
    vlan_name: str | None = Field(default=None, description="Optional VLAN name")
    vlan_cidr: str | None = Field(default=None, description="VLAN subnet CIDR")
    in_vlan: bool = Field(description="Whether IP belongs to VLAN subnet")
    reason_code: str = Field(description="Machine-readable reason code")
    best_guess_vlan: VlanMatch | None = Field(
        default=None, description="If not in VLAN: best guess VLAN for the IP (unique match)"
    )
    next_checks: list[str] = Field(
        default_factory=list, description="Short, Tier1-friendly next checks"
    )
    summary: str = Field(description="Human-readable summary for the LLM")


class VlanMapValidationResult(BaseModel):
    """Validate VLAN map (format + overlaps)."""

    success: bool = Field(description="Whether map has no errors")
    vlan_count: int = Field(description="Number of valid VLAN entries parsed")
    errors: list[str] = Field(default_factory=list, description="Validation errors")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")
    overlaps: list[OverlapConflict] = Field(default_factory=list, description="Overlaps found")
    summary: str = Field(description="Human-readable summary for the LLM")


class PlanSubnetsRequest(BaseModel):
    """Single VLAN subnet requirement for plan_subnets."""

    vlan_id: str | int = Field(description="VLAN ID")
    name: str = Field(description="Friendly VLAN name")
    needed_hosts: int | None = Field(
        default=None,
        validation_alias=AliasChoices("needed_hosts", "hosts"),
        description="Required usable IPv4 hosts (excludes network/broadcast). Alias: hosts",
    )
    desired_prefix: int | None = Field(
        default=None,
        validation_alias=AliasChoices("desired_prefix", "prefix"),
        description="Desired IPv4 prefix length. Alias: prefix",
    )
    avoid: list[str] | None = Field(
        default=None, description="CIDRs within parent to avoid allocating from"
    )
    contiguous: bool = Field(
        default=False,
        description="Preference flag (kept for forward compatibility; not required for 1-subnet-per-VLAN).",
    )

    @model_validator(mode="after")
    def _validate_choice(self):
        if (self.needed_hosts is None and self.desired_prefix is None) or (
            self.needed_hosts is not None and self.desired_prefix is not None
        ):
            raise ValueError("Provide exactly one of needed_hosts or desired_prefix")
        if self.needed_hosts is not None and self.needed_hosts <= 0:
            raise ValueError("needed_hosts must be > 0")
        if self.desired_prefix is not None and not (0 <= self.desired_prefix <= 32):
            raise ValueError("desired_prefix must be between 0 and 32")
        return self


class PlanSubnetsAllocation(BaseModel):
    """Per-VLAN allocation output."""

    vlan_id: str = Field(description="VLAN ID")
    name: str = Field(description="VLAN name")
    requested_hosts: int | None = Field(default=None, description="Requested usable hosts")
    requested_prefix: int | None = Field(default=None, description="Requested prefix length")
    allocated_cidr: str | None = Field(default=None, description="Allocated subnet CIDR")
    success: bool = Field(description="Whether allocation succeeded")
    notes: list[str] = Field(default_factory=list, description="Notes/warnings for this VLAN")


class RemainingSpace(BaseModel):
    """Remaining free space after allocation."""

    free_cidrs: list[str] = Field(default_factory=list, description="Remaining free CIDRs")


class PlanSubnetsResult(BaseModel):
    """Allocate VLAN subnets from a parent block."""

    success: bool = Field(description="Whether all allocations succeeded and inputs were valid")
    parent_cidr: str = Field(description="Parent CIDR")
    allocations: list[PlanSubnetsAllocation] = Field(
        default_factory=list, description="Per-VLAN allocations"
    )
    remaining: RemainingSpace = Field(description="Remaining free space")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings")
    summary: str = Field(description="Human-readable summary for the LLM")
