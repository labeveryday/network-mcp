"""Pydantic models for structured MCP responses."""

from network_mcp.models.responses import (
    Conversation,
    DnsAnalysisResult,
    DnsLookupResult,
    DnsRecord,
    ErrorResponse,
    FilteredPacket,
    FilterPacketsResult,
    MtrHop,
    MtrResult,
    PcapSummaryResult,
    PingResult,
    PortCheckResult,
    ProtocolHierarchyResult,
    TcpIssue,
    TcpIssuesResult,
    TracerouteHop,
    TracerouteResult,
)

__all__ = [
    # Connectivity models
    "PingResult",
    "TracerouteResult",
    "TracerouteHop",
    "DnsLookupResult",
    "DnsRecord",
    "PortCheckResult",
    "MtrResult",
    "MtrHop",
    # Pcap models
    "PcapSummaryResult",
    "Conversation",
    "TcpIssue",
    "TcpIssuesResult",
    "DnsAnalysisResult",
    "FilteredPacket",
    "FilterPacketsResult",
    "ProtocolHierarchyResult",
    # Common
    "ErrorResponse",
]
