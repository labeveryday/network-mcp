# Network MCP Server

A Model Context Protocol (MCP) server providing network diagnostic tools for AI agents. Designed to offload heavy network analysis to the server and return structured, actionable data optimized for LLM consumption.

[![PyPI version](https://badge.fury.io/py/network-mcp.svg)](https://badge.fury.io/py/network-mcp)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Connectivity Testing**: ping, traceroute, DNS lookups, port checks, MTR
- **Batch Operations**: Test multiple hosts/ports concurrently
- **Local Network Info**: Get interfaces, routes, DNS config, ARP table, connections (cross-platform)
- **Pcap Analysis**: Analyze packet captures with scapy (no tshark required)
- **Custom Filters**: Execute scapy filter expressions for advanced queries
- **Security Controls**: Configurable allowlist/blocklist for target validation
- **Smart Summaries**: Returns human-readable summaries plus structured data

## Installation

```bash
pip install network-mcp
```

Or install from source:

```bash
git clone https://github.com/labeveryday/network-mcp.git
cd network-mcp
pip install -e .
```

## Quick Start

Run the MCP server:

```bash
network-mcp
```

Or with Python:

```bash
python -m network_mcp.server
```

## Available Tools

### Connectivity Tools

| Tool | Description |
|------|-------------|
| `ping` | ICMP ping with latency statistics and packet loss |
| `traceroute` | Path analysis showing each hop with latency |
| `dns_lookup` | DNS resolution (A, AAAA, MX, TXT, etc.) and reverse lookups |
| `port_check` | TCP port connectivity test with banner grabbing |
| `mtr` | Combined traceroute + ping with per-hop statistics |

### Batch Operations

| Tool | Description |
|------|-------------|
| `batch_ping` | Ping multiple hosts concurrently |
| `batch_port_check` | Check multiple ports on a single host |
| `batch_dns_lookup` | Resolve multiple hostnames in parallel |

### Local Network Info Tools

Cross-platform tools that work on Linux, macOS, and Windows.

| Tool | Description |
|------|-------------|
| `get_interfaces` | List network interfaces with IPs, MACs, and status |
| `get_routes` | Get routing table with default gateway |
| `get_dns_config` | Get configured DNS servers and search domains |
| `get_arp_table` | Get ARP cache (IP to MAC mappings) |
| `get_connections` | List active TCP/UDP connections |
| `get_public_ip` | Get public/external IP address as seen from the internet |

### Pcap Analysis Tools

| Tool | Description |
|------|-------------|
| `pcap_summary` | High-level capture stats: packets, duration, protocols, top talkers |
| `get_conversations` | Network flows/conversations between endpoints |
| `find_tcp_issues` | Detect retransmissions, resets, zero windows, dup ACKs |
| `analyze_dns_traffic` | DNS queries, failures, slow responses |
| `filter_packets` | Extract packets by IP, port, or protocol |
| `get_protocol_hierarchy` | Protocol breakdown by packets and bytes |
| `custom_scapy_filter` | Execute custom scapy filter expressions |

## IDE Integration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "network-tools": {
      "command": "network-mcp"
    }
  }
}
```

### Cursor

Add to your MCP settings:

```json
{
  "mcpServers": {
    "network-tools": {
      "command": "network-mcp"
    }
  }
}
```

### Using with uv

If you installed with uv:

```json
{
  "mcpServers": {
    "network-tools": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/network-mcp", "network-mcp"]
    }
  }
}
```

## Example Responses

### Ping

```json
{
  "success": true,
  "target": "google.com",
  "resolved_ip": "142.250.80.46",
  "packets_sent": 4,
  "packets_received": 4,
  "packet_loss_percent": 0.0,
  "min_latency_ms": 11.2,
  "avg_latency_ms": 12.8,
  "max_latency_ms": 15.1,
  "summary": "google.com is reachable. 4/4 packets received, avg latency 12.8ms"
}
```

### Batch Ping

```json
{
  "success": true,
  "total_targets": 3,
  "successful": 3,
  "failed": 0,
  "results": [
    {"target": "8.8.8.8", "success": true, "avg_latency_ms": 12.5},
    {"target": "1.1.1.1", "success": true, "avg_latency_ms": 8.2},
    {"target": "google.com", "success": true, "avg_latency_ms": 15.1}
  ],
  "summary": "Batch ping: 3/3 targets reachable"
}
```

### TCP Issues Detection

```json
{
  "success": true,
  "file_path": "/tmp/capture.pcap",
  "total_tcp_packets": 15234,
  "issues": [
    {
      "issue_type": "retransmission",
      "count": 47,
      "severity": "medium",
      "recommendation": "Retransmissions indicate packet loss. Check for network congestion."
    }
  ],
  "has_issues": true,
  "summary": "TCP issues detected in 15234 packets: 47 retransmissions"
}
```

### Get Interfaces

```json
{
  "success": true,
  "interfaces": [
    {
      "name": "en0",
      "status": "up",
      "mac_address": "00:11:22:33:44:55",
      "ipv4_addresses": ["192.168.1.100"],
      "ipv6_addresses": ["fe80::1"],
      "netmask": "255.255.255.0",
      "mtu": 1500
    }
  ],
  "default_interface": "en0",
  "summary": "Found 5 interfaces (3 up). Primary: en0"
}
```

### Get Public IP

```json
{
  "success": true,
  "public_ip": "203.0.113.42",
  "service_used": "ipify.org",
  "summary": "Public IP: 203.0.113.42 (via ipify.org)"
}
```

## Configuration

Create `config.yaml` in your working directory or `~/.network-mcp/config.yaml`:

```yaml
security:
  # Only allow these targets (glob patterns, CIDR ranges)
  allowed_targets:
    - "*.company.com"
    - "10.0.0.0/8"
    - "192.168.0.0/16"

  # Block these targets
  blocked_targets:
    - "*.gov"
    - "localhost"
    - "127.0.0.0/8"

  # Block private IPs
  block_private: false

  # Block cloud metadata endpoints (AWS, GCP, etc.)
  block_cloud_metadata: true

pcap:
  max_packets: 100000
  allow_custom_filters: true
```

Environment variables:

```bash
NETWORK_MCP_ALLOWED_TARGETS="*.company.com,10.0.0.0/8"
NETWORK_MCP_BLOCKED_TARGETS="*.gov,localhost"
NETWORK_MCP_BLOCK_PRIVATE="true"
NETWORK_MCP_MAX_PACKETS="50000"
```

## Why MCP for Network Tools?

**Token Efficiency**: LLMs have context limits. The server does heavy processing (parsing 100k packets) and returns concise summaries instead of raw data.

**Better Reasoning**: LLMs excel at deciding *what* to investigate, not parsing raw output. Structured data leads to better decisions.

**Consistency**: Server-side processing is deterministic. You don't rely on the LLM to correctly interpret traceroute output every time.

## Development

```bash
# Clone and install dev dependencies
git clone https://github.com/yourusername/network-mcp.git
cd network-mcp
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
```

### Project Structure

```
network-mcp/
├── src/network_mcp/
│   ├── __init__.py
│   ├── server.py           # FastMCP server
│   ├── config.py           # Configuration and security
│   ├── tools/
│   │   ├── connectivity.py # ping, traceroute, dns, port_check, mtr, batch ops
│   │   ├── local.py        # local network info (interfaces, routes, etc.)
│   │   └── pcap.py         # pcap analysis tools
│   └── models/
│       └── responses.py    # Pydantic response models
├── tests/
├── pyproject.toml
└── README.md
```

## Requirements

- Python 3.10+
- System tools: `ping`, `traceroute` (standard on most systems)
- Optional: `mtr` for the MTR tool

## License

MIT License - see [LICENSE](LICENSE) file for details.
