"""Connectivity testing tools for network diagnostics.

These tools provide smart summarization of network connectivity tests,
returning structured data optimized for LLM consumption.
"""

import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Literal

import dns.resolver
import dns.reversename

from network_mcp.config import validate_target
from network_mcp.models.responses import (
    BatchDnsResult,
    BatchDnsTargetResult,
    BatchPingResult,
    BatchPingTargetResult,
    BatchPortCheckResult,
    BatchPortResult,
    DnsLookupResult,
    DnsRecord,
    MtrHop,
    MtrResult,
    PingResult,
    PortCheckResult,
    TracerouteHop,
    TracerouteResult,
)


def _get_system() -> str:
    """Get the operating system type."""
    return platform.system().lower()


def _resolve_hostname(hostname: str) -> str | None:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def _extract_ip_candidate(text: str) -> str | None:
    """Extract a valid IPv4/IPv6 address from an arbitrary traceroute/mtr segment."""
    # Prefer addresses in parentheses: "host (1.2.3.4)" or "(2001:db8::1)"
    for candidate in re.findall(r"\(([^)]+)\)", text):
        candidate = candidate.strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue

    # Otherwise scan tokens and validate them as full IPs (avoid numeric fragments like "93" or "301")
    tokens = re.split(r"[\s,\[\]<>]+", text)
    for tok in tokens:
        tok = tok.strip("()")
        if not tok:
            continue
        # Strip common trailing punctuation
        tok = tok.strip(";:,")
        try:
            return str(ipaddress.ip_address(tok))
        except ValueError:
            continue
    return None


def ping(
    target: str,
    count: int = 4,
    timeout: int = 5,
) -> PingResult:
    """Ping a host to check connectivity and measure latency.

    Args:
        target: Hostname or IP address to ping
        count: Number of ICMP packets to send (default: 4)
        timeout: Timeout in seconds for each packet (default: 5)

    Returns:
        PingResult with latency statistics and packet loss information
    """
    # Validate target against security policy
    is_allowed, error = validate_target(target)
    if not is_allowed:
        return PingResult(
            success=False,
            target=target,
            resolved_ip=None,
            packets_sent=0,
            packets_received=0,
            packet_loss_percent=100.0,
            summary=f"Target blocked by security policy: {error}",
        )

    system = _get_system()
    resolved_ip = None

    # Resolve hostname if needed
    try:
        socket.inet_aton(target)
        # It's already an IP
    except socket.error:
        resolved_ip = _resolve_hostname(target)
        if not resolved_ip:
            return PingResult(
                success=False,
                target=target,
                resolved_ip=None,
                packets_sent=0,
                packets_received=0,
                packet_loss_percent=100.0,
                summary=f"Failed to resolve hostname '{target}' to an IP address",
            )

    # Build ping command based on OS
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), target]
    else:  # macOS, Linux
        cmd = ["ping", "-c", str(count), "-W", str(timeout), target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * count + 10,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return PingResult(
            success=False,
            target=target,
            resolved_ip=resolved_ip,
            packets_sent=count,
            packets_received=0,
            packet_loss_percent=100.0,
            summary=f"Ping to {target} timed out - host may be unreachable or blocking ICMP",
        )
    except FileNotFoundError:
        return PingResult(
            success=False,
            target=target,
            resolved_ip=resolved_ip,
            packets_sent=0,
            packets_received=0,
            packet_loss_percent=100.0,
            summary="Ping command not found on system",
        )

    # Parse output
    packets_sent = count
    packets_received = 0
    min_latency = None
    avg_latency = None
    max_latency = None
    stddev_latency = None

    # Parse packet statistics
    if system == "windows":
        # Windows: Sent = 4, Received = 4, Lost = 0 (0% loss)
        match = re.search(r"Sent = (\d+), Received = (\d+)", output)
        if match:
            packets_sent = int(match.group(1))
            packets_received = int(match.group(2))
        # Windows: Minimum = 1ms, Maximum = 3ms, Average = 2ms
        match = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)
        if match:
            min_latency = float(match.group(1))
            max_latency = float(match.group(2))
            avg_latency = float(match.group(3))
    else:
        # macOS/Linux: 4 packets transmitted, 4 received, 0% packet loss
        match = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", output)
        if match:
            packets_sent = int(match.group(1))
            packets_received = int(match.group(2))
        # macOS: round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms
        # Linux: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.567 ms
        match = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", output)
        if match:
            min_latency = float(match.group(1))
            avg_latency = float(match.group(2))
            max_latency = float(match.group(3))
            stddev_latency = float(match.group(4))

    packet_loss = (
        ((packets_sent - packets_received) / packets_sent * 100) if packets_sent > 0 else 100.0
    )
    success = packets_received > 0

    # Build summary
    if success:
        if packet_loss == 0:
            summary = f"{target} is reachable. {packets_received}/{packets_sent} packets received, avg latency {avg_latency:.1f}ms"
        else:
            summary = f"{target} is reachable but experiencing {packet_loss:.0f}% packet loss. Avg latency {avg_latency:.1f}ms when responding"
    else:
        summary = (
            f"{target} is unreachable - no ICMP replies received. Host may be down or blocking ICMP"
        )

    return PingResult(
        success=success,
        target=target,
        resolved_ip=resolved_ip,
        packets_sent=packets_sent,
        packets_received=packets_received,
        packet_loss_percent=round(packet_loss, 2),
        min_latency_ms=min_latency,
        avg_latency_ms=avg_latency,
        max_latency_ms=max_latency,
        stddev_latency_ms=stddev_latency,
        summary=summary,
    )


def traceroute(
    target: str,
    max_hops: int = 30,
    timeout: int = 5,
) -> TracerouteResult:
    """Trace the route to a destination, showing each hop along the path.

    Args:
        target: Hostname or IP address to trace
        max_hops: Maximum number of hops to trace (default: 30)
        timeout: Timeout in seconds for each probe (default: 5)

    Returns:
        TracerouteResult with hop-by-hop path analysis
    """
    # Validate target against security policy
    is_allowed, error = validate_target(target)
    if not is_allowed:
        return TracerouteResult(
            success=False,
            target=target,
            resolved_ip=None,
            hops=[],
            reached_destination=False,
            total_hops=0,
            summary=f"Target blocked by security policy: {error}",
        )

    system = _get_system()
    resolved_ip = None

    # Resolve hostname
    try:
        socket.inet_aton(target)
    except socket.error:
        resolved_ip = _resolve_hostname(target)
        if not resolved_ip:
            return TracerouteResult(
                success=False,
                target=target,
                resolved_ip=None,
                hops=[],
                reached_destination=False,
                total_hops=0,
                summary=f"Failed to resolve hostname '{target}'",
            )

    # Build traceroute command
    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), target]
    elif system == "darwin":  # macOS
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), target]
    else:  # Linux
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_hops * timeout + 30,
        )
        output = result.stdout
    except subprocess.TimeoutExpired:
        return TracerouteResult(
            success=False,
            target=target,
            resolved_ip=resolved_ip,
            hops=[],
            reached_destination=False,
            total_hops=0,
            summary=f"Traceroute to {target} timed out",
        )
    except FileNotFoundError:
        return TracerouteResult(
            success=False,
            target=target,
            resolved_ip=resolved_ip,
            hops=[],
            reached_destination=False,
            total_hops=0,
            summary="Traceroute command not found on system",
        )

    # Parse output
    hops = []
    reached_destination = False
    issues = []
    target_ip = resolved_ip or target

    lines = output.strip().split("\n")
    for line in lines:
        # Skip header lines
        if not line.strip() or "traceroute" in line.lower() or "tracing" in line.lower():
            continue

        # Parse hop line
        # Format varies by OS but generally: hop_num  hostname (ip)  time1 ms  time2 ms  time3 ms
        # Or: hop_num  * * *  (timeout)
        match = re.match(r"\s*(\d+)\s+(.+)", line)
        if not match:
            continue

        hop_num = int(match.group(1))
        rest = match.group(2)

        # Check for timeout
        if rest.strip() == "* * *" or "Request timed out" in rest:
            hops.append(
                TracerouteHop(
                    hop_number=hop_num,
                    ip_address=None,
                    hostname=None,
                    latency_ms=[],
                    packet_loss=True,
                )
            )
            continue

        # Extract IP and hostname
        ip_address = _extract_ip_candidate(rest)

        hostname = None
        # Heuristic: if the line begins with a hostname token, capture it (even if it starts with digits).
        hostname_match = re.match(r"(\S+)\s+", rest)
        if hostname_match:
            candidate = hostname_match.group(1)
            # Avoid treating an IP as hostname
            try:
                ipaddress.ip_address(candidate.strip("()"))
            except ValueError:
                hostname = candidate

        # Extract latencies
        latencies = [float(x) for x in re.findall(r"([\d.]+)\s*ms", rest)]
        avg_latency = sum(latencies) / len(latencies) if latencies else None

        # Check if destination reached
        is_destination = (ip_address == target_ip) or (
            resolved_ip is not None and ip_address == resolved_ip
        )
        if is_destination:
            reached_destination = True

        # Detect issues
        if avg_latency and avg_latency > 100:
            issues.append(f"High latency at hop {hop_num} ({avg_latency:.0f}ms)")

        hops.append(
            TracerouteHop(
                hop_number=hop_num,
                ip_address=ip_address,
                hostname=hostname,
                latency_ms=latencies,
                avg_latency_ms=avg_latency,
                packet_loss="*" in rest,
                is_destination=is_destination,
            )
        )

    # Check for packet loss issues
    consecutive_loss = 0
    for hop in hops:
        if hop.packet_loss:
            consecutive_loss += 1
        else:
            consecutive_loss = 0
        if consecutive_loss >= 3:
            issues.append(
                f"Multiple consecutive hops with packet loss starting at hop {hop.hop_number - 2}"
            )
            break

    # Build summary
    if reached_destination:
        summary = f"Route to {target} traverses {len(hops)} hops and reaches destination"
        if issues:
            summary += f". Issues detected: {'; '.join(issues)}"
    else:
        summary = f"Route to {target} traced {len(hops)} hops but did not reach destination"
        if issues:
            summary += f". Issues: {'; '.join(issues)}"

    return TracerouteResult(
        success=True,
        target=target,
        resolved_ip=resolved_ip,
        hops=hops,
        reached_destination=reached_destination,
        total_hops=len(hops),
        issues_detected=issues,
        summary=summary,
    )


def dns_lookup(
    query: str,
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "ANY"] = "A",
    nameserver: str | None = None,
) -> DnsLookupResult:
    """Perform DNS lookup for a hostname or reverse lookup for an IP.

    Args:
        query: Hostname to lookup, or IP address for reverse lookup
        record_type: DNS record type to query (default: A)
        nameserver: Optional specific nameserver to use

    Returns:
        DnsLookupResult with DNS records and response time
    """
    # Validate query target against security policy
    is_allowed, error = validate_target(query)
    if not is_allowed:
        return DnsLookupResult(
            success=False,
            query=query,
            query_type="forward",
            records=[],
            nameserver=nameserver,
            summary=f"Target blocked by security policy: {error}",
        )

    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]

    # Detect if this is a reverse lookup
    is_reverse = False
    try:
        socket.inet_aton(query)
        is_reverse = True
        query = dns.reversename.from_address(query).to_text()
        record_type = "PTR"
    except socket.error:
        pass

    start_time = time.time()
    records = []

    try:
        answers = resolver.resolve(query, record_type)
        response_time = (time.time() - start_time) * 1000

        for rdata in answers:
            record = DnsRecord(
                record_type=record_type,
                value=str(rdata),
                ttl=answers.ttl,
            )
            # Add priority for MX records
            if record_type == "MX":
                record.priority = rdata.preference
            records.append(record)

        # Build summary
        if is_reverse:
            hostnames = [r.value for r in records]
            summary = f"Reverse DNS for {query}: {', '.join(hostnames)}"
        else:
            values = [r.value for r in records[:3]]  # Limit to first 3 for summary
            more = f" (+{len(records) - 3} more)" if len(records) > 3 else ""
            summary = f"{query} resolves to: {', '.join(values)}{more}"

        return DnsLookupResult(
            success=True,
            query=query,
            query_type="reverse" if is_reverse else "forward",
            records=records,
            response_time_ms=round(response_time, 2),
            nameserver=nameserver or resolver.nameservers[0],
            summary=summary,
        )

    except dns.resolver.NXDOMAIN:
        return DnsLookupResult(
            success=False,
            query=query,
            query_type="reverse" if is_reverse else "forward",
            records=[],
            response_time_ms=(time.time() - start_time) * 1000,
            nameserver=nameserver,
            summary=f"DNS lookup failed: {query} does not exist (NXDOMAIN)",
        )
    except dns.resolver.NoAnswer:
        return DnsLookupResult(
            success=False,
            query=query,
            query_type="reverse" if is_reverse else "forward",
            records=[],
            response_time_ms=(time.time() - start_time) * 1000,
            nameserver=nameserver,
            summary=f"DNS lookup returned no {record_type} records for {query}",
        )
    except dns.resolver.Timeout:
        return DnsLookupResult(
            success=False,
            query=query,
            query_type="reverse" if is_reverse else "forward",
            records=[],
            nameserver=nameserver,
            summary=f"DNS lookup timed out for {query}",
        )
    except Exception as e:
        return DnsLookupResult(
            success=False,
            query=query,
            query_type="reverse" if is_reverse else "forward",
            records=[],
            nameserver=nameserver,
            summary=f"DNS lookup failed: {str(e)}",
        )


def port_check(
    target: str,
    port: int,
    timeout: float = 5.0,
    grab_banner: bool = True,
) -> PortCheckResult:
    """Check if a TCP port is open and optionally grab service banner.

    Args:
        target: Hostname or IP address
        port: TCP port number to check
        timeout: Connection timeout in seconds (default: 5)
        grab_banner: Whether to attempt to grab service banner (default: True)

    Returns:
        PortCheckResult with connection status and optional banner
    """
    # Validate target against security policy
    is_allowed, error = validate_target(target)
    if not is_allowed:
        return PortCheckResult(
            success=False,
            target=target,
            port=port,
            is_open=False,
            response_time_ms=None,
            banner=None,
            service_hint=None,
            summary=f"Target blocked by security policy: {error}",
        )

    # Common port to service mapping
    port_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        27017: "MongoDB",
    }

    service_hint = port_services.get(port)
    banner = None

    start_time = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        response_time = (time.time() - start_time) * 1000

        if result == 0:
            is_open = True

            # Try to grab banner
            if grab_banner:
                try:
                    # Send a basic request for HTTP ports
                    if port in [80, 8080, 8000, 8888]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    sock.settimeout(2.0)
                    banner_data = sock.recv(1024)
                    banner = banner_data.decode("utf-8", errors="ignore").strip()[:200]

                    # Try to identify service from banner
                    if not service_hint:
                        if "SSH" in banner:
                            service_hint = "SSH"
                        elif "HTTP" in banner:
                            service_hint = "HTTP"
                        elif "SMTP" in banner:
                            service_hint = "SMTP"
                        elif "FTP" in banner:
                            service_hint = "FTP"
                except (socket.timeout, ConnectionResetError):
                    pass

            summary = f"Port {port} on {target} is OPEN"
            if service_hint:
                summary += f" ({service_hint})"
            summary += f". Response time: {response_time:.1f}ms"
        else:
            is_open = False
            summary = f"Port {port} on {target} is CLOSED or filtered"
            if service_hint:
                summary += f" (expected: {service_hint})"

        return PortCheckResult(
            success=True,
            target=target,
            port=port,
            is_open=is_open,
            response_time_ms=round(response_time, 2) if is_open else None,
            banner=banner,
            service_hint=service_hint,
            summary=summary,
        )

    except socket.timeout:
        return PortCheckResult(
            success=True,
            target=target,
            port=port,
            is_open=False,
            response_time_ms=None,
            banner=None,
            service_hint=service_hint,
            summary=f"Port {port} on {target} timed out - likely filtered by firewall",
        )
    except socket.gaierror:
        return PortCheckResult(
            success=False,
            target=target,
            port=port,
            is_open=False,
            response_time_ms=None,
            banner=None,
            service_hint=service_hint,
            summary=f"Failed to resolve hostname '{target}'",
        )
    except Exception as e:
        return PortCheckResult(
            success=False,
            target=target,
            port=port,
            is_open=False,
            response_time_ms=None,
            banner=None,
            service_hint=service_hint,
            summary=f"Port check failed: {str(e)}",
        )
    finally:
        sock.close()


def mtr(
    target: str,
    count: int = 10,
    timeout: int = 5,
) -> MtrResult:
    """Run MTR (My Traceroute) combining traceroute and ping for path analysis.

    MTR provides more detailed statistics than traceroute by sending multiple
    probes to each hop and tracking packet loss and latency over time.

    Args:
        target: Hostname or IP address
        count: Number of pings to send to each hop (default: 10)
        timeout: Timeout in seconds (default: 5)

    Returns:
        MtrResult with per-hop statistics including packet loss and latency
    """
    # Validate target against security policy
    is_allowed, error = validate_target(target)
    if not is_allowed:
        return MtrResult(
            success=False,
            target=target,
            resolved_ip=None,
            hops=[],
            report_cycles=count,
            reached_destination=False,
            summary=f"Target blocked by security policy: {error}",
        )

    # Check if mtr is available
    mtr_path = shutil.which("mtr")
    if not mtr_path:
        # Fallback: provide actionable alternatives for agents (traceroute + ping)
        tr = traceroute(target, max_hops=min(30, max(1, count)), timeout=timeout)
        pg = ping(target, count=min(4, max(1, count)), timeout=timeout)
        return MtrResult(
            success=False,
            target=target,
            resolved_ip=pg.resolved_ip or tr.resolved_ip,
            hops=[],
            report_cycles=count,
            reached_destination=False,
            error_type="missing_dependency",
            suggestion=(
                "Install mtr (macOS: brew install mtr; Debian/Ubuntu: sudo apt-get install -y mtr; "
                "RHEL/Fedora: sudo dnf install -y mtr; Alpine: apk add mtr). "
                "If you cannot install it, use traceroute + ping fallbacks included in this response."
            ),
            fallback={
                "traceroute": tr.model_dump(),
                "ping": pg.model_dump(),
            },
            summary=(
                "mtr is not installed on this system. Returning traceroute+ping fallback results. "
                "Install mtr to get per-hop loss/latency statistics."
            ),
        )

    resolved_ip = None
    try:
        socket.inet_aton(target)
    except socket.error:
        resolved_ip = _resolve_hostname(target)
        if not resolved_ip:
            return MtrResult(
                success=False,
                target=target,
                resolved_ip=None,
                hops=[],
                report_cycles=count,
                reached_destination=False,
                summary=f"Failed to resolve hostname '{target}'",
            )

    # Run MTR in report mode
    cmd = ["mtr", "-r", "-c", str(count), "-w", target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=count * timeout + 60,
        )
        output = result.stdout
    except subprocess.TimeoutExpired:
        return MtrResult(
            success=False,
            target=target,
            resolved_ip=resolved_ip,
            hops=[],
            report_cycles=count,
            reached_destination=False,
            summary=f"MTR to {target} timed out",
        )
    except Exception as e:
        return MtrResult(
            success=False,
            target=target,
            resolved_ip=resolved_ip,
            hops=[],
            report_cycles=count,
            reached_destination=False,
            summary=f"MTR failed: {str(e)}",
        )

    # Parse MTR output
    # Format: HOST: Loss%   Snt   Last   Avg  Best  Wrst StDev
    hops = []
    issues = []
    reached_destination = False
    target_ip = resolved_ip or target

    lines = output.strip().split("\n")
    for line in lines:
        # Skip header
        if not line.strip() or "HOST:" in line or "Start:" in line:
            continue

        # Parse: |-- hostname        0.0%    10    1.2   1.3   1.1   1.5   0.1
        # Or:    1.|-- hostname        0.0%    10    1.2   1.3   1.1   1.5   0.1
        match = re.match(
            r"\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)?",
            line,
        )
        if not match:
            # Try alternative format
            match = re.match(
                r"\s*\|--\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)",
                line,
            )
            if match:
                hop_num = len(hops) + 1
                hostname = match.group(1)
                loss = float(match.group(2))
                sent = int(match.group(3))
                avg = float(match.group(5))
                best = float(match.group(6))
                worst = float(match.group(7))
                stddev = None
            else:
                continue
        else:
            hop_num = int(match.group(1))
            hostname = match.group(2)
            loss = float(match.group(3))
            sent = int(match.group(4))
            avg = float(match.group(6))
            best = float(match.group(7))
            worst = float(match.group(8))
            stddev = float(match.group(9)) if match.group(9) else None

        # Determine IP vs hostname (validate full IPs; avoid numeric fragments)
        ip_address = _extract_ip_candidate(hostname) if hostname else None
        host = None
        if hostname:
            # If hostname token itself is an IP, leave host unset
            try:
                ipaddress.ip_address(hostname.strip("()"))
            except ValueError:
                # Strip "(ip)" suffix if present
                host = hostname.split("(")[0].strip()

        # Check if destination
        is_dest = (
            hostname == target or hostname == target_ip or (resolved_ip and hostname == resolved_ip)
        )
        if is_dest:
            reached_destination = True

        # Detect issues
        if loss > 5:
            issues.append(f"Hop {hop_num} has {loss:.0f}% packet loss")
        if avg > 100:
            issues.append(f"Hop {hop_num} has high latency ({avg:.0f}ms avg)")

        hops.append(
            MtrHop(
                hop_number=hop_num,
                ip_address=ip_address,
                hostname=host,
                loss_percent=loss,
                sent=sent,
                received=int(sent * (100 - loss) / 100),
                best_ms=best,
                avg_ms=avg,
                worst_ms=worst,
                stddev_ms=stddev,
            )
        )

    # Build summary
    if reached_destination:
        summary = f"MTR to {target}: {len(hops)} hops, destination reached"
        if hops:
            final_hop = hops[-1]
            summary += f". Final hop latency: {final_hop.avg_ms:.1f}ms avg"
        if issues:
            summary += f". Issues: {'; '.join(issues[:3])}"
    else:
        summary = f"MTR to {target}: traced {len(hops)} hops, destination not reached"
        if issues:
            summary += f". Issues: {'; '.join(issues[:3])}"

    return MtrResult(
        success=True,
        target=target,
        resolved_ip=resolved_ip,
        hops=hops,
        report_cycles=count,
        reached_destination=reached_destination,
        issues_detected=issues,
        summary=summary,
    )


# =============================================================================
# Batch Operations
# =============================================================================


def batch_ping(
    targets: list[str],
    count: int = 4,
    timeout: int = 5,
    max_concurrent: int = 10,
    validate_targets: bool = True,
) -> BatchPingResult:
    """Ping multiple hosts in parallel.

    Efficiently tests connectivity to multiple targets simultaneously.
    Useful for checking multiple servers, network devices, or endpoints.

    Args:
        targets: List of hostnames or IP addresses to ping
        count: Number of ICMP packets per target (default: 4)
        timeout: Timeout in seconds per packet (default: 5)
        max_concurrent: Maximum concurrent pings (default: 10)
        validate_targets: Whether to validate targets against allowlist (default: True)

    Returns:
        BatchPingResult with results for all targets and summary statistics
    """
    results: list[BatchPingTargetResult] = []
    blocked_targets = []

    # Validate targets if enabled
    if validate_targets:
        valid_targets = []
        for target in targets:
            is_allowed, error = validate_target(target)
            if is_allowed:
                valid_targets.append(target)
            else:
                blocked_targets.append({"target": target, "error": error})
        targets_to_ping = valid_targets
    else:
        targets_to_ping = targets

    # Ping targets in parallel
    def ping_target(target: str) -> BatchPingTargetResult:
        result = ping(target, count=count, timeout=timeout)
        return BatchPingTargetResult(
            target=result.target,
            success=result.success,
            packets_sent=result.packets_sent,
            packets_received=result.packets_received,
            packet_loss_percent=result.packet_loss_percent,
            avg_latency_ms=result.avg_latency_ms,
            error=None,
        )

    if targets_to_ping:
        with ThreadPoolExecutor(max_workers=min(max_concurrent, len(targets_to_ping))) as executor:
            future_to_target = {
                executor.submit(ping_target, target): target for target in targets_to_ping
            }

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append(
                        BatchPingTargetResult(
                            target=target,
                            success=False,
                            error=str(e),
                        )
                    )

    # Add blocked targets to results
    for blocked in blocked_targets:
        results.append(
            BatchPingTargetResult(
                target=blocked["target"],
                success=False,
                error=f"Target blocked: {blocked['error']}",
            )
        )

    # Calculate statistics
    successful = sum(1 for r in results if r.success and r.packets_received > 0)
    failed = len(results) - successful

    # Build summary
    reachable = [r.target for r in results if r.success and r.packets_received > 0]
    unreachable = [r.target for r in results if not r.success or r.packets_received == 0]

    summary_parts = [f"Batch ping: {successful}/{len(results)} targets reachable"]
    if reachable and len(reachable) <= 5:
        summary_parts.append(f"Reachable: {', '.join(reachable)}")
    if unreachable and len(unreachable) <= 5:
        summary_parts.append(f"Unreachable: {', '.join(unreachable)}")
    if blocked_targets:
        summary_parts.append(f"{len(blocked_targets)} targets blocked by policy")

    return BatchPingResult(
        success=True,
        total_targets=len(results),
        successful=successful,
        failed=failed,
        results=results,
        summary=". ".join(summary_parts),
    )


def batch_port_check(
    target: str,
    ports: list[int],
    timeout: float = 2.0,
    max_concurrent: int = 20,
    grab_banner: bool = False,
    validate_target_host: bool = True,
) -> BatchPortCheckResult:
    """Check multiple TCP ports on a single host.

    Efficiently scans multiple ports on a target host in parallel.
    Useful for service discovery or firewall rule verification.

    Args:
        target: Hostname or IP address to scan
        ports: List of TCP port numbers to check
        timeout: Connection timeout per port in seconds (default: 2)
        max_concurrent: Maximum concurrent port checks (default: 20)
        grab_banner: Whether to attempt banner grab on open ports (default: False)
        validate_target_host: Whether to validate target against allowlist (default: True)

    Returns:
        BatchPortCheckResult with results for all ports and summary
    """
    # Validate target
    if validate_target_host:
        is_allowed, error = validate_target(target)
        if not is_allowed:
            return BatchPortCheckResult(
                success=False,
                target=target,
                total_ports=len(ports),
                open_ports=0,
                closed_ports=0,
                results=[],
                summary=f"Target blocked: {error}",
            )

    results: list[BatchPortResult] = []

    def check_port(port: int) -> BatchPortResult:
        result = port_check(target, port=port, timeout=timeout, grab_banner=grab_banner)
        return BatchPortResult(
            port=result.port,
            is_open=result.is_open,
            response_time_ms=result.response_time_ms,
            banner=result.banner,
            service_hint=result.service_hint,
        )

    if ports:
        with ThreadPoolExecutor(max_workers=min(max_concurrent, len(ports))) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception:
                    results.append(
                        BatchPortResult(
                            port=port,
                            is_open=False,
                        )
                    )

    # Sort by port number
    results.sort(key=lambda r: r.port)

    # Calculate statistics
    open_ports_list = [r.port for r in results if r.is_open]
    closed_count = len(results) - len(open_ports_list)

    # Build summary
    if open_ports_list:
        open_str = ", ".join(str(p) for p in sorted(open_ports_list)[:10])
        if len(open_ports_list) > 10:
            open_str += f" (+{len(open_ports_list) - 10} more)"
        summary = f"Port scan of {target}: {len(open_ports_list)} open, {closed_count} closed. Open: {open_str}"
    else:
        summary = f"Port scan of {target}: No open ports found among {len(ports)} checked"

    return BatchPortCheckResult(
        success=True,
        target=target,
        total_ports=len(results),
        open_ports=len(open_ports_list),
        closed_ports=closed_count,
        results=results,
        summary=summary,
    )


def batch_dns_lookup(
    queries: list[str],
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS"] = "A",
    nameserver: str | None = None,
    max_concurrent: int = 10,
) -> BatchDnsResult:
    """Resolve multiple domain names in parallel.

    Efficiently performs DNS lookups for multiple domains simultaneously.
    Useful for verifying DNS configuration across multiple domains.

    Args:
        queries: List of hostnames to lookup
        record_type: DNS record type for all queries (default: A)
        nameserver: Optional specific nameserver to use
        max_concurrent: Maximum concurrent lookups (default: 10)

    Returns:
        BatchDnsResult with results for all queries and summary
    """
    results: list[BatchDnsTargetResult] = []

    def lookup_domain(query: str) -> BatchDnsTargetResult:
        result = dns_lookup(query, record_type=record_type, nameserver=nameserver)
        return BatchDnsTargetResult(
            query=result.query,
            success=result.success,
            records=result.records,
            error=None if result.success else "Lookup failed",
        )

    if queries:
        with ThreadPoolExecutor(max_workers=min(max_concurrent, len(queries))) as executor:
            future_to_query = {executor.submit(lookup_domain, query): query for query in queries}

            for future in as_completed(future_to_query):
                query = future_to_query[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append(
                        BatchDnsTargetResult(
                            query=query,
                            success=False,
                            error=str(e),
                        )
                    )

    # Calculate statistics
    successful = sum(1 for r in results if r.success)
    failed = len(results) - successful

    # Build summary
    failed_queries = [r.query for r in results if not r.success]

    summary_parts = [f"Batch DNS: {successful}/{len(results)} queries resolved"]
    if failed_queries and len(failed_queries) <= 5:
        summary_parts.append(f"Failed: {', '.join(failed_queries)}")

    return BatchDnsResult(
        success=True,
        record_type=record_type,
        total_queries=len(results),
        successful=successful,
        failed=failed,
        results=results,
        summary=". ".join(summary_parts),
    )
