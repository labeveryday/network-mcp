"""Local network information tools.

Cross-platform tools for getting local network configuration:
- Network interfaces
- Routing table
- DNS configuration
- ARP table
- Active connections

Supports Linux, macOS, and Windows.
"""

import platform
import re
import subprocess

from network_mcp.models.responses import (
    ArpEntry,
    ArpTableResult,
    Connection,
    ConnectionsResult,
    DnsConfigResult,
    InterfacesResult,
    NetworkInterface,
    PublicIpResult,
    Route,
    RoutesResult,
)


def _get_platform() -> str:
    """Get normalized platform name."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    return system  # "linux" or "windows"


def _run_command(cmd: list[str], timeout: int = 10) -> tuple[bool, str]:
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return True, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except Exception as e:
        return False, str(e)


# =============================================================================
# Get Interfaces
# =============================================================================


def _parse_linux_ip_addr(output: str) -> list[NetworkInterface]:
    """Parse output of 'ip addr' on Linux."""
    interfaces = []
    current_iface = None

    for line in output.split("\n"):
        # New interface line: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ..."
        iface_match = re.match(r"^\d+:\s+(\S+):\s+<([^>]*)>.*mtu\s+(\d+)", line)
        if iface_match:
            if current_iface:
                interfaces.append(current_iface)
            name = iface_match.group(1).rstrip(":")
            flags = iface_match.group(2)
            mtu = int(iface_match.group(3))
            status = "up" if "UP" in flags else "down"
            current_iface = NetworkInterface(
                name=name,
                status=status,
                mtu=mtu,
            )
        elif current_iface:
            # MAC address line: "    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff"
            mac_match = re.search(r"link/ether\s+([0-9a-f:]+)", line)
            if mac_match:
                current_iface.mac_address = mac_match.group(1)

            # IPv4 address: "    inet 192.168.1.100/24 brd 192.168.1.255 scope global"
            ipv4_match = re.search(r"inet\s+([\d.]+)/(\d+)(?:\s+brd\s+([\d.]+))?", line)
            if ipv4_match:
                current_iface.ipv4_addresses.append(ipv4_match.group(1))
                # Convert CIDR to netmask
                prefix = int(ipv4_match.group(2))
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                current_iface.netmask = f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"
                if ipv4_match.group(3):
                    current_iface.broadcast = ipv4_match.group(3)

            # IPv6 address: "    inet6 fe80::1/64 scope link"
            ipv6_match = re.search(r"inet6\s+([0-9a-f:]+)/\d+", line)
            if ipv6_match:
                current_iface.ipv6_addresses.append(ipv6_match.group(1))

    if current_iface:
        interfaces.append(current_iface)

    return interfaces


def _parse_macos_ifconfig(output: str) -> list[NetworkInterface]:
    """Parse output of 'ifconfig' on macOS."""
    interfaces = []
    current_iface = None

    for line in output.split("\n"):
        # New interface: "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500"
        iface_match = re.match(r"^(\S+):\s+flags=\d+<([^>]*)>\s+mtu\s+(\d+)", line)
        if iface_match:
            if current_iface:
                interfaces.append(current_iface)
            name = iface_match.group(1)
            flags = iface_match.group(2)
            mtu = int(iface_match.group(3))
            status = "up" if "UP" in flags else "down"
            current_iface = NetworkInterface(
                name=name,
                status=status,
                mtu=mtu,
            )
        elif current_iface:
            # MAC address: "	ether 00:11:22:33:44:55"
            mac_match = re.search(r"ether\s+([0-9a-f:]+)", line)
            if mac_match:
                current_iface.mac_address = mac_match.group(1)

            # IPv4: "	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255"
            ipv4_match = re.search(
                r"inet\s+([\d.]+)\s+netmask\s+(\S+)(?:\s+broadcast\s+([\d.]+))?", line
            )
            if ipv4_match:
                current_iface.ipv4_addresses.append(ipv4_match.group(1))
                # Convert hex netmask to dotted decimal
                netmask_hex = ipv4_match.group(2)
                if netmask_hex.startswith("0x"):
                    mask = int(netmask_hex, 16)
                    current_iface.netmask = f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"
                else:
                    current_iface.netmask = netmask_hex
                if ipv4_match.group(3):
                    current_iface.broadcast = ipv4_match.group(3)

            # IPv6: "	inet6 fe80::1%en0 prefixlen 64 scopeid 0x4"
            ipv6_match = re.search(r"inet6\s+([0-9a-f:]+)", line)
            if ipv6_match:
                addr = ipv6_match.group(1).split("%")[0]  # Remove scope ID
                current_iface.ipv6_addresses.append(addr)

    if current_iface:
        interfaces.append(current_iface)

    return interfaces


def _parse_windows_ipconfig(output: str) -> list[NetworkInterface]:
    """Parse output of 'ipconfig /all' on Windows."""
    interfaces = []
    current_iface = None

    for line in output.split("\n"):
        line = line.strip()

        # New adapter section
        if "adapter" in line.lower() and line.endswith(":"):
            if current_iface:
                interfaces.append(current_iface)
            # Extract adapter name
            name = re.sub(r"^.*adapter\s+", "", line, flags=re.IGNORECASE).rstrip(":")
            current_iface = NetworkInterface(
                name=name,
                status="unknown",
            )
        elif current_iface:
            # Media State (disconnected means down)
            if "media state" in line.lower():
                if "disconnected" in line.lower():
                    current_iface.status = "down"
                else:
                    current_iface.status = "up"

            # Physical Address (MAC)
            mac_match = re.search(r"physical address[.\s:]+([0-9A-Fa-f-]+)", line, re.IGNORECASE)
            if mac_match:
                current_iface.mac_address = mac_match.group(1).replace("-", ":").lower()

            # IPv4 Address
            ipv4_match = re.search(r"ipv4 address[.\s:]+([\d.]+)", line, re.IGNORECASE)
            if ipv4_match:
                current_iface.ipv4_addresses.append(ipv4_match.group(1))
                if current_iface.status == "unknown":
                    current_iface.status = "up"

            # Subnet Mask
            mask_match = re.search(r"subnet mask[.\s:]+([\d.]+)", line, re.IGNORECASE)
            if mask_match:
                current_iface.netmask = mask_match.group(1)

            # IPv6 Address
            ipv6_match = re.search(r"ipv6 address[.\s:]+([0-9a-f:]+)", line, re.IGNORECASE)
            if ipv6_match:
                current_iface.ipv6_addresses.append(ipv6_match.group(1))

    if current_iface:
        interfaces.append(current_iface)

    # Filter out interfaces with no addresses and set unknown status to down
    for iface in interfaces:
        if iface.status == "unknown":
            iface.status = "down" if not iface.ipv4_addresses else "up"

    return interfaces


def get_interfaces() -> InterfacesResult:
    """Get network interfaces on the local system.

    Returns information about all network interfaces including IP addresses,
    MAC addresses, and status. Works on Linux, macOS, and Windows.

    Returns:
        InterfacesResult with list of interfaces and default interface
    """
    plat = _get_platform()

    if plat == "linux":
        success, output = _run_command(["ip", "addr"])
        if not success:
            # Fallback to ifconfig
            success, output = _run_command(["ifconfig", "-a"])
            if success:
                interfaces = _parse_macos_ifconfig(output)  # Similar format
            else:
                return InterfacesResult(
                    success=False,
                    summary=f"Failed to get interfaces: {output}",
                )
        else:
            interfaces = _parse_linux_ip_addr(output)

    elif plat == "macos":
        success, output = _run_command(["ifconfig"])
        if not success:
            return InterfacesResult(
                success=False,
                summary=f"Failed to get interfaces: {output}",
            )
        interfaces = _parse_macos_ifconfig(output)

    elif plat == "windows":
        success, output = _run_command(["ipconfig", "/all"])
        if not success:
            return InterfacesResult(
                success=False,
                summary=f"Failed to get interfaces: {output}",
            )
        interfaces = _parse_windows_ipconfig(output)

    else:
        return InterfacesResult(
            success=False,
            summary=f"Unsupported platform: {plat}",
        )

    # Find default interface (one with most IPv4 addresses or first UP interface)
    default_iface = None
    for iface in interfaces:
        if iface.status == "up" and iface.ipv4_addresses:
            if not iface.name.startswith(("lo", "docker", "br-", "veth")):
                default_iface = iface.name
                break

    # Build summary
    up_count = sum(1 for i in interfaces if i.status == "up")
    summary = f"Found {len(interfaces)} interfaces ({up_count} up)"
    if default_iface:
        summary += f". Primary: {default_iface}"

    return InterfacesResult(
        success=True,
        interfaces=interfaces,
        default_interface=default_iface,
        summary=summary,
    )


# =============================================================================
# Get Routes
# =============================================================================


def _parse_linux_routes(output: str) -> tuple[list[Route], str | None]:
    """Parse output of 'ip route' on Linux."""
    routes = []
    default_gw = None

    for line in output.strip().split("\n"):
        if not line:
            continue

        parts = line.split()
        if not parts:
            continue

        route = Route(destination=parts[0])

        # Parse key-value pairs
        i = 1
        while i < len(parts):
            if parts[i] == "via" and i + 1 < len(parts):
                route.gateway = parts[i + 1]
                i += 2
            elif parts[i] == "dev" and i + 1 < len(parts):
                route.interface = parts[i + 1]
                i += 2
            elif parts[i] == "metric" and i + 1 < len(parts):
                route.metric = int(parts[i + 1])
                i += 2
            else:
                i += 1

        if route.destination == "default" and route.gateway:
            default_gw = route.gateway

        routes.append(route)

    return routes, default_gw


def _parse_macos_routes(output: str) -> tuple[list[Route], str | None]:
    """Parse output of 'netstat -rn' on macOS."""
    routes = []
    default_gw = None
    in_table = False

    for line in output.split("\n"):
        # Skip until we find the routing table header
        if "Destination" in line and "Gateway" in line:
            in_table = True
            continue

        if not in_table or not line.strip():
            continue

        # Skip section headers
        if line.startswith("Internet") or line.startswith("Routing"):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        dest = parts[0]
        gateway = parts[1]
        flags = parts[2]
        interface = parts[-1] if len(parts) >= 4 else None

        route = Route(
            destination=dest,
            gateway=gateway
            if gateway not in ("link#", "*") and not gateway.startswith("link#")
            else None,
            interface=interface,
            flags=flags,
        )

        if dest == "default" and route.gateway:
            default_gw = route.gateway

        routes.append(route)

    return routes, default_gw


def _parse_windows_routes(output: str) -> tuple[list[Route], str | None]:
    """Parse output of 'route print' on Windows."""
    routes = []
    default_gw = None
    in_table = False

    for line in output.split("\n"):
        line = line.strip()

        # Look for IPv4 route table
        if "Network Destination" in line:
            in_table = True
            continue

        if not in_table or not line:
            continue

        # End of table
        if "=" in line or "Persistent" in line:
            in_table = False
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        try:
            route = Route(
                destination=parts[0],
                netmask=parts[1],
                gateway=parts[2] if parts[2] != "On-link" else None,
                interface=parts[3] if len(parts) > 3 else None,
                metric=int(parts[4]) if len(parts) > 4 else None,
            )

            if parts[0] == "0.0.0.0" and route.gateway:
                default_gw = route.gateway

            routes.append(route)
        except (ValueError, IndexError):
            continue

    return routes, default_gw


def get_routes() -> RoutesResult:
    """Get the routing table of the local system.

    Returns all routes including the default gateway. Works on Linux, macOS,
    and Windows.

    Returns:
        RoutesResult with list of routes and default gateway
    """
    plat = _get_platform()

    if plat == "linux":
        success, output = _run_command(["ip", "route"])
        if not success:
            return RoutesResult(
                success=False,
                summary=f"Failed to get routes: {output}",
            )
        routes, default_gw = _parse_linux_routes(output)

    elif plat == "macos":
        success, output = _run_command(["netstat", "-rn"])
        if not success:
            return RoutesResult(
                success=False,
                summary=f"Failed to get routes: {output}",
            )
        routes, default_gw = _parse_macos_routes(output)

    elif plat == "windows":
        success, output = _run_command(["route", "print"])
        if not success:
            return RoutesResult(
                success=False,
                summary=f"Failed to get routes: {output}",
            )
        routes, default_gw = _parse_windows_routes(output)

    else:
        return RoutesResult(
            success=False,
            summary=f"Unsupported platform: {plat}",
        )

    summary = f"Found {len(routes)} routes"
    if default_gw:
        summary += f". Default gateway: {default_gw}"

    return RoutesResult(
        success=True,
        routes=routes,
        default_gateway=default_gw,
        summary=summary,
    )


# =============================================================================
# Get DNS Config
# =============================================================================


def get_dns_config() -> DnsConfigResult:
    """Get DNS configuration of the local system.

    Returns configured DNS servers and search domains. Works on Linux, macOS,
    and Windows.

    Returns:
        DnsConfigResult with nameservers and search domains
    """
    plat = _get_platform()
    nameservers = []
    search_domains = []

    if plat == "linux":
        # Try /etc/resolv.conf first
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            nameservers.append(parts[1])
                    elif line.startswith("search") or line.startswith("domain"):
                        parts = line.split()
                        search_domains.extend(parts[1:])
        except Exception:
            pass

        # Also try systemd-resolve if available
        if not nameservers:
            success, output = _run_command(["resolvectl", "status"])
            if success:
                for line in output.split("\n"):
                    if "DNS Servers" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            nameservers.extend(parts[1].strip().split())

    elif plat == "macos":
        success, output = _run_command(["scutil", "--dns"])
        if success:
            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ns = parts[1].strip()
                        if ns and ns not in nameservers:
                            nameservers.append(ns)
                elif line.startswith("search domain"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        if domain and domain not in search_domains:
                            search_domains.append(domain)

    elif plat == "windows":
        success, output = _run_command(["ipconfig", "/all"])
        if success:
            for line in output.split("\n"):
                line = line.strip()
                if "dns server" in line.lower():
                    # Handle both single line and continuation lines
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ns = parts[1].strip()
                        if ns and ns not in nameservers:
                            nameservers.append(ns)
                elif "connection-specific dns suffix" in line.lower():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        if domain and domain not in search_domains:
                            search_domains.append(domain)

    if not nameservers:
        return DnsConfigResult(
            success=False,
            summary="Could not determine DNS configuration",
        )

    summary = f"DNS servers: {', '.join(nameservers)}"
    if search_domains:
        summary += f". Search domains: {', '.join(search_domains)}"

    return DnsConfigResult(
        success=True,
        nameservers=nameservers,
        search_domains=search_domains,
        summary=summary,
    )


# =============================================================================
# Get ARP Table
# =============================================================================


def _parse_linux_arp(output: str) -> list[ArpEntry]:
    """Parse output of 'ip neigh' on Linux."""
    entries = []

    for line in output.strip().split("\n"):
        if not line:
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        ip_addr = parts[0]
        mac_addr = None
        interface = None
        state = None

        for i, part in enumerate(parts):
            if part == "lladdr" and i + 1 < len(parts):
                mac_addr = parts[i + 1]
            elif part == "dev" and i + 1 < len(parts):
                interface = parts[i + 1]
            elif part in ("REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT"):
                state = part

        entries.append(
            ArpEntry(
                ip_address=ip_addr,
                mac_address=mac_addr,
                interface=interface,
                state=state,
            )
        )

    return entries


def _parse_macos_arp(output: str) -> list[ArpEntry]:
    """Parse output of 'arp -a' on macOS."""
    entries = []

    for line in output.strip().split("\n"):
        # Format: hostname (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]
        match = re.search(r"\(([\d.]+)\)\s+at\s+([0-9a-f:]+)(?:\s+on\s+(\S+))?", line)
        if match:
            entries.append(
                ArpEntry(
                    ip_address=match.group(1),
                    mac_address=match.group(2) if match.group(2) != "(incomplete)" else None,
                    interface=match.group(3),
                )
            )

    return entries


def _parse_windows_arp(output: str) -> list[ArpEntry]:
    """Parse output of 'arp -a' on Windows."""
    entries = []
    current_interface = None

    for line in output.split("\n"):
        line = line.strip()

        # Interface header
        if line.startswith("Interface:"):
            match = re.search(r"Interface:\s+([\d.]+)", line)
            if match:
                current_interface = match.group(1)
            continue

        # ARP entry: "  192.168.1.1          00-11-22-33-44-55     dynamic"
        parts = line.split()
        if len(parts) >= 2:
            ip_addr = parts[0]
            # Validate IP address format
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_addr):
                mac_addr = parts[1].replace("-", ":").lower() if len(parts) > 1 else None
                state = parts[2] if len(parts) > 2 else None
                entries.append(
                    ArpEntry(
                        ip_address=ip_addr,
                        mac_address=mac_addr if mac_addr != "ff:ff:ff:ff:ff:ff" else None,
                        interface=current_interface,
                        state=state,
                    )
                )

    return entries


def get_arp_table() -> ArpTableResult:
    """Get the ARP table of the local system.

    Returns cached MAC address to IP address mappings. Works on Linux, macOS,
    and Windows.

    Returns:
        ArpTableResult with list of ARP entries
    """
    plat = _get_platform()

    if plat == "linux":
        success, output = _run_command(["ip", "neigh"])
        if not success:
            # Fallback to arp
            success, output = _run_command(["arp", "-a"])
            if success:
                entries = _parse_macos_arp(output)
            else:
                return ArpTableResult(
                    success=False,
                    summary=f"Failed to get ARP table: {output}",
                )
        else:
            entries = _parse_linux_arp(output)

    elif plat == "macos":
        success, output = _run_command(["arp", "-a"])
        if not success:
            return ArpTableResult(
                success=False,
                summary=f"Failed to get ARP table: {output}",
            )
        entries = _parse_macos_arp(output)

    elif plat == "windows":
        success, output = _run_command(["arp", "-a"])
        if not success:
            return ArpTableResult(
                success=False,
                summary=f"Failed to get ARP table: {output}",
            )
        entries = _parse_windows_arp(output)

    else:
        return ArpTableResult(
            success=False,
            summary=f"Unsupported platform: {plat}",
        )

    summary = f"ARP table has {len(entries)} entries"

    return ArpTableResult(
        success=True,
        entries=entries,
        summary=summary,
    )


# =============================================================================
# Get Connections
# =============================================================================


def _parse_linux_ss(output: str) -> list[Connection]:
    """Parse output of 'ss -tunapl' on Linux."""
    connections = []

    for line in output.strip().split("\n")[1:]:  # Skip header
        parts = line.split()
        if len(parts) < 5:
            continue

        try:
            proto = parts[0].upper()
            state = (
                parts[1]
                if parts[1] not in ("UNCONN", "ESTAB", "LISTEN", "TIME-WAIT", "CLOSE-WAIT")
                else parts[1]
            )

            # Local address
            local = parts[4]
            if ":" in local:
                local_parts = local.rsplit(":", 1)
                local_addr = local_parts[0].strip("[]")
                local_port = int(local_parts[1]) if local_parts[1] != "*" else 0
            else:
                continue

            # Remote address
            remote = parts[5] if len(parts) > 5 else "*:*"
            if ":" in remote:
                remote_parts = remote.rsplit(":", 1)
                remote_addr = (
                    remote_parts[0].strip("[]") if remote_parts[0] not in ("*", "0.0.0.0") else None
                )
                remote_port = int(remote_parts[1]) if remote_parts[1] not in ("*", "0") else None
            else:
                remote_addr = None
                remote_port = None

            # Process info (if available)
            pid = None
            process_name = None
            for part in parts:
                if "pid=" in part:
                    pid_match = re.search(r"pid=(\d+)", part)
                    if pid_match:
                        pid = int(pid_match.group(1))
                if "users:" in part or '"' in part:
                    name_match = re.search(r'"([^"]+)"', part)
                    if name_match:
                        process_name = name_match.group(1)

            connections.append(
                Connection(
                    protocol=proto,
                    local_address=local_addr,
                    local_port=local_port,
                    remote_address=remote_addr,
                    remote_port=remote_port,
                    state=state
                    if state
                    in (
                        "LISTEN",
                        "ESTAB",
                        "ESTABLISHED",
                        "TIME-WAIT",
                        "CLOSE-WAIT",
                        "SYN-SENT",
                        "SYN-RECV",
                    )
                    else None,
                    pid=pid,
                    process_name=process_name,
                )
            )
        except (ValueError, IndexError):
            continue

    return connections


def _parse_netstat(output: str) -> list[Connection]:
    """Parse output of 'netstat -an' (works on macOS and as fallback)."""
    connections = []

    for line in output.strip().split("\n"):
        parts = line.split()
        if len(parts) < 4:
            continue

        proto = parts[0].upper()
        if proto not in ("TCP", "UDP", "TCP4", "TCP6", "UDP4", "UDP6"):
            continue

        proto = "TCP" if proto.startswith("TCP") else "UDP"

        try:
            # Different formats for different systems
            if len(parts) >= 6 and parts[5] in (
                "LISTEN",
                "ESTABLISHED",
                "TIME_WAIT",
                "CLOSE_WAIT",
                "SYN_SENT",
            ):
                # macOS/BSD format: Proto Recv-Q Send-Q Local Foreign State
                local = parts[3]
                remote = parts[4]
                state = parts[5]
            elif len(parts) >= 5:
                local = parts[3]
                remote = parts[4]
                state = parts[5] if len(parts) > 5 else None
            else:
                continue

            # Parse local address
            if "." in local:
                # IPv4: 192.168.1.1.443 or 192.168.1.1:443
                if ":" in local:
                    local_parts = local.rsplit(":", 1)
                else:
                    local_parts = local.rsplit(".", 1)
                local_addr = local_parts[0]
                local_port = int(local_parts[1]) if local_parts[1] != "*" else 0
            else:
                continue

            # Parse remote address
            remote_addr = None
            remote_port = None
            if remote != "*.*" and remote != "*:*":
                if ":" in remote:
                    remote_parts = remote.rsplit(":", 1)
                else:
                    remote_parts = remote.rsplit(".", 1)
                remote_addr = remote_parts[0] if remote_parts[0] not in ("*", "0.0.0.0") else None
                remote_port = (
                    int(remote_parts[1])
                    if len(remote_parts) > 1 and remote_parts[1] not in ("*", "0")
                    else None
                )

            connections.append(
                Connection(
                    protocol=proto,
                    local_address=local_addr,
                    local_port=local_port,
                    remote_address=remote_addr,
                    remote_port=remote_port,
                    state=state,
                )
            )
        except (ValueError, IndexError):
            continue

    return connections


def get_connections(
    protocol: str | None = None,
    state: str | None = None,
) -> ConnectionsResult:
    """Get active network connections on the local system.

    Returns TCP and UDP connections including listening ports. Works on Linux,
    macOS, and Windows.

    Args:
        protocol: Filter by protocol (tcp, udp, or None for all)
        state: Filter by connection state (e.g., ESTABLISHED, LISTEN)

    Returns:
        ConnectionsResult with list of connections and counts
    """
    plat = _get_platform()

    if plat == "linux":
        # Try ss first (preferred on modern Linux)
        success, output = _run_command(["ss", "-tunapl"])
        if not success:
            # Fallback to netstat
            success, output = _run_command(["netstat", "-tunapl"])
            if success:
                connections = _parse_netstat(output)
            else:
                return ConnectionsResult(
                    success=False,
                    summary=f"Failed to get connections: {output}",
                )
        else:
            connections = _parse_linux_ss(output)

    elif plat == "macos":
        success, output = _run_command(["netstat", "-an"])
        if not success:
            return ConnectionsResult(
                success=False,
                summary=f"Failed to get connections: {output}",
            )
        connections = _parse_netstat(output)

    elif plat == "windows":
        success, output = _run_command(["netstat", "-an"])
        if not success:
            return ConnectionsResult(
                success=False,
                summary=f"Failed to get connections: {output}",
            )
        connections = _parse_netstat(output)

    else:
        return ConnectionsResult(
            success=False,
            summary=f"Unsupported platform: {plat}",
        )

    # Apply filters
    if protocol:
        proto_upper = protocol.upper()
        connections = [c for c in connections if c.protocol.upper() == proto_upper]

    if state:
        state_upper = state.upper()
        connections = [c for c in connections if c.state and state_upper in c.state.upper()]

    # Count states
    listening = sum(1 for c in connections if c.state and "LISTEN" in c.state.upper())
    established = sum(
        1
        for c in connections
        if c.state and ("ESTAB" in c.state.upper() or c.state.upper() == "ESTABLISHED")
    )

    summary = (
        f"Found {len(connections)} connections ({listening} listening, {established} established)"
    )

    return ConnectionsResult(
        success=True,
        connections=connections,
        listening_count=listening,
        established_count=established,
        summary=summary,
    )


# =============================================================================
# Get Public IP
# =============================================================================


def get_public_ip(timeout: int = 10) -> PublicIpResult:
    """Get the public/external IP address of the local system.

    Uses external services to determine the public IP address as seen from
    the internet. Tries multiple services for reliability.

    Args:
        timeout: Timeout in seconds for each service request (default: 10)

    Returns:
        PublicIpResult with public IP address and service used
    """
    import urllib.error
    import urllib.request

    # Services to try (in order of preference)
    services = [
        ("https://api.ipify.org", "ipify.org"),
        ("https://ifconfig.me/ip", "ifconfig.me"),
        ("https://icanhazip.com", "icanhazip.com"),
        ("https://checkip.amazonaws.com", "checkip.amazonaws.com"),
    ]

    for url, service_name in services:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "network-mcp/1.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                public_ip = response.read().decode("utf-8").strip()
                # Basic validation - should look like an IP
                if public_ip and ("." in public_ip or ":" in public_ip):
                    return PublicIpResult(
                        success=True,
                        public_ip=public_ip,
                        service_used=service_name,
                        summary=f"Public IP: {public_ip} (via {service_name})",
                    )
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, Exception):
            continue

    return PublicIpResult(
        success=False,
        summary="Could not determine public IP address. Check internet connectivity.",
    )
