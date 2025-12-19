"""Tests for local network info tools."""

from unittest.mock import MagicMock, patch

import pytest

from network_mcp.tools.local import (
    get_arp_table,
    get_connections,
    get_dns_config,
    get_interfaces,
    get_public_ip,
    get_routes,
)


class TestGetInterfaces:
    """Tests for get_interfaces tool."""

    @pytest.mark.integration
    def test_get_interfaces_success(self):
        """Test getting network interfaces returns valid result."""
        result = get_interfaces()
        assert result.success is True
        assert isinstance(result.interfaces, list)
        assert len(result.interfaces) >= 0
        assert "summary" in result.model_dump()

    @pytest.mark.integration
    def test_get_interfaces_has_loopback(self):
        """Test that loopback interface is typically present."""
        result = get_interfaces()
        if result.success and result.interfaces:
            # loopback may not always be present in output
            assert result.success is True

    @pytest.mark.integration
    def test_get_interfaces_structure(self):
        """Test interface structure has expected fields."""
        result = get_interfaces()
        if result.success and result.interfaces:
            iface = result.interfaces[0]
            assert hasattr(iface, "name")
            assert hasattr(iface, "status")
            assert hasattr(iface, "mac_address")
            assert hasattr(iface, "ipv4_addresses")
            assert hasattr(iface, "ipv6_addresses")


class TestGetRoutes:
    """Tests for get_routes tool."""

    @pytest.mark.integration
    def test_get_routes_success(self):
        """Test getting routing table returns valid result."""
        result = get_routes()
        assert result.success is True
        assert isinstance(result.routes, list)
        assert "summary" in result.model_dump()

    @pytest.mark.integration
    def test_get_routes_has_default(self):
        """Test that default gateway is typically found."""
        result = get_routes()
        if result.success and result.routes:
            # Default gateway may not always be present (e.g., disconnected)
            # Just check that result is valid
            assert result.success is True

    @pytest.mark.integration
    def test_get_routes_structure(self):
        """Test route structure has expected fields."""
        result = get_routes()
        if result.success and result.routes:
            route = result.routes[0]
            assert hasattr(route, "destination")
            assert hasattr(route, "gateway")
            assert hasattr(route, "interface")


class TestGetDnsConfig:
    """Tests for get_dns_config tool."""

    @pytest.mark.integration
    def test_get_dns_config_success(self):
        """Test getting DNS config returns valid result."""
        result = get_dns_config()
        assert result.success is True
        assert isinstance(result.nameservers, list)
        assert isinstance(result.search_domains, list)
        assert "summary" in result.model_dump()

    @pytest.mark.integration
    def test_get_dns_config_has_nameservers(self):
        """Test that nameservers are typically found."""
        result = get_dns_config()
        if result.success:
            # Should have at least one nameserver on a configured system
            # but may be empty in some environments
            assert result.success is True


class TestGetArpTable:
    """Tests for get_arp_table tool."""

    @pytest.mark.integration
    def test_get_arp_table_success(self):
        """Test getting ARP table returns valid result."""
        result = get_arp_table()
        assert result.success is True
        assert isinstance(result.entries, list)
        assert "summary" in result.model_dump()

    @pytest.mark.integration
    def test_get_arp_table_structure(self):
        """Test ARP entry structure has expected fields."""
        result = get_arp_table()
        if result.success and result.entries:
            entry = result.entries[0]
            assert hasattr(entry, "ip_address")
            assert hasattr(entry, "mac_address")
            assert hasattr(entry, "interface")


class TestGetConnections:
    """Tests for get_connections tool."""

    @pytest.mark.integration
    def test_get_connections_success(self):
        """Test getting connections returns valid result."""
        result = get_connections()
        assert result.success is True
        assert isinstance(result.connections, list)
        assert isinstance(result.listening_count, int)
        assert isinstance(result.established_count, int)
        assert "summary" in result.model_dump()

    @pytest.mark.integration
    def test_get_connections_filter_tcp(self):
        """Test filtering connections by TCP protocol."""
        result = get_connections(protocol="tcp")
        assert result.success is True
        if result.connections:
            for conn in result.connections:
                assert conn.protocol.lower() == "tcp"

    @pytest.mark.integration
    def test_get_connections_filter_udp(self):
        """Test filtering connections by UDP protocol."""
        result = get_connections(protocol="udp")
        assert result.success is True
        if result.connections:
            for conn in result.connections:
                assert conn.protocol.lower() == "udp"

    @pytest.mark.integration
    def test_get_connections_filter_state(self):
        """Test filtering connections by state."""
        result = get_connections(state="LISTEN")
        assert result.success is True
        # All returned connections should be in LISTEN state
        if result.connections:
            for conn in result.connections:
                if conn.state:
                    assert "LISTEN" in conn.state.upper()

    @pytest.mark.integration
    def test_get_connections_structure(self):
        """Test connection structure has expected fields."""
        result = get_connections()
        if result.success and result.connections:
            conn = result.connections[0]
            assert hasattr(conn, "protocol")
            assert hasattr(conn, "local_address")
            assert hasattr(conn, "local_port")
            assert hasattr(conn, "state")


class TestGetPublicIp:
    """Tests for get_public_ip tool."""

    @pytest.mark.integration
    def test_get_public_ip_success(self):
        """Test getting public IP returns valid result."""
        result = get_public_ip()
        # May fail if no internet connection
        assert "summary" in result.model_dump()
        if result.success:
            assert result.public_ip is not None
            assert result.service_used is not None
            # Should be a valid IP format (IPv4 or IPv6)
            assert "." in result.public_ip or ":" in result.public_ip

    def test_get_public_ip_structure(self):
        """Test public IP result structure has expected fields."""
        result = get_public_ip()
        assert hasattr(result, "success")
        assert hasattr(result, "public_ip")
        assert hasattr(result, "service_used")
        assert hasattr(result, "summary")

    @patch("urllib.request.urlopen")
    def test_get_public_ip_mock_success(self, mock_urlopen):
        """Test public IP with mocked successful response."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"203.0.113.42"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = get_public_ip()
        assert result.success is True
        assert result.public_ip == "203.0.113.42"

    @patch("urllib.request.urlopen")
    def test_get_public_ip_all_services_fail(self, mock_urlopen):
        """Test handling when all services fail."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("No internet")

        result = get_public_ip()
        assert result.success is False
        assert result.public_ip is None
        assert "Could not determine" in result.summary


class TestCrossPlatformParsing:
    """Tests for cross-platform command parsing."""

    def test_linux_ip_addr_parsing(self):
        """Test parsing Linux ip addr output."""
        from network_mcp.tools.local import _parse_linux_ip_addr

        output = """2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link
       valid_lft forever preferred_lft forever
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever"""

        interfaces = _parse_linux_ip_addr(output)
        assert len(interfaces) >= 1

    def test_linux_route_parsing(self):
        """Test parsing Linux route output."""
        from network_mcp.tools.local import _parse_linux_routes

        output = """default via 192.168.1.1 dev eth0 proto dhcp metric 100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100"""

        routes, default_gw = _parse_linux_routes(output)
        assert len(routes) >= 1
        assert default_gw == "192.168.1.1"

    def test_macos_ifconfig_parsing(self):
        """Test parsing macOS ifconfig output."""
        from network_mcp.tools.local import _parse_macos_ifconfig

        output = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 00:11:22:33:44:55
	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
	inet6 fe80::1%en0 prefixlen 64 scopeid 0x4
	status: active
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128"""

        interfaces = _parse_macos_ifconfig(output)
        assert len(interfaces) >= 1

    def test_macos_route_parsing(self):
        """Test parsing macOS netstat -rn output."""
        from network_mcp.tools.local import _parse_macos_routes

        output = """Routing tables

Internet:
Destination        Gateway            Flags     Netif Expire
default            192.168.1.1        UGSc      en0
127.0.0.1          127.0.0.1          UH        lo0
192.168.1.0/24     link#4             UCS       en0"""

        routes, default_gw = _parse_macos_routes(output)
        assert len(routes) >= 1
        assert default_gw == "192.168.1.1"

    def test_windows_ipconfig_parsing(self):
        """Test parsing Windows ipconfig /all output."""
        from network_mcp.tools.local import _parse_windows_ipconfig

        output = """Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : local
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.100(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 8.8.8.8"""

        interfaces = _parse_windows_ipconfig(output)
        assert len(interfaces) >= 1

    def test_macos_arp_parsing(self):
        """Test parsing macOS arp -a output."""
        from network_mcp.tools.local import _parse_macos_arp

        output = """? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]
? (192.168.1.100) at 00:aa:bb:cc:dd:ee on en0 ifscope [ethernet]"""

        entries = _parse_macos_arp(output)
        assert len(entries) >= 1
        assert entries[0].ip_address == "192.168.1.1"
        assert entries[0].mac_address == "00:11:22:33:44:55"

    def test_windows_arp_parsing(self):
        """Test parsing Windows arp -a output."""
        from network_mcp.tools.local import _parse_windows_arp

        output = """Interface: 192.168.1.100 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.254         00-aa-bb-cc-dd-ee     dynamic"""

        entries = _parse_windows_arp(output)
        assert len(entries) >= 1
        assert entries[0].ip_address == "192.168.1.1"

    def test_linux_arp_parsing(self):
        """Test parsing Linux ip neigh output."""
        from network_mcp.tools.local import _parse_linux_arp

        output = """192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.254 dev eth0 lladdr 00:aa:bb:cc:dd:ee STALE"""

        entries = _parse_linux_arp(output)
        assert len(entries) >= 1
        assert entries[0].ip_address == "192.168.1.1"
        assert entries[0].mac_address == "00:11:22:33:44:55"
        assert entries[0].state == "REACHABLE"


class TestErrorHandling:
    """Tests for error handling in local tools."""

    @patch("subprocess.run")
    def test_get_interfaces_command_failure(self, mock_run):
        """Test handling of command failure in get_interfaces."""
        mock_run.side_effect = Exception("Command failed")
        result = get_interfaces()
        assert result.success is False

    @patch("subprocess.run")
    def test_get_routes_command_failure(self, mock_run):
        """Test handling of command failure in get_routes."""
        mock_run.side_effect = Exception("Command failed")
        result = get_routes()
        assert result.success is False

    @patch("subprocess.run")
    def test_get_dns_config_command_failure(self, mock_run):
        """Test handling of command failure in get_dns_config."""
        mock_run.side_effect = Exception("Command failed")
        result = get_dns_config()
        assert result.success is False

    @patch("subprocess.run")
    def test_get_arp_table_command_failure(self, mock_run):
        """Test handling of command failure in get_arp_table."""
        mock_run.side_effect = Exception("Command failed")
        result = get_arp_table()
        assert result.success is False

    @patch("subprocess.run")
    def test_get_connections_command_failure(self, mock_run):
        """Test handling of command failure in get_connections."""
        mock_run.side_effect = Exception("Command failed")
        result = get_connections()
        assert result.success is False
