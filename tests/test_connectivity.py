"""Tests for connectivity tools."""

from unittest.mock import patch

import pytest

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


class TestPing:
    """Tests for ping tool."""

    @pytest.mark.integration
    def test_ping_success(self):
        """Test successful ping to public DNS."""
        result = ping("8.8.8.8", count=2, timeout=5)
        assert result.success is True
        assert result.target == "8.8.8.8"
        assert result.packets_sent == 2
        assert result.packets_received >= 0
        assert "summary" in result.model_dump()

    @pytest.mark.integration
    def test_ping_unreachable(self):
        """Test ping to unreachable host."""
        result = ping("192.0.2.1", count=1, timeout=1)  # TEST-NET, should fail
        assert result.packets_sent == 1
        assert result.packet_loss_percent >= 0

    def test_ping_invalid_target(self):
        """Test ping with invalid target."""
        result = ping("not.a" + "valid.host" * 20 + ".com", count=1, timeout=1)
        assert result.success is False


class TestDnsLookup:
    """Tests for DNS lookup tool."""

    @pytest.mark.integration
    def test_dns_lookup_a_record(self):
        """Test A record lookup."""
        result = dns_lookup("google.com", record_type="A")
        assert result.success is True
        assert result.query == "google.com"
        assert len(result.records) > 0
        assert result.records[0].record_type == "A"

    @pytest.mark.integration
    def test_dns_lookup_mx_record(self):
        """Test MX record lookup."""
        result = dns_lookup("google.com", record_type="MX")
        assert result.success is True
        assert any(r.record_type == "MX" for r in result.records)

    @pytest.mark.integration
    def test_dns_lookup_nonexistent(self):
        """Test lookup of non-existent domain."""
        result = dns_lookup("thisdomaindoesnotexist12345.com", record_type="A")
        assert result.success is False

    @pytest.mark.integration
    def test_dns_lookup_with_nameserver(self):
        """Test lookup with specific nameserver."""
        result = dns_lookup("google.com", record_type="A", nameserver="8.8.8.8")
        assert result.success is True
        assert result.nameserver == "8.8.8.8"


class TestPortCheck:
    """Tests for port check tool."""

    @pytest.mark.integration
    def test_port_check_open(self):
        """Test checking an open port."""
        result = port_check("google.com", port=443, timeout=5)
        assert result.success is True
        assert result.port == 443
        assert result.is_open is True
        assert result.response_time_ms is not None

    @pytest.mark.integration
    def test_port_check_closed(self):
        """Test checking a closed port."""
        result = port_check("google.com", port=12345, timeout=2)
        assert result.success is True
        assert result.is_open is False

    @pytest.mark.integration
    def test_port_check_with_banner(self):
        """Test port check with banner grab."""
        result = port_check("google.com", port=80, timeout=5, grab_banner=True)
        assert result.success is True


class TestTraceroute:
    """Tests for traceroute tool."""

    @pytest.mark.integration
    def test_traceroute_basic(self):
        """Test basic traceroute."""
        result = traceroute("8.8.8.8", max_hops=5, timeout=2)
        assert result.success is True
        assert result.target == "8.8.8.8"
        assert len(result.hops) > 0
        assert result.total_hops > 0


class TestBatchPing:
    """Tests for batch ping tool."""

    @pytest.mark.integration
    def test_batch_ping_multiple_targets(self):
        """Test pinging multiple targets."""
        result = batch_ping(["8.8.8.8", "1.1.1.1"], count=1, timeout=2)
        assert result.total_targets == 2
        assert len(result.results) == 2
        assert result.successful + result.failed == result.total_targets

    def test_batch_ping_empty_list(self):
        """Test batch ping with empty list."""
        result = batch_ping([], count=1, timeout=1)
        assert result.total_targets == 0
        assert result.successful == 0
        assert result.failed == 0

    @pytest.mark.integration
    def test_batch_ping_mixed_results(self):
        """Test batch ping with mix of reachable and unreachable."""
        result = batch_ping(["8.8.8.8", "192.0.2.1"], count=1, timeout=1)
        assert result.total_targets == 2


class TestBatchPortCheck:
    """Tests for batch port check tool."""

    @pytest.mark.integration
    def test_batch_port_check_multiple_ports(self):
        """Test checking multiple ports."""
        result = batch_port_check("google.com", ports=[80, 443, 12345], timeout=2)
        assert result.total_ports == 3
        assert len(result.results) == 3
        assert result.open_ports + result.closed_ports == result.total_ports

    @pytest.mark.integration
    def test_batch_port_check_common_ports(self):
        """Test checking common web ports."""
        result = batch_port_check("google.com", ports=[80, 443], timeout=3)
        assert result.open_ports >= 1  # At least HTTP or HTTPS should be open


class TestBatchDnsLookup:
    """Tests for batch DNS lookup tool."""

    @pytest.mark.integration
    def test_batch_dns_lookup_multiple(self):
        """Test looking up multiple domains."""
        result = batch_dns_lookup(["google.com", "cloudflare.com"])
        assert result.total_queries == 2
        assert result.successful >= 1

    @pytest.mark.integration
    def test_batch_dns_lookup_with_failures(self):
        """Test batch DNS with some failures."""
        result = batch_dns_lookup(["google.com", "nonexistent12345domain.com"])
        assert result.total_queries == 2
        assert result.failed >= 1


class TestSecurityPolicyEnforcement:
    """Tests for security policy enforcement on single-target tools.

    These tests verify that validate_target() is called and enforced
    on all single-target connectivity tools, not just batch operations.
    """

    @patch("network_mcp.tools.connectivity.validate_target")
    def test_ping_validates_target(self, mock_validate):
        """Test that ping validates target against security policy."""
        mock_validate.return_value = (False, "Target blocked by test policy")
        result = ping("blocked.example.com", count=1, timeout=1)
        assert result.success is False
        assert "blocked by security policy" in result.summary.lower()
        mock_validate.assert_called_once_with("blocked.example.com")

    @patch("network_mcp.tools.connectivity.validate_target")
    def test_traceroute_validates_target(self, mock_validate):
        """Test that traceroute validates target against security policy."""
        mock_validate.return_value = (False, "Target blocked by test policy")
        result = traceroute("blocked.example.com", max_hops=5, timeout=1)
        assert result.success is False
        assert "blocked by security policy" in result.summary.lower()
        mock_validate.assert_called_once_with("blocked.example.com")

    @patch("network_mcp.tools.connectivity.validate_target")
    def test_dns_lookup_validates_target(self, mock_validate):
        """Test that dns_lookup validates target against security policy."""
        mock_validate.return_value = (False, "Target blocked by test policy")
        result = dns_lookup("blocked.example.com", record_type="A")
        assert result.success is False
        assert "blocked by security policy" in result.summary.lower()
        mock_validate.assert_called_once_with("blocked.example.com")

    @patch("network_mcp.tools.connectivity.validate_target")
    def test_port_check_validates_target(self, mock_validate):
        """Test that port_check validates target against security policy."""
        mock_validate.return_value = (False, "Target blocked by test policy")
        result = port_check("blocked.example.com", port=80, timeout=1)
        assert result.success is False
        assert "blocked by security policy" in result.summary.lower()
        mock_validate.assert_called_once_with("blocked.example.com")

    @patch("network_mcp.tools.connectivity.validate_target")
    def test_mtr_validates_target(self, mock_validate):
        """Test that mtr validates target against security policy."""
        mock_validate.return_value = (False, "Target blocked by test policy")
        result = mtr("blocked.example.com", count=1, timeout=1)
        assert result.success is False
        assert "blocked by security policy" in result.summary.lower()
        mock_validate.assert_called_once_with("blocked.example.com")

    def test_ping_blocks_cloud_metadata(self):
        """Test that ping blocks cloud metadata endpoints by default."""
        result = ping("169.254.169.254", count=1, timeout=1)
        assert result.success is False
        assert "blocked" in result.summary.lower() or "metadata" in result.summary.lower()

    def test_traceroute_blocks_cloud_metadata(self):
        """Test that traceroute blocks cloud metadata endpoints by default."""
        result = traceroute("169.254.169.254", max_hops=5, timeout=1)
        assert result.success is False
        assert "blocked" in result.summary.lower() or "metadata" in result.summary.lower()

    def test_dns_lookup_blocks_cloud_metadata(self):
        """Test that dns_lookup blocks cloud metadata endpoints by default."""
        result = dns_lookup("169.254.169.254", record_type="PTR")
        assert result.success is False
        assert "blocked" in result.summary.lower() or "metadata" in result.summary.lower()

    def test_port_check_blocks_cloud_metadata(self):
        """Test that port_check blocks cloud metadata endpoints by default."""
        result = port_check("169.254.169.254", port=80, timeout=1)
        assert result.success is False
        assert "blocked" in result.summary.lower() or "metadata" in result.summary.lower()
