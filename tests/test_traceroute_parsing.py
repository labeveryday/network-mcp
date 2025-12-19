"""Unit tests for traceroute parsing edge cases."""

from types import SimpleNamespace
from unittest.mock import patch

from network_mcp.tools.connectivity import traceroute


@patch("network_mcp.tools.connectivity.validate_target", return_value=(True, None))
@patch("network_mcp.tools.connectivity._get_system", return_value="darwin")
@patch("subprocess.run")
def test_traceroute_does_not_parse_numeric_fragments_as_ip(mock_run, _sys, _val):
    # This simulates a hostname containing digits like "301" where the old regex could capture "301" as an IP.
    out = """traceroute to 8.8.8.8 (8.8.8.8), 30 hops max
 1  301.router.example.com (10.0.0.1)  1.234 ms  1.111 ms  1.222 ms
 2  93.edge.example.net (93.184.216.34)  10.0 ms  11.0 ms  12.0 ms
"""
    mock_run.return_value = SimpleNamespace(stdout=out)

    result = traceroute("8.8.8.8", max_hops=5, timeout=1)
    assert result.success is True
    assert result.hops[0].ip_address == "10.0.0.1"
    assert result.hops[1].ip_address == "93.184.216.34"
