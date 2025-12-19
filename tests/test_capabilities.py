"""Tests for capabilities/doctor tool output."""

from network_mcp.tools.capabilities import capabilities


def test_capabilities_structure():
    result = capabilities()
    assert result.success is True
    assert isinstance(result.server_version, str)
    assert isinstance(result.platform, str)
    assert isinstance(result.python_version, str)
    assert isinstance(result.dependencies, list)
    assert isinstance(result.security, dict)
    assert isinstance(result.pcap, dict)
    assert "summary" in result.model_dump()
