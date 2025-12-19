"""Unit tests for external intel tools (RDAP + ASN)."""

from unittest.mock import MagicMock, patch

import dns.resolver

from network_mcp.tools.external_intel import asn_lookup, rdap_lookup


@patch("network_mcp.tools.external_intel.validate_target")
@patch("urllib.request.urlopen")
def test_rdap_lookup_parses_basic_fields(mock_urlopen, mock_validate):
    mock_validate.return_value = (True, None)
    mock_resp = MagicMock()
    mock_resp.read.return_value = (
        b'{"handle":"TEST","country":"US","startAddress":"1.1.1.0","endAddress":"1.1.1.255"}'
    )
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    result = rdap_lookup("1.1.1.1", timeout=1)
    assert result.success is True
    assert result.handle == "TEST"
    assert result.country == "US"
    assert result.start_address == "1.1.1.0"


@patch("network_mcp.tools.external_intel.validate_target")
def test_asn_lookup_parses_cymru_txt(mock_validate):
    mock_validate.return_value = (True, None)

    fake_answers = [MagicMock()]
    fake_answers[
        0
    ].__str__.return_value = '"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11 | CLOUDFLARENET"'

    with patch.object(dns.resolver.Resolver, "resolve", return_value=fake_answers):
        result = asn_lookup("1.1.1.1", timeout=1)
        assert result.success is True
        assert result.asn == "13335"
        assert result.prefix == "1.1.1.0/24"
        assert result.as_name == "CLOUDFLARENET"
