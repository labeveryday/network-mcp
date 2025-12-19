"""External intelligence tools (WHOIS/RDAP and ASN lookup).

These complement DNS/connectivity tools when investigating external IPs/domains.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

import dns.resolver

from network_mcp.config import validate_target
from network_mcp.models.responses import AsnLookupResult, RdapLookupResult


def rdap_lookup(query: str, timeout: int = 10) -> RdapLookupResult:
    """Perform an RDAP lookup for a domain or IP.

    Uses rdap.org as a bootstrap aggregator which redirects to the authoritative RDAP server.
    """
    is_allowed, err = validate_target(query)
    if not is_allowed:
        return RdapLookupResult(
            success=False,
            query=query,
            query_type="ip" if _is_ip(query) else "domain",
            error_type="blocked_by_policy",
            suggestion="Adjust NETWORK_MCP_ALLOWED_TARGETS / NETWORK_MCP_BLOCKED_TARGETS policy if appropriate.",
            summary=f"Target blocked by security policy: {err}",
        )

    qtype = "ip" if _is_ip(query) else "domain"
    base = "https://rdap.org/ip/" if qtype == "ip" else "https://rdap.org/domain/"
    url = base + urllib.parse.quote(query.strip())

    try:
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        return RdapLookupResult(
            success=False,
            query=query,
            query_type=qtype,
            rdap_url=url,
            error_type="http_error",
            suggestion="Verify the query and try again. Some TLDs/IP ranges may not support RDAP.",
            summary=f"RDAP lookup failed with HTTP {e.code}",
        )
    except Exception as e:
        return RdapLookupResult(
            success=False,
            query=query,
            query_type=qtype,
            rdap_url=url,
            error_type="lookup_failed",
            suggestion="Check internet connectivity and try again.",
            summary=f"RDAP lookup failed: {e}",
        )

    handle = data.get("handle")
    name = data.get("name") or data.get("ldhName") or data.get("unicodeName")
    country = data.get("country")
    start_address = data.get("startAddress")
    end_address = data.get("endAddress")

    # Some RDAP responses include an "asn" field in remarks or extensions; keep it as a hint only.
    asn_hint = None
    for key in ("asn", "autnum"):
        if key in data:
            asn_hint = str(data.get(key))
            break

    if qtype == "ip" and start_address and end_address:
        summary = f"RDAP {query}: {start_address}–{end_address}"
        if country:
            summary += f" ({country})"
        if handle:
            summary += f", handle {handle}"
    else:
        summary = f"RDAP {query}"
        if handle:
            summary += f", handle {handle}"
        if country:
            summary += f" ({country})"

    return RdapLookupResult(
        success=True,
        query=query,
        query_type=qtype,
        rdap_url=url,
        handle=handle,
        name=name,
        country=country,
        start_address=start_address,
        end_address=end_address,
        asn_hint=asn_hint,
        summary=summary,
    )


def asn_lookup(ip: str, timeout: int = 5) -> AsnLookupResult:
    """Lookup origin ASN for an IP using Team Cymru DNS.

    Source: origin.asn.cymru.com (IPv4) / origin6.asn.cymru.com (IPv6).
    """
    is_allowed, err = validate_target(ip)
    if not is_allowed:
        return AsnLookupResult(
            success=False,
            ip=ip,
            error_type="blocked_by_policy",
            suggestion="Adjust NETWORK_MCP_ALLOWED_TARGETS / NETWORK_MCP_BLOCKED_TARGETS policy if appropriate.",
            summary=f"Target blocked by security policy: {err}",
        )

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return AsnLookupResult(
            success=False,
            ip=ip,
            error_type="invalid_input",
            suggestion="Provide a valid IPv4 or IPv6 address.",
            summary=f"Invalid IP address: {ip}",
        )

    if addr.version == 4:
        rev = ".".join(reversed(ip.split(".")))
        qname = f"{rev}.origin.asn.cymru.com"
    else:
        # nibble format for IPv6
        nibbles = addr.exploded.replace(":", "")
        rev = ".".join(reversed(list(nibbles)))
        qname = f"{rev}.origin6.asn.cymru.com"

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(qname, "TXT")
        txt = str(answers[0]).strip('"')
    except Exception as e:
        return AsnLookupResult(
            success=False,
            ip=ip,
            error_type="lookup_failed",
            suggestion="Check DNS/internet connectivity and try again.",
            summary=f"ASN lookup failed: {e}",
        )

    # Format: "ASN | PREFIX | CC | REGISTRY | ALLOCATED | AS_NAME"
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 5:
        return AsnLookupResult(
            success=False,
            ip=ip,
            error_type="parse_error",
            suggestion="Try again later; upstream response format was unexpected.",
            summary=f"ASN lookup returned unexpected format: {txt}",
        )

    asn = parts[0]
    prefix = parts[1] if len(parts) > 1 else None
    country = parts[2] if len(parts) > 2 else None
    registry = parts[3] if len(parts) > 3 else None
    allocated = parts[4] if len(parts) > 4 else None
    as_name = parts[5] if len(parts) > 5 else None

    summary = f"{ip} originates from AS{asn}"
    if as_name:
        summary += f" ({as_name})"
    if prefix:
        summary += f", prefix {prefix}"

    return AsnLookupResult(
        success=True,
        ip=ip,
        asn=asn,
        prefix=prefix,
        country=country,
        registry=registry,
        allocated=allocated,
        as_name=as_name,
        summary=summary,
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
