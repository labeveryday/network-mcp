"""Planning tools (CIDR math + VLAN/subnet validation).

These tools are intentionally **pure**:
- no network calls
- deterministic output
- safe-by-default

They are designed for Tier 1 / Tier 2 NOC workflows like:
- "Is this IP in this subnet?"
- "Does this IP belong to VLAN 20?"
- "If not, what VLAN *does* it match?"
- "Can I carve these VLANs out of this parent block?"
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from network_mcp.models.responses import (
    CheckOverlapsResult,
    CidrInfoResult,
    CidrSummarizeResult,
    CidrSummarizeVersionResult,
    IpInSubnetResult,
    IpInVlanResult,
    OverlapConflict,
    PlanSubnetsAllocation,
    PlanSubnetsRequest,
    PlanSubnetsResult,
    RemainingSpace,
    SubnetSplitResult,
    VlanMapValidationResult,
    VlanMatch,
    VlanMatchResult,
)


def _as_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(ip.strip())


def _as_net(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr.strip(), strict=False)


def _ip_version(obj: ipaddress._BaseAddress | ipaddress._BaseNetwork) -> int:
    return 4 if obj.version == 4 else 6


def _ipv4_netmask(prefixlen: int) -> str:
    mask = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
    return f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"


def _ipv4_wildcard(prefixlen: int) -> str:
    mask = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
    wc = (~mask) & 0xFFFFFFFF
    return f"{(wc >> 24) & 0xFF}.{(wc >> 16) & 0xFF}.{(wc >> 8) & 0xFF}.{wc & 0xFF}"


def _ipv4_usable_host_count(net: ipaddress.IPv4Network) -> int:
    # RFC 3021: /31 has 2 usable addresses for P2P links
    if net.prefixlen == 32:
        return 1
    if net.prefixlen == 31:
        return 2
    if net.prefixlen >= 0:
        return max(int(net.num_addresses) - 2, 0)
    return 0


def _ipv4_first_last_usable(net: ipaddress.IPv4Network) -> tuple[str | None, str | None]:
    if net.prefixlen == 32:
        host = str(net.network_address)
        return host, host
    if net.prefixlen == 31:
        return str(net.network_address), str(net.broadcast_address)
    if net.num_addresses <= 2:
        return None, None
    return str(net.network_address + 1), str(net.broadcast_address - 1)


def cidr_info(cidr: str) -> CidrInfoResult:
    """Return common CIDR primitives for IPv4/IPv6."""
    try:
        net = _as_net(cidr)
    except ValueError as e:
        return CidrInfoResult(
            success=False,
            cidr_input=cidr,
            cidr_normalized=None,
            ip_version=None,
            prefix_length=None,
            network_address=None,
            broadcast_address=None,
            netmask=None,
            wildcard_mask=None,
            total_addresses=None,
            usable_host_addresses=None,
            first_usable=None,
            last_usable=None,
            notes=[f"Invalid CIDR: {e}"],
            summary=f"Invalid CIDR '{cidr}': {e}",
        )

    notes: list[str] = []
    ip_version = _ip_version(net)
    total = int(net.num_addresses)
    broadcast = str(net.broadcast_address) if ip_version == 4 else None
    netmask = _ipv4_netmask(net.prefixlen) if ip_version == 4 else str(net.netmask)
    wildcard = _ipv4_wildcard(net.prefixlen) if ip_version == 4 else None

    if ip_version == 4:
        usable = _ipv4_usable_host_count(net)  # type: ignore[arg-type]
        first, last = _ipv4_first_last_usable(net)  # type: ignore[arg-type]
        if net.prefixlen == 31:
            notes.append("IPv4 /31: treated as point-to-point (RFC 3021), both addresses usable.")
        elif net.prefixlen == 32:
            notes.append("IPv4 /32: host route (single address).")
    else:
        # IPv6: no broadcast concept; all addresses are generally assignable.
        usable = total
        first = str(net.network_address)
        last = str(net[-1])
        notes.append("IPv6: no broadcast address; usable range is the full prefix.")

    norm = str(net)
    summary = f"{norm} (IPv{ip_version}): {usable} usable host addresses"
    if first and last:
        summary += f", range {first} - {last}"

    return CidrInfoResult(
        success=True,
        cidr_input=cidr,
        cidr_normalized=norm,
        ip_version=ip_version,
        prefix_length=net.prefixlen,
        network_address=str(net.network_address),
        broadcast_address=broadcast,
        netmask=netmask,
        wildcard_mask=wildcard,
        total_addresses=total,
        usable_host_addresses=usable,
        first_usable=first,
        last_usable=last,
        notes=notes,
        summary=summary,
    )


def ip_in_subnet(ip: str, cidr: str) -> IpInSubnetResult:
    """Check whether an IP is in a subnet and whether it's a usable host address."""
    try:
        addr = _as_ip(ip)
    except ValueError as e:
        return IpInSubnetResult(
            success=False,
            ip_input=ip,
            ip_normalized=None,
            cidr_input=cidr,
            cidr_normalized=None,
            in_subnet=False,
            is_usable_host=False,
            reason_code="IP_INVALID",
            special_ip=None,
            summary=f"Invalid IP '{ip}': {e}",
        )

    try:
        net = _as_net(cidr)
    except ValueError as e:
        return IpInSubnetResult(
            success=False,
            ip_input=ip,
            ip_normalized=str(addr),
            cidr_input=cidr,
            cidr_normalized=None,
            in_subnet=False,
            is_usable_host=False,
            reason_code="CIDR_INVALID",
            special_ip=None,
            summary=f"Invalid CIDR '{cidr}': {e}",
        )

    if addr.version != net.version:
        return IpInSubnetResult(
            success=True,
            ip_input=ip,
            ip_normalized=str(addr),
            cidr_input=cidr,
            cidr_normalized=str(net),
            in_subnet=False,
            is_usable_host=False,
            reason_code="VERSION_MISMATCH",
            special_ip=None,
            summary=f"No — IP is IPv{addr.version} but CIDR is IPv{net.version} ({net}).",
        )

    in_subnet = addr in net
    if not in_subnet:
        return IpInSubnetResult(
            success=True,
            ip_input=ip,
            ip_normalized=str(addr),
            cidr_input=cidr,
            cidr_normalized=str(net),
            in_subnet=False,
            is_usable_host=False,
            reason_code="OUT_OF_RANGE",
            special_ip=None,
            summary=f"No — {addr} is not in {net}.",
        )

    # In subnet; determine "usable host" semantics.
    special: str | None = None
    usable = True
    reason = "IN_RANGE_USABLE"

    if addr.version == 4:
        v4net = net  # type: ignore[assignment]
        if addr == v4net.network_address and v4net.prefixlen < 31:
            usable = False
            special = "network"
            reason = "IN_RANGE_NETWORK_ADDRESS"
        elif addr == v4net.broadcast_address and v4net.prefixlen < 31:
            usable = False
            special = "broadcast"
            reason = "IN_RANGE_BROADCAST_ADDRESS"
        # /31 and /32 are treated as usable (RFC 3021 + host routes).

    summary = f"Yes — {addr} is in {net}."
    if not usable and special:
        summary += f" Note: this is the {special} address (not a usable host)."

    return IpInSubnetResult(
        success=True,
        ip_input=ip,
        ip_normalized=str(addr),
        cidr_input=cidr,
        cidr_normalized=str(net),
        in_subnet=True,
        is_usable_host=usable,
        reason_code=reason,
        special_ip=special,
        summary=summary,
    )


def subnet_split(
    cidr: str, new_prefix: int | None = None, count: int | None = None
) -> SubnetSplitResult:
    """Split a parent CIDR into child subnets (equal-size)."""
    try:
        net = _as_net(cidr)
    except ValueError as e:
        return SubnetSplitResult(
            success=False,
            parent_cidr=cidr,
            child_prefix=None,
            count=None,
            subnets=[],
            summary=f"Invalid CIDR '{cidr}': {e}",
        )

    if (new_prefix is None and count is None) or (new_prefix is not None and count is not None):
        return SubnetSplitResult(
            success=False,
            parent_cidr=str(net),
            child_prefix=None,
            count=None,
            subnets=[],
            summary="Provide exactly one of new_prefix or count.",
        )

    if count is not None:
        if count <= 0:
            return SubnetSplitResult(
                success=False,
                parent_cidr=str(net),
                child_prefix=None,
                count=count,
                subnets=[],
                summary="count must be > 0.",
            )
        # Equal split count must be a power of two for CIDR-aligned subdivision.
        if count & (count - 1) != 0:
            return SubnetSplitResult(
                success=False,
                parent_cidr=str(net),
                child_prefix=None,
                count=count,
                subnets=[],
                summary="count must be a power of two (e.g., 2, 4, 8, 16) for equal CIDR splits.",
            )
        add_bits = int(math.log2(count))
        new_prefix = net.prefixlen + add_bits

    assert new_prefix is not None
    if new_prefix < net.prefixlen:
        return SubnetSplitResult(
            success=False,
            parent_cidr=str(net),
            child_prefix=new_prefix,
            count=None,
            subnets=[],
            summary=f"new_prefix {new_prefix} is shorter than parent prefix {net.prefixlen}.",
        )
    if new_prefix > (32 if net.version == 4 else 128):
        return SubnetSplitResult(
            success=False,
            parent_cidr=str(net),
            child_prefix=new_prefix,
            count=None,
            subnets=[],
            summary="new_prefix is out of range for this IP version.",
        )

    subs = [str(s) for s in net.subnets(new_prefix=new_prefix)]
    summary = f"Split {net} into {len(subs)} subnets of /{new_prefix}."
    return SubnetSplitResult(
        success=True,
        parent_cidr=str(net),
        child_prefix=new_prefix,
        count=len(subs),
        subnets=subs,
        summary=summary,
    )


def cidr_summarize(cidrs: list[str]) -> CidrSummarizeResult:
    """Aggregate and collapse CIDRs into summarized routes."""
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    invalid: list[str] = []

    for c in cidrs:
        try:
            n = _as_net(c)
        except ValueError:
            invalid.append(c)
            continue
        if n.version == 4:
            v4.append(n)  # type: ignore[arg-type]
        else:
            v6.append(n)  # type: ignore[arg-type]

    def _collapse(nets: list[ipaddress._BaseNetwork]) -> list[str]:
        return [str(n) for n in ipaddress.collapse_addresses(nets)]

    out_v4 = _collapse(v4) if v4 else []
    out_v6 = _collapse(v6) if v6 else []
    notes: list[str] = []
    if invalid:
        notes.append(f"Ignored invalid CIDRs: {invalid}")
    if v4 and v6:
        notes.append("Mixed IPv4 and IPv6 inputs; summarized separately.")

    parts: list[str] = []
    if out_v4:
        parts.append(f"{len(out_v4)} IPv4 route(s)")
    if out_v6:
        parts.append(f"{len(out_v6)} IPv6 route(s)")
    if not parts:
        parts.append("0 routes")
    summary = f"Summarized into {', '.join(parts)}."

    return CidrSummarizeResult(
        success=len(invalid) == 0,
        input_cidrs=cidrs,
        invalid_cidrs=invalid,
        ipv4=CidrSummarizeVersionResult(input_count=len(v4), summarized=out_v4),
        ipv6=CidrSummarizeVersionResult(input_count=len(v6), summarized=out_v6),
        notes=notes,
        summary=summary,
    )


def check_overlaps(cidrs: list[str]) -> CheckOverlapsResult:
    """Detect CIDR overlaps and containment relationships."""
    nets: list[ipaddress._BaseNetwork] = []
    invalid: list[str] = []
    for c in cidrs:
        try:
            nets.append(_as_net(c))
        except ValueError:
            invalid.append(c)

    conflicts: list[OverlapConflict] = []
    # Compare within each IP version only.
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            a = nets[i]
            b = nets[j]
            if a.version != b.version:
                continue
            if not a.overlaps(b):
                continue
            relationship = "overlaps"
            overlap_cidr = None
            if a == b:
                relationship = "equal"
                overlap_cidr = str(a)
            elif a.supernet_of(b):  # type: ignore[attr-defined]
                relationship = "contains"
                overlap_cidr = str(b)
            elif a.subnet_of(b):  # type: ignore[attr-defined]
                relationship = "contained_by"
                overlap_cidr = str(a)
            else:
                # For CIDR blocks, overlap implies containment/equality; keep generic fallback.
                overlap_cidr = None

            conflicts.append(
                OverlapConflict(
                    a=str(a),
                    b=str(b),
                    relationship=relationship,
                    overlap_cidr=overlap_cidr,
                )
            )

    summary = f"Found {len(conflicts)} overlap(s)." if conflicts else "No overlaps detected."
    if invalid:
        summary += f" Ignored {len(invalid)} invalid CIDR(s)."

    return CheckOverlapsResult(
        success=len(invalid) == 0,
        input_cidrs=cidrs,
        invalid_cidrs=invalid,
        overlaps=conflicts,
        summary=summary,
    )


@dataclass(frozen=True)
class _VlanDef:
    vlan_id: str
    cidr: str
    name: str | None = None


def _parse_vlan_map(vlan_map: dict[str, Any]) -> tuple[list[_VlanDef], list[str]]:
    vlans: list[_VlanDef] = []
    errors: list[str] = []
    for k, v in (vlan_map or {}).items():
        vlan_id = str(k)
        # Accept a shorthand format for NOC ergonomics:
        # {"10": "192.168.10.0/24"}
        # ...in addition to the structured format:
        # {"10": {"cidr": "192.168.10.0/24", "name": "Mgmt"}}
        if isinstance(v, str):
            cidr = v
            name = None
        elif isinstance(v, dict):
            cidr = v.get("cidr")
            name = v.get("name")
        else:
            errors.append(
                f"VLAN {vlan_id}: value must be either a CIDR string or an object with at least 'cidr'"
            )
            continue
        if not cidr or not isinstance(cidr, str):
            errors.append(f"VLAN {vlan_id}: missing/invalid 'cidr'")
            continue
        try:
            n = _as_net(cidr)
        except ValueError as e:
            errors.append(f"VLAN {vlan_id}: invalid cidr '{cidr}': {e}")
            continue
        if n.version != 4:
            errors.append(f"VLAN {vlan_id}: only IPv4 VLAN subnets are supported right now")
            continue
        vlans.append(_VlanDef(vlan_id=vlan_id, cidr=str(n), name=str(name) if name else None))
    return vlans, errors


def validate_vlan_map(vlan_map: dict[str, Any]) -> VlanMapValidationResult:
    """Validate a simple VLAN map (1 subnet per VLAN) and surface overlaps."""
    vlans, errors = _parse_vlan_map(vlan_map)
    cidrs = [v.cidr for v in vlans]
    overlaps = check_overlaps(cidrs).overlaps

    warnings: list[str] = []
    if overlaps:
        warnings.append("Overlapping VLAN subnets detected (this is usually an error on-prem).")

    ok = not errors
    summary = "VLAN map valid."
    if errors:
        summary = f"VLAN map has {len(errors)} error(s)."
    elif overlaps:
        summary = f"VLAN map valid but has {len(overlaps)} overlap(s)."

    return VlanMapValidationResult(
        success=ok,
        vlan_count=len(vlans),
        errors=errors,
        warnings=warnings,
        overlaps=overlaps,
        summary=summary,
    )


def find_vlan_for_ip(ip: str, vlan_map: dict[str, Any]) -> VlanMatchResult:
    """Find which VLAN subnet (if any) matches an IP."""
    try:
        addr = _as_ip(ip)
    except ValueError as e:
        return VlanMatchResult(
            success=False,
            ip_input=ip,
            ip_normalized=None,
            match_type="NO_MATCH",
            matches=[],
            summary=f"Invalid IP '{ip}': {e}",
        )

    vlans, errors = _parse_vlan_map(vlan_map)
    # If vlan_map invalid, still try best-effort matches from valid entries.
    matches: list[VlanMatch] = []
    for v in vlans:
        net = _as_net(v.cidr)
        if addr.version != net.version:
            continue
        if addr in net:
            matches.append(VlanMatch(vlan_id=v.vlan_id, name=v.name, cidr=str(net)))

    match_type: str
    if len(matches) == 1:
        match_type = "ONE_MATCH"
        summary = f"IP {addr} matches VLAN {matches[0].vlan_id} ({matches[0].cidr})."
    elif len(matches) == 0:
        match_type = "NO_MATCH"
        summary = f"IP {addr} does not match any VLAN subnet in the provided map."
    else:
        match_type = "MULTIPLE_MATCHES"
        summary = (
            f"IP {addr} matches multiple VLAN subnets (overlap): {[m.vlan_id for m in matches]}."
        )

    if errors:
        summary += f" Note: VLAN map had {len(errors)} error(s); some entries were ignored."

    return VlanMatchResult(
        success=len(errors) == 0,
        ip_input=ip,
        ip_normalized=str(addr),
        match_type=match_type,
        matches=matches,
        summary=summary,
    )


def ip_in_vlan(ip: str, vlan_id: str | int, vlan_map: dict[str, Any]) -> IpInVlanResult:
    """Check if an IP belongs to a VLAN (1 subnet per VLAN)."""
    vlan_key = str(vlan_id)
    try:
        addr = _as_ip(ip)
    except ValueError as e:
        return IpInVlanResult(
            success=False,
            ip_input=ip,
            ip_normalized=None,
            vlan_id=vlan_key,
            vlan_name=None,
            vlan_cidr=None,
            in_vlan=False,
            reason_code="IP_INVALID",
            best_guess_vlan=None,
            summary=f"Invalid IP '{ip}': {e}",
            next_checks=[],
        )

    vlans, errors = _parse_vlan_map(vlan_map)
    vlan_def = next((v for v in vlans if v.vlan_id == vlan_key), None)
    if vlan_def is None:
        return IpInVlanResult(
            success=False,
            ip_input=ip,
            ip_normalized=str(addr),
            vlan_id=vlan_key,
            vlan_name=None,
            vlan_cidr=None,
            in_vlan=False,
            reason_code="VLAN_NOT_FOUND",
            best_guess_vlan=None,
            summary=f"VLAN {vlan_key} not found in vlan_map.",
            next_checks=["Verify the VLAN map includes this VLAN ID for the correct site."],
        )

    net = _as_net(vlan_def.cidr)
    if addr.version != net.version:
        return IpInVlanResult(
            success=True,
            ip_input=ip,
            ip_normalized=str(addr),
            vlan_id=vlan_key,
            vlan_name=vlan_def.name,
            vlan_cidr=str(net),
            in_vlan=False,
            reason_code="VERSION_MISMATCH",
            best_guess_vlan=None,
            summary=f"No — IP is IPv{addr.version} but VLAN {vlan_key} subnet is IPv{net.version} ({net}).",
            next_checks=[],
        )

    in_vlan = addr in net
    next_checks: list[str] = []
    best_guess: VlanMatch | None = None

    if in_vlan:
        summary = f"Yes — {addr} belongs to VLAN {vlan_key} ({net})."
        reason = "IN_VLAN"
    else:
        # Provide a helpful best-guess VLAN for Tier 1/2 triage.
        match = find_vlan_for_ip(str(addr), vlan_map)
        if match.match_type == "ONE_MATCH":
            best_guess = match.matches[0]
            next_checks = [
                "Likely wrong switchport VLAN assignment or trunk tagging.",
                "If DHCP: verify the DHCP scope/relay for the expected VLAN.",
            ]
            summary = f"No — VLAN {vlan_key} is {net}; IP {addr} matches VLAN {best_guess.vlan_id} ({best_guess.cidr})."
        elif match.match_type == "MULTIPLE_MATCHES":
            next_checks = [
                "Overlapping subnets detected in VLAN map; escalate to network engineering."
            ]
            summary = f"No — IP {addr} matches multiple VLAN subnets (overlap)."
        else:
            next_checks = [
                "Verify the IP is correct and the VLAN map is current for this site.",
                "If this is a transit/ptp/loopback range, it may not be in the VLAN map.",
            ]
            summary = f"No — {addr} is not in VLAN {vlan_key} subnet {net}, and it did not match any VLAN subnet."
        reason = "NOT_IN_VLAN"

    if errors and not in_vlan:
        summary += f" Note: VLAN map had {len(errors)} error(s); some entries were ignored."

    return IpInVlanResult(
        success=len(errors) == 0,
        ip_input=ip,
        ip_normalized=str(addr),
        vlan_id=vlan_key,
        vlan_name=vlan_def.name,
        vlan_cidr=str(net),
        in_vlan=in_vlan,
        reason_code=reason,
        best_guess_vlan=best_guess,
        summary=summary,
        next_checks=next_checks,
    )


def _next_pow2(n: int) -> int:
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


def _required_prefix_for_hosts(needed_hosts: int) -> int:
    if needed_hosts <= 0:
        raise ValueError("needed_hosts must be > 0")
    if needed_hosts == 1:
        return 32
    if needed_hosts == 2:
        return 31
    total_needed = needed_hosts + 2
    size = _next_pow2(total_needed)
    return 32 - int(math.log2(size))


def _exclude_networks(
    free: list[ipaddress.IPv4Network], exclude: ipaddress.IPv4Network
) -> list[ipaddress.IPv4Network]:
    out: list[ipaddress.IPv4Network] = []
    for f in free:
        if not f.overlaps(exclude):
            out.append(f)
            continue
        if exclude.supernet_of(f) or exclude == f:
            # Excluding covers this entire free block.
            continue
        if f.supernet_of(exclude):
            out.extend(list(f.address_exclude(exclude)))
            continue
        # CIDR overlap implies containment; this should be unreachable, but keep safe fallback.
        out.append(f)
    # Keep deterministic ordering: smallest network address first, then longest prefix first.
    out.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    return out


def _allocate_from_free(
    free: list[ipaddress.IPv4Network], prefix: int
) -> tuple[ipaddress.IPv4Network | None, list[ipaddress.IPv4Network]]:
    for idx, block in enumerate(free):
        if prefix < block.prefixlen:
            continue
        if prefix == block.prefixlen:
            alloc = block
            new_free = free[:idx] + free[idx + 1 :]
            return alloc, new_free
        # Split block and take first child.
        child = next(block.subnets(new_prefix=prefix))
        new_free = free[:idx] + free[idx + 1 :]
        new_free = _exclude_networks(new_free + [block], child)
        return child, new_free
    return None, free


def plan_subnets(parent_cidr: str, requirements: list[dict[str, Any]]) -> PlanSubnetsResult:
    """Allocate VLAN subnets from a parent IPv4 block (1 subnet per VLAN)."""
    try:
        parent = _as_net(parent_cidr)
    except ValueError as e:
        return PlanSubnetsResult(
            success=False,
            parent_cidr=parent_cidr,
            allocations=[],
            remaining=RemainingSpace(free_cidrs=[]),
            warnings=[f"Invalid parent CIDR: {e}"],
            summary=f"Invalid parent CIDR '{parent_cidr}': {e}",
        )

    if parent.version != 4:
        return PlanSubnetsResult(
            success=False,
            parent_cidr=str(parent),
            allocations=[],
            remaining=RemainingSpace(free_cidrs=[]),
            warnings=["Only IPv4 planning is supported right now."],
            summary="Only IPv4 planning is supported right now.",
        )

    # Parse and normalize requests.
    def _format_req_errors(req: dict[str, Any], err: ValidationError) -> list[str]:
        msgs: list[str] = []
        for e in err.errors():
            loc = ".".join(str(p) for p in (e.get("loc") or []) if p is not None)
            if not loc:
                loc = "requirement"
            msg = e.get("msg", "Invalid value")
            msgs.append(f"{loc}: {msg}")
        msgs.append(
            "Example requirement: "
            '{"vlan_id": 10, "name": "Mgmt", "hosts": 50}  '
            'or {"vlan_id": 10, "name": "Mgmt", "prefix": 26}'
        )
        return msgs

    parsed: list[PlanSubnetsRequest] = []
    errors: list[str] = []
    for r in requirements:
        try:
            parsed.append(PlanSubnetsRequest.model_validate(r))
        except ValidationError as e:
            errors.extend(_format_req_errors(r, e))
        except Exception as e:
            errors.append(f"Invalid requirement object: {r}. Error: {e}")

    if errors:
        return PlanSubnetsResult(
            success=False,
            parent_cidr=str(parent),
            allocations=[],
            remaining=RemainingSpace(free_cidrs=[str(parent)]),
            warnings=errors,
            summary="Invalid requirements. See warnings for what to fix and an example payload.",
        )

    # Build free list and apply avoid ranges.
    free: list[ipaddress.IPv4Network] = [parent]  # type: ignore[list-item]
    avoid_all: list[str] = []
    for req in parsed:
        for a in req.avoid or []:
            avoid_all.append(a)
            try:
                ex = _as_net(a)
            except ValueError:
                continue
            if ex.version != 4:
                continue
            if not parent.overlaps(ex):
                continue
            # Only exclude the portion inside parent.
            if parent.supernet_of(ex) or parent == ex:  # type: ignore[arg-type]
                free = _exclude_networks(free, ex)  # type: ignore[arg-type]

    # Sort requests: largest first to reduce fragmentation.
    def _req_prefix(req: PlanSubnetsRequest) -> int:
        if req.desired_prefix is not None:
            return req.desired_prefix
        assert req.needed_hosts is not None
        return _required_prefix_for_hosts(req.needed_hosts)

    parsed.sort(key=lambda r: _req_prefix(r))  # smaller prefix number == larger network

    allocations: list[PlanSubnetsAllocation] = []
    warnings: list[str] = []
    if avoid_all:
        warnings.append("Some ranges were excluded via 'avoid'.")

    for req in parsed:
        try:
            prefix = _req_prefix(req)
        except ValueError as e:
            allocations.append(
                PlanSubnetsAllocation(
                    vlan_id=str(req.vlan_id),
                    name=req.name,
                    requested_hosts=req.needed_hosts,
                    requested_prefix=req.desired_prefix,
                    allocated_cidr=None,
                    success=False,
                    notes=[str(e)],
                )
            )
            continue

        alloc, free = _allocate_from_free(free, prefix)
        if alloc is None:
            allocations.append(
                PlanSubnetsAllocation(
                    vlan_id=str(req.vlan_id),
                    name=req.name,
                    requested_hosts=req.needed_hosts,
                    requested_prefix=req.desired_prefix,
                    allocated_cidr=None,
                    success=False,
                    notes=["Not enough contiguous free space to allocate this VLAN."],
                )
            )
            warnings.append("Plan is too tight: at least one VLAN could not be allocated.")
            continue

        usable = _ipv4_usable_host_count(alloc)
        notes = []
        if req.needed_hosts is not None and usable < req.needed_hosts:
            notes.append(
                f"Allocated {alloc} has {usable} usable hosts, less than requested {req.needed_hosts}."
            )

        allocations.append(
            PlanSubnetsAllocation(
                vlan_id=str(req.vlan_id),
                name=req.name,
                requested_hosts=req.needed_hosts,
                requested_prefix=req.desired_prefix,
                allocated_cidr=str(alloc),
                success=True,
                notes=notes,
            )
        )

    # Remaining space: collapse and order.
    free_collapsed = [str(n) for n in ipaddress.collapse_addresses(free)]
    if len(free_collapsed) > 8:
        warnings.append(f"Fragmentation warning: {len(free_collapsed)} free blocks remain.")

    ok = all(a.success for a in allocations) and not errors
    summary = f"Allocated {sum(1 for a in allocations if a.success)}/{len(allocations)} VLANs from {parent}."
    return PlanSubnetsResult(
        success=ok,
        parent_cidr=str(parent),
        allocations=allocations,
        remaining=RemainingSpace(free_cidrs=free_collapsed),
        warnings=warnings,
        summary=summary,
    )
