"""Tests for planning tools (pure CIDR/VLAN math)."""

from network_mcp.tools.planning import (
    check_overlaps,
    cidr_info,
    cidr_summarize,
    find_vlan_for_ip,
    ip_in_subnet,
    ip_in_vlan,
    plan_subnets,
    subnet_split,
    validate_vlan_map,
)


class TestCidrInfo:
    def test_ipv4_cidr_info(self):
        r = cidr_info("10.0.0.0/24")
        assert r.success is True
        assert r.cidr_normalized == "10.0.0.0/24"
        assert r.usable_host_addresses == 254
        assert r.first_usable == "10.0.0.1"
        assert r.last_usable == "10.0.0.254"
        assert r.netmask == "255.255.255.0"
        assert r.wildcard_mask == "0.0.0.255"

    def test_ipv6_cidr_info(self):
        r = cidr_info("2001:db8::/64")
        assert r.success is True
        assert r.ip_version == 6
        assert r.broadcast_address is None
        assert "IPv6" in r.summary


class TestIpInSubnet:
    def test_network_address_not_usable(self):
        r = ip_in_subnet("10.0.0.0", "10.0.0.0/24")
        assert r.success is True
        assert r.in_subnet is True
        assert r.is_usable_host is False
        assert r.reason_code == "IN_RANGE_NETWORK_ADDRESS"

    def test_broadcast_address_not_usable(self):
        r = ip_in_subnet("10.0.0.255", "10.0.0.0/24")
        assert r.success is True
        assert r.in_subnet is True
        assert r.is_usable_host is False
        assert r.reason_code == "IN_RANGE_BROADCAST_ADDRESS"

    def test_in_range_usable(self):
        r = ip_in_subnet("10.0.0.10", "10.0.0.0/24")
        assert r.success is True
        assert r.in_subnet is True
        assert r.is_usable_host is True
        assert r.reason_code == "IN_RANGE_USABLE"

    def test_ipv4_31_usable(self):
        r0 = ip_in_subnet("10.0.0.0", "10.0.0.0/31")
        r1 = ip_in_subnet("10.0.0.1", "10.0.0.0/31")
        assert r0.success is True and r1.success is True
        assert r0.is_usable_host is True
        assert r1.is_usable_host is True

    def test_out_of_range(self):
        r = ip_in_subnet("10.0.1.10", "10.0.0.0/24")
        assert r.success is True
        assert r.in_subnet is False
        assert r.reason_code == "OUT_OF_RANGE"


class TestSubnetSplit:
    def test_split_by_prefix(self):
        r = subnet_split("10.0.0.0/24", new_prefix=26)
        assert r.success is True
        assert r.child_prefix == 26
        assert r.count == 4
        assert r.subnets[0] == "10.0.0.0/26"

    def test_split_by_count_requires_pow2(self):
        r = subnet_split("10.0.0.0/24", count=3)
        assert r.success is False


class TestSummarizeAndOverlaps:
    def test_summarize_adjacent(self):
        r = cidr_summarize(["10.0.0.0/24", "10.0.1.0/24"])
        assert r.success is True
        assert r.ipv4.summarized == ["10.0.0.0/23"]

    def test_overlaps_detected(self):
        r = check_overlaps(["10.0.0.0/24", "10.0.0.0/25"])
        assert r.success is True
        assert len(r.overlaps) == 1
        assert r.overlaps[0].relationship in {"contains", "contained_by"}


class TestVlanTools:
    def test_validate_vlan_map_and_find(self):
        vlan_map = {
            "10": {"name": "Users", "cidr": "10.10.10.0/24"},
            "20": {"name": "Voice", "cidr": "10.10.20.0/24"},
        }
        v = validate_vlan_map(vlan_map)
        assert v.success is True
        assert v.vlan_count == 2

        m = find_vlan_for_ip("10.10.20.15", vlan_map)
        assert m.match_type == "ONE_MATCH"
        assert m.matches[0].vlan_id == "20"

    def test_vlan_map_shorthand_string(self):
        vlan_map = {
            "10": "192.168.10.0/24",
            "20": {"cidr": "192.168.20.0/24", "name": "Voice"},
        }
        v = validate_vlan_map(vlan_map)
        assert v.success is True

        r = ip_in_vlan("192.168.10.50", 10, vlan_map)
        assert r.success is True
        assert r.in_vlan is True

    def test_ip_in_vlan_best_guess(self):
        vlan_map = {
            "20": {"name": "Voice", "cidr": "10.10.20.0/24"},
            "50": {"name": "Printers", "cidr": "10.10.50.0/24"},
        }
        r = ip_in_vlan("10.10.50.12", "20", vlan_map)
        assert r.success is True
        assert r.in_vlan is False
        assert r.best_guess_vlan is not None
        assert r.best_guess_vlan.vlan_id == "50"


class TestPlanSubnets:
    def test_plan_subnets_basic(self):
        reqs = [
            {"vlan_id": 10, "name": "Users", "needed_hosts": 120},
            {"vlan_id": 20, "name": "Voice", "needed_hosts": 60},
            {"vlan_id": 30, "name": "Printers", "needed_hosts": 60},
            {"vlan_id": 40, "name": "Cameras", "needed_hosts": 30},
        ]
        r = plan_subnets("10.0.0.0/23", reqs)
        assert r.success is True
        assert len(r.allocations) == 4
        assert all(a.success for a in r.allocations)

        # Ensure allocations do not overlap
        allocated = [a.allocated_cidr for a in r.allocations if a.allocated_cidr]
        o = check_overlaps(allocated)  # type: ignore[arg-type]
        assert len(o.overlaps) == 0

    def test_plan_subnets_alias_hosts_and_prefix(self):
        reqs = [
            {"vlan_id": 10, "name": "Users", "hosts": 120},
            {"vlan_id": 20, "name": "Voice", "prefix": 26},
        ]
        r = plan_subnets("10.0.0.0/24", reqs)
        assert r.success is True
        assert all(a.success for a in r.allocations)

    def test_plan_subnets_with_avoid(self):
        reqs = [
            {"vlan_id": 10, "name": "Users", "needed_hosts": 120, "avoid": ["10.0.0.0/24"]},
        ]
        r = plan_subnets("10.0.0.0/23", reqs)
        assert r.success is True
        alloc = r.allocations[0].allocated_cidr
        assert alloc is not None
        # Should land in the other /24
        assert alloc.startswith("10.0.1.")

    def test_plan_subnets_friendly_validation_error(self):
        # Missing vlan_id; should return a short warning with an example.
        r = plan_subnets("10.0.0.0/24", [{"name": "Mgmt", "hosts": 50}])
        assert r.success is False
        assert any("Example requirement" in w for w in r.warnings)
