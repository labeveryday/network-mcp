"""Tests for configuration and security system."""

import os
import tempfile
from pathlib import Path

import yaml

from network_mcp.config import (
    Config,
    PcapConfig,
    SecurityConfig,
    _is_private_ip,
    _matches_pattern,
    load_config,
    validate_scapy_filter,
    validate_target,
)


class TestSecurityConfig:
    """Tests for SecurityConfig dataclass."""

    def test_default_config(self):
        """Test default security configuration."""
        config = SecurityConfig()
        assert config.allowed_targets == []
        assert config.block_private is False
        assert config.block_cloud_metadata is True
        assert "169.254.169.254" in config.blocked_targets

    def test_custom_config(self):
        """Test custom security configuration."""
        config = SecurityConfig(
            allowed_targets=["*.example.com"],
            blocked_targets=["bad.com"],
            block_private=True,
        )
        assert config.allowed_targets == ["*.example.com"]
        assert config.blocked_targets == ["bad.com"]
        assert config.block_private is True


class TestValidateTarget:
    """Tests for target validation."""

    def test_allow_public_ip(self):
        """Test that public IPs are allowed by default."""
        allowed, msg = validate_target("8.8.8.8")
        assert allowed is True
        assert msg is None

    def test_block_cloud_metadata(self):
        """Test blocking cloud metadata endpoints."""
        allowed, msg = validate_target("169.254.169.254")
        assert allowed is False
        assert "cloud metadata" in msg.lower()

    def test_block_gcp_metadata(self):
        """Test blocking GCP metadata."""
        allowed, msg = validate_target("metadata.google.internal")
        assert allowed is False

    def test_allow_hostname(self):
        """Test allowing valid hostnames."""
        allowed, msg = validate_target("google.com")
        assert allowed is True


class TestMatchesPattern:
    """Tests for pattern matching."""

    def test_exact_match(self):
        """Test exact IP match."""
        assert _matches_pattern("8.8.8.8", "8.8.8.8") is True
        assert _matches_pattern("8.8.8.8", "1.1.1.1") is False

    def test_cidr_match(self):
        """Test CIDR notation matching."""
        assert _matches_pattern("10.0.0.1", "10.0.0.0/8") is True
        assert _matches_pattern("192.168.1.1", "192.168.0.0/16") is True
        assert _matches_pattern("8.8.8.8", "10.0.0.0/8") is False

    def test_glob_match(self):
        """Test glob pattern matching."""
        assert _matches_pattern("test.example.com", "*.example.com") is True
        assert _matches_pattern("example.com", "*.example.com") is False
        assert _matches_pattern("sub.test.example.com", "*.example.com") is True


class TestIsPrivateIp:
    """Tests for private IP detection."""

    def test_private_ips(self):
        """Test detection of private IPs."""
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("127.0.0.1") is True

    def test_public_ips(self):
        """Test that public IPs are not flagged."""
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False
        assert _is_private_ip("142.250.80.46") is False


class TestValidateScapyFilter:
    """Tests for scapy filter validation."""

    def test_valid_filters(self):
        """Test valid filter expressions."""
        valid_filters = [
            "TCP in pkt",
            "UDP in pkt",
            "pkt[TCP].dport == 80",
            "pkt[IP].ttl < 64",
            "len(pkt) > 1000",
            "pkt.haslayer(TCP)",
            "pkt[TCP].sport == 443 and pkt[TCP].dport > 1024",
            "pkt[IP].src == '10.0.0.1'",
            "not pkt.haslayer(UDP)",
            # Bitwise ops (common for TCP flags)
            "pkt[TCP].flags & 0x02",
        ]
        for f in valid_filters:
            valid, msg = validate_scapy_filter(f)
            assert valid is True, f"Filter '{f}' should be valid: {msg}"

    def test_blocked_keywords(self):
        """Test that dangerous keywords are blocked."""
        dangerous_filters = [
            "import os",
            "exec('print(1)')",
            "eval('1+1')",
            "__import__('os')",
            "os.system('ls')",
            "subprocess.run(['ls'])",
        ]
        for f in dangerous_filters:
            valid, msg = validate_scapy_filter(f)
            assert valid is False, f"Filter '{f}' should be blocked"

    def test_blocked_scapy_functions(self):
        """Test that scapy send functions are blocked."""
        blocked = ["send(pkt)", "sendp(pkt)", "sr(pkt)", "sniff()"]
        for f in blocked:
            valid, msg = validate_scapy_filter(f)
            assert valid is False, f"Filter '{f}' should be blocked"

    def test_ast_validation_blocks_unsafe_operations(self):
        """Test that AST validation blocks unsafe operations."""
        unsafe_filters = [
            "().__class__.__mro__[1].__subclasses__()",  # Object traversal
            "getattr(pkt, 'dangerous')",  # getattr not allowed
            "pkt.__class__.__bases__",  # dunder attribute access
            "lambda x: x",  # lambda functions
            "open('/etc/passwd')",  # file operations
            "[x for x in range(10)]",  # list comprehensions
            "{x: 1 for x in [1,2,3]}",  # dict comprehensions
        ]
        for f in unsafe_filters:
            valid, msg = validate_scapy_filter(f)
            assert valid is False, f"Filter '{f}' should be blocked: {msg}"

    def test_ast_validation_blocks_unknown_names(self):
        """Test that AST validation blocks unknown identifiers."""
        # These use names that aren't in the allowed list
        invalid_filters = [
            "os.path.exists('/tmp')",
            "sys.exit()",
            "socket.socket()",
        ]
        for f in invalid_filters:
            valid, msg = validate_scapy_filter(f)
            assert valid is False, f"Filter '{f}' should be blocked: {msg}"

    def test_filter_length_limit(self):
        """Test that overly long filters are rejected."""
        long_filter = "pkt[TCP].dport == 80 and " * 100
        valid, msg = validate_scapy_filter(long_filter)
        assert valid is False
        assert "too long" in msg.lower()

    def test_ast_validation_allows_comparisons(self):
        """Test that various comparison operators work."""
        comparison_filters = [
            "pkt[TCP].dport == 80",
            "pkt[TCP].dport != 443",
            "pkt[IP].ttl < 64",
            "pkt[IP].ttl > 32",
            "pkt[IP].ttl <= 64",
            "pkt[IP].ttl >= 32",
            "TCP in pkt",
        ]
        for f in comparison_filters:
            valid, msg = validate_scapy_filter(f)
            assert valid is True, f"Filter '{f}' should be valid: {msg}"


class TestLoadConfig:
    """Tests for configuration loading."""

    def test_load_default_config(self):
        """Test loading default configuration."""
        config = Config()
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.pcap, PcapConfig)

    def test_load_from_yaml(self):
        """Test loading configuration from YAML file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.yaml"
            config_data = {
                "security": {
                    "allowed_targets": ["*.test.com"],
                    "block_private": True,
                },
                "pcap": {
                    "max_packets": 50000,
                },
            }
            with open(config_path, "w") as f:
                yaml.dump(config_data, f)

            config = load_config(config_path)
            assert config.security.allowed_targets == ["*.test.com"]
            assert config.security.block_private is True
            assert config.pcap.max_packets == 50000

    def test_env_override(self):
        """Test environment variable overrides."""
        original = os.environ.get("NETWORK_MCP_BLOCK_PRIVATE")
        try:
            os.environ["NETWORK_MCP_BLOCK_PRIVATE"] = "true"
            # Force reload
            import network_mcp.config as cfg

            cfg._config = None
            config = load_config()
            assert config.security.block_private is True
        finally:
            if original is None:
                os.environ.pop("NETWORK_MCP_BLOCK_PRIVATE", None)
            else:
                os.environ["NETWORK_MCP_BLOCK_PRIVATE"] = original
            cfg._config = None


class TestPcapConfig:
    """Tests for PcapConfig dataclass."""

    def test_default_pcap_config(self):
        """Test default pcap configuration."""
        config = PcapConfig()
        assert config.max_packets == 100000
        assert config.allow_custom_filters is True
        assert "send" in config.blocked_filter_keywords
        assert "import" in config.blocked_filter_keywords
