"""Configuration system with allowlist/blocklist for target validation.

Supports loading from:
1. config.yaml in current directory
2. ~/.network-mcp/config.yaml
3. Environment variables (NETWORK_MCP_*)

Example config.yaml:
```yaml
security:
  # Targets that are allowed (if specified, only these are allowed)
  allowed_targets:
    - "*.company.com"
    - "10.0.0.0/8"
    - "192.168.0.0/16"
    - "8.8.8.8"
    - "1.1.1.1"

  # Targets that are blocked (checked after allowlist)
  blocked_targets:
    - "*.gov"
    - "*.mil"
    - "localhost"
    - "127.0.0.0/8"

  # Block private IPs by default (can be overridden)
  block_private: false

  # Block requests to cloud metadata endpoints
  block_cloud_metadata: true

pcap:
  # Maximum packets to analyze
  max_packets: 100000

  # Allow custom scapy filter expressions
  allow_custom_filters: true

  # Restricted scapy operations (for custom filters)
  blocked_filter_keywords:
    - "send"
    - "sendp"
    - "sr"
    - "srp"
    - "sniff"
```
"""

import fnmatch
import ipaddress
import os
import re
import socket
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class SecurityConfig:
    """Security configuration for target validation."""

    allowed_targets: list[str] = field(default_factory=list)
    blocked_targets: list[str] = field(
        default_factory=lambda: [
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",  # GCP metadata
            "100.100.100.200",  # Alibaba metadata
        ]
    )
    block_private: bool = False
    block_cloud_metadata: bool = True


@dataclass
class PcapConfig:
    """Pcap analysis configuration."""

    max_packets: int = 100000
    allow_custom_filters: bool = True
    # If set, pcap file access is restricted to these directories (after path resolution).
    # Defaults are intentionally conservative for shared/runtime deployments.
    allowed_paths: list[str] = field(
        # Include common temp locations across platforms; macOS often resolves /tmp -> /private/tmp.
        default_factory=lambda: [
            str(Path.cwd()),
            tempfile.gettempdir(),
            "/tmp",
            "/private/tmp",
            # Common local-user locations (keeps workflow ergonomic without requiring /tmp copies)
            str(Path.home() / "Documents"),
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
        ],
    )
    blocked_filter_keywords: list[str] = field(
        default_factory=lambda: [
            "send",
            "sendp",
            "sr",
            "srp",
            "sr1",
            "srp1",
            "srloop",
            "srploop",
            "sniff",
            "bridge_and_sniff",
            "sendpfast",
            "import",
            "exec",
            "eval",
            "compile",
            "__",
            "os.",
            "subprocess",
            "system",
        ]
    )


@dataclass
class Config:
    """Main configuration container."""

    security: SecurityConfig = field(default_factory=SecurityConfig)
    pcap: PcapConfig = field(default_factory=PcapConfig)


# Global config instance
_config: Config | None = None


def _find_config_file() -> Path | None:
    """Find config file in standard locations."""
    locations = [
        Path.cwd() / "config.yaml",
        Path.cwd() / "network-mcp.yaml",
        Path.home() / ".network-mcp" / "config.yaml",
        Path.home() / ".config" / "network-mcp" / "config.yaml",
    ]

    for path in locations:
        if path.exists():
            return path
    return None


def _load_from_env(config: Config) -> None:
    """Override config from environment variables."""
    # NETWORK_MCP_ALLOWED_TARGETS=*.company.com,10.0.0.0/8
    if allowed := os.environ.get("NETWORK_MCP_ALLOWED_TARGETS"):
        config.security.allowed_targets = [t.strip() for t in allowed.split(",")]

    # NETWORK_MCP_BLOCKED_TARGETS=*.gov,*.mil
    if blocked := os.environ.get("NETWORK_MCP_BLOCKED_TARGETS"):
        config.security.blocked_targets = [t.strip() for t in blocked.split(",")]

    # NETWORK_MCP_BLOCK_PRIVATE=true
    if block_private := os.environ.get("NETWORK_MCP_BLOCK_PRIVATE"):
        config.security.block_private = block_private.lower() in ("true", "1", "yes")

    # NETWORK_MCP_MAX_PACKETS=50000
    if max_packets := os.environ.get("NETWORK_MCP_MAX_PACKETS"):
        config.pcap.max_packets = int(max_packets)

    # NETWORK_MCP_ALLOW_CUSTOM_FILTERS=false
    if allow_filters := os.environ.get("NETWORK_MCP_ALLOW_CUSTOM_FILTERS"):
        config.pcap.allow_custom_filters = allow_filters.lower() in ("true", "1", "yes")

    # NETWORK_MCP_PCAP_ALLOWED_PATHS=/tmp,/captures
    if allowed_paths := os.environ.get("NETWORK_MCP_PCAP_ALLOWED_PATHS"):
        config.pcap.allowed_paths = [p.strip() for p in allowed_paths.split(",") if p.strip()]


def load_config(config_path: Path | str | None = None) -> Config:
    """Load configuration from file and environment."""
    global _config

    config = Config()

    # Find config file
    if config_path:
        path = Path(config_path)
    else:
        path = _find_config_file()

    # Load from YAML if found
    if path and path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        if "security" in data:
            sec = data["security"]
            if "allowed_targets" in sec:
                config.security.allowed_targets = sec["allowed_targets"]
            if "blocked_targets" in sec:
                config.security.blocked_targets = sec["blocked_targets"]
            if "block_private" in sec:
                config.security.block_private = sec["block_private"]
            if "block_cloud_metadata" in sec:
                config.security.block_cloud_metadata = sec["block_cloud_metadata"]

        if "pcap" in data:
            pcap = data["pcap"]
            if "max_packets" in pcap:
                config.pcap.max_packets = pcap["max_packets"]
            if "allow_custom_filters" in pcap:
                config.pcap.allow_custom_filters = pcap["allow_custom_filters"]
            if "allowed_paths" in pcap:
                config.pcap.allowed_paths = pcap["allowed_paths"]
            if "blocked_filter_keywords" in pcap:
                config.pcap.blocked_filter_keywords = pcap["blocked_filter_keywords"]

    # Override with environment variables
    _load_from_env(config)

    _config = config
    return config


def get_config() -> Config:
    """Get current configuration, loading if necessary."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _resolve_to_ip(target: str) -> str | None:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _matches_pattern(target: str, pattern: str) -> bool:
    """Check if target matches a pattern (glob, CIDR, or exact)."""
    # Check CIDR notation
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            # Try target as IP directly
            try:
                target_ip = ipaddress.ip_address(target)
                return target_ip in network
            except ValueError:
                # Target is hostname, resolve it
                resolved = _resolve_to_ip(target)
                if resolved:
                    return ipaddress.ip_address(resolved) in network
                return False
        except ValueError:
            pass

    # Check glob pattern (for hostnames)
    if fnmatch.fnmatch(target.lower(), pattern.lower()):
        return True

    # Check exact match
    if target.lower() == pattern.lower():
        return True

    return False


def validate_target(target: str) -> tuple[bool, str | None]:
    """Validate a target against allowlist/blocklist.

    Returns:
        (is_allowed, error_message)
        - (True, None) if target is allowed
        - (False, "reason") if target is blocked
    """
    config = get_config()

    # Check cloud metadata endpoints first (highest priority block)
    if config.security.block_cloud_metadata:
        cloud_metadata = [
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.goog",
            "100.100.100.200",
        ]
        for endpoint in cloud_metadata:
            if target.lower() == endpoint.lower() or target == endpoint:
                return False, f"Access to cloud metadata endpoint '{target}' is blocked"

    # Resolve hostname to check IP-based rules
    resolved_ip = None
    try:
        socket.inet_aton(target)
        resolved_ip = target
    except socket.error:
        resolved_ip = _resolve_to_ip(target)

    # Check private IP blocking
    if config.security.block_private and resolved_ip:
        if _is_private_ip(resolved_ip):
            return False, f"Access to private IP '{target}' ({resolved_ip}) is blocked"

    # Check allowlist (if configured, ONLY these are allowed)
    if config.security.allowed_targets:
        allowed = False
        for pattern in config.security.allowed_targets:
            if _matches_pattern(target, pattern):
                allowed = True
                break
            # Also check resolved IP against patterns
            if resolved_ip and _matches_pattern(resolved_ip, pattern):
                allowed = True
                break

        if not allowed:
            return False, f"Target '{target}' is not in the allowlist"

    # Check blocklist
    for pattern in config.security.blocked_targets:
        if _matches_pattern(target, pattern):
            return False, f"Target '{target}' matches blocked pattern '{pattern}'"
        # Also check resolved IP
        if resolved_ip and _matches_pattern(resolved_ip, pattern):
            return False, f"Target '{target}' resolves to blocked IP matching '{pattern}'"

    return True, None


def _validate_ast_safety(filter_expr: str) -> tuple[bool, str | None]:
    """Validate filter expression using AST to ensure only safe operations.

    Only allows:
    - Name nodes (identifiers like TCP, pkt, IP, etc.)
    - Attribute access (pkt.haslayer, pkt[TCP].sport)
    - Subscript access (pkt[TCP])
    - Comparisons (==, !=, <, >, <=, >=, in, not in)
    - Boolean operations (and, or, not)
    - Numbers and strings (literals)
    - Call nodes (limited to known safe methods)

    Returns:
        (is_safe, error_message)
    """
    import ast

    # Max expression length to prevent DoS
    MAX_EXPR_LENGTH = 500
    if len(filter_expr) > MAX_EXPR_LENGTH:
        return False, f"Filter expression too long (max {MAX_EXPR_LENGTH} chars)"

    try:
        tree = ast.parse(filter_expr, mode="eval")
    except SyntaxError as e:
        return False, f"Invalid syntax: {e}"

    # Allowed identifier names
    allowed_names = {
        "TCP",
        "UDP",
        "IP",
        "ICMP",
        "DNS",
        "DNSQR",
        "DNSRR",
        "ARP",
        "Ether",
        "pkt",
        "packet",
        "True",
        "False",
        "None",
        "len",
    }

    # Allowed method names for call nodes
    allowed_methods = {"haslayer", "getlayer"}

    # Allowed attributes
    allowed_attrs = {
        "src",
        "dst",
        "sport",
        "dport",
        "flags",
        "proto",
        "type",
        "ttl",
        "len",
        "id",
        "seq",
        "ack",
        "window",
        "chksum",
        "payload",
        "qname",
        "qtype",
        "rdata",
        "qr",
        "opcode",
        "rcode",
        "haslayer",
        "getlayer",
    }

    def check_node(node) -> tuple[bool, str | None]:
        """Recursively check each AST node for safety."""
        if isinstance(node, ast.Expression):
            return check_node(node.body)

        elif isinstance(node, ast.BoolOp):
            # and, or
            for value in node.values:
                ok, err = check_node(value)
                if not ok:
                    return False, err
            return True, None

        elif isinstance(node, ast.UnaryOp):
            # not, -, +
            if isinstance(node.op, (ast.Not, ast.UAdd, ast.USub)):
                return check_node(node.operand)
            return False, f"Disallowed unary operator: {type(node.op).__name__}"

        elif isinstance(node, ast.BinOp):
            # Restrict binary operators to safe numeric / bitwise operations.
            allowed_ops = (
                ast.Add,
                ast.Sub,
                ast.Mult,
                ast.Div,
                ast.Mod,
                ast.BitAnd,
                ast.BitOr,
                ast.BitXor,
                ast.LShift,
                ast.RShift,
            )
            if not isinstance(node.op, allowed_ops):
                return False, f"Disallowed binary operator: {type(node.op).__name__}"
            ok1, err1 = check_node(node.left)
            if not ok1:
                return False, err1
            ok2, err2 = check_node(node.right)
            if not ok2:
                return False, err2
            return True, None

        elif isinstance(node, ast.Compare):
            # ==, !=, <, >, <=, >=, in, not in
            ok, err = check_node(node.left)
            if not ok:
                return False, err
            for comparator in node.comparators:
                ok, err = check_node(comparator)
                if not ok:
                    return False, err
            return True, None

        elif isinstance(node, ast.Name):
            if node.id in allowed_names:
                return True, None
            return False, f"Disallowed name: '{node.id}'"

        elif isinstance(node, ast.Attribute):
            if node.attr not in allowed_attrs:
                return False, f"Disallowed attribute: '{node.attr}'"
            return check_node(node.value)

        elif isinstance(node, ast.Subscript):
            ok, err = check_node(node.value)
            if not ok:
                return False, err
            return check_node(node.slice)

        elif isinstance(node, ast.Call):
            # Only allow specific safe function calls
            if isinstance(node.func, ast.Attribute):
                if node.func.attr not in allowed_methods:
                    return False, f"Disallowed method call: '{node.func.attr}'"
                ok, err = check_node(node.func.value)
                if not ok:
                    return False, err
            elif isinstance(node.func, ast.Name):
                if node.func.id not in {"len"}:
                    return False, f"Disallowed function call: '{node.func.id}'"
            else:
                return False, "Complex function calls not allowed"

            for arg in node.args:
                ok, err = check_node(arg)
                if not ok:
                    return False, err
            return True, None

        elif isinstance(node, ast.Constant):
            # Literals: numbers, strings, booleans
            if isinstance(node.value, (int, float, str, bool, type(None))):
                return True, None
            return False, f"Disallowed literal type: {type(node.value).__name__}"

        else:
            return False, f"Disallowed expression type: {type(node).__name__}"

    return check_node(tree)


def validate_scapy_filter(filter_expr: str) -> tuple[bool, str | None]:
    """Validate a scapy filter expression for safety.

    Uses multiple layers of validation:
    1. Configuration check (custom filters enabled)
    2. Keyword blocklist
    3. Suspicious pattern detection
    4. AST-based safety validation

    Returns:
        (is_allowed, error_message)
    """
    config = get_config()

    if not config.pcap.allow_custom_filters:
        return False, "Custom scapy filters are disabled in configuration"

    # Check for blocked keywords (using word boundaries to avoid false positives)
    filter_lower = filter_expr.lower()
    for keyword in config.pcap.blocked_filter_keywords:
        # Use word boundary matching to avoid matching substrings like 'src' matching 'sr'
        pattern = r"\b" + re.escape(keyword.lower()) + r"\b"
        if re.search(pattern, filter_lower):
            return False, f"Filter contains blocked keyword: '{keyword}'"

    # Check for suspicious patterns
    suspicious_patterns = [
        r"__\w+__",  # Dunder methods
        r"lambda\s*:",  # Lambda functions
        r"\bopen\s*\(",  # File operations
        r"\bread\s*\(",
        r"\bwrite\s*\(",
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, filter_expr):
            return False, f"Filter contains suspicious pattern: '{pattern}'"

    # AST-based validation for additional safety
    is_safe, error = _validate_ast_safety(filter_expr)
    if not is_safe:
        return False, f"Filter failed safety check: {error}"

    return True, None


def validate_pcap_file_path(file_path: str) -> tuple[bool, str | None, str | None]:
    """Validate a pcap file path against configured allowlist directories.

    Returns:
        (is_allowed, resolved_path, error_message)
    """
    config = get_config()
    try:
        path = Path(file_path).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        else:
            path = path.resolve()
    except Exception as e:
        return False, None, f"Invalid path '{file_path}': {e}"

    allowed_dirs = [p for p in (config.pcap.allowed_paths or []) if p]
    if not allowed_dirs:
        return True, str(path), None

    for allowed in allowed_dirs:
        try:
            base = Path(allowed).expanduser().resolve()
        except Exception:
            continue

        try:
            path.relative_to(base)
            return True, str(path), None
        except ValueError:
            continue

    return (
        False,
        str(path),
        f"PCAP path '{path}' is outside allowed directories: {', '.join(allowed_dirs)}",
    )
