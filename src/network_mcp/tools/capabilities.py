"""Runtime capabilities / dependency introspection.

This is designed for MCP clients (including smaller local models) to decide which
tools to call and what fallbacks to use.
"""

import platform
import shutil

from network_mcp import __version__
from network_mcp.config import get_config
from network_mcp.models.responses import CapabilitiesResult, DependencyStatus


def _dep(name: str, executable: str, note: str | None = None) -> DependencyStatus:
    path = shutil.which(executable)
    return DependencyStatus(name=name, available=path is not None, path=path, note=note)


def capabilities() -> CapabilitiesResult:
    cfg = get_config()

    deps = [
        _dep("ping", "ping", note="Required for ping tool (OS built-in on most systems)"),
        _dep("traceroute", "traceroute", note="Required for traceroute tool (Linux/macOS)"),
        _dep("tracert", "tracert", note="Required for traceroute tool (Windows)"),
        _dep("mtr", "mtr", note="Optional (used by mtr tool)."),
    ]

    sec = {
        "allowed_targets_configured": bool(cfg.security.allowed_targets),
        "allowed_targets_count": len(cfg.security.allowed_targets),
        "blocked_targets_count": len(cfg.security.blocked_targets),
        "block_private": cfg.security.block_private,
        "block_cloud_metadata": cfg.security.block_cloud_metadata,
    }

    pcap = {
        "max_packets": cfg.pcap.max_packets,
        "allow_custom_filters": cfg.pcap.allow_custom_filters,
        "allowed_paths": cfg.pcap.allowed_paths,
    }

    mtr_ok = next((d.available for d in deps if d.name == "mtr"), False)
    summary = f"network-mcp {__version__} on {platform.system().lower()} (Python {platform.python_version()}). "
    summary += "mtr available." if mtr_ok else "mtr not installed (mtr tool will use fallbacks)."

    return CapabilitiesResult(
        success=True,
        server_version=__version__,
        platform=platform.system().lower(),
        python_version=platform.python_version(),
        dependencies=deps,
        security=sec,
        pcap=pcap,
        summary=summary,
    )
