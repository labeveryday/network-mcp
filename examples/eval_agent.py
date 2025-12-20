"""
Network MCP Tool Evaluation Script

Evaluates how well a model can use the Network MCP tools by running
a series of prompts and capturing tool usage and responses.

Usage:
    python eval_agent.py --model qwen3:4b
    python eval_agent.py --model llama3.2:3b --output results.md

Prerequisites:
- pip install strands-agents 'strands-agents[ollama]'
- ollama installed and running
- model pulled: ollama pull <model_id>
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

from mcp import StdioServerParameters, stdio_client
from strands import Agent
from strands.hooks import HookProvider, HookRegistry
from strands.hooks.events import AfterToolCallEvent
from strands.models.ollama import OllamaModel
from strands.tools.mcp import MCPClient


# =============================================================================
# TOOL TRACKING HOOK
# =============================================================================


class ToolTracker(HookProvider):
    """Hook provider that tracks tool calls during agent execution."""

    def __init__(self):
        self.tool_calls = []

    def register_hooks(self, registry: HookRegistry) -> None:
        registry.add_callback(AfterToolCallEvent, self.after_tool)

    def after_tool(self, event: AfterToolCallEvent) -> None:
        """Called after each tool execution."""
        tool_name = event.tool_use.get("name", "unknown")
        tool_input = event.tool_use.get("input", {})
        self.tool_calls.append({"tool": tool_name, "input": tool_input})

    def clear(self):
        """Clear tracked tool calls."""
        self.tool_calls = []

    def get_tool_names(self) -> list[str]:
        """Get list of tool names that were called."""
        return [tc["tool"] for tc in self.tool_calls]

# =============================================================================
# EVALUATION PROMPTS
# =============================================================================
# Each prompt targets specific tool(s). Keep prompts unambiguous.
# Organized by tool category.

EVAL_PROMPTS = [
    # -------------------------------------------------------------------------
    # CAPABILITIES (1 tool)
    # -------------------------------------------------------------------------
    {
        "name": "capabilities",
        "prompt": "What tools and capabilities are available on this system? Use the capabilities tool.",
        "expected_tools": ["capabilities"],
        "category": "capabilities",
    },
    # -------------------------------------------------------------------------
    # CONNECTIVITY TOOLS (5 tools)
    # -------------------------------------------------------------------------
    {
        "name": "ping",
        "prompt": "Ping 8.8.8.8 and tell me the average latency.",
        "expected_tools": ["ping"],
        "category": "connectivity",
    },
    {
        "name": "dns_lookup_a",
        "prompt": "Look up the DNS A records for google.com.",
        "expected_tools": ["dns_lookup"],
        "category": "connectivity",
    },
    {
        "name": "dns_lookup_mx",
        "prompt": "What are the MX records for gmail.com?",
        "expected_tools": ["dns_lookup"],
        "category": "connectivity",
    },
    {
        "name": "dns_lookup_reverse",
        "prompt": "Do a reverse DNS lookup for 8.8.8.8.",
        "expected_tools": ["dns_lookup"],
        "category": "connectivity",
    },
    {
        "name": "port_check_https",
        "prompt": "Check if port 443 is open on google.com.",
        "expected_tools": ["port_check"],
        "category": "connectivity",
    },
    {
        "name": "port_check_ssh",
        "prompt": "Is SSH port 22 open on github.com?",
        "expected_tools": ["port_check"],
        "category": "connectivity",
    },
    {
        "name": "traceroute",
        "prompt": "Run a traceroute to 1.1.1.1 and show me the path.",
        "expected_tools": ["traceroute"],
        "category": "connectivity",
    },
    {
        "name": "mtr",
        "prompt": "Run an MTR to 8.8.8.8 to analyze the network path with statistics.",
        "expected_tools": ["mtr"],
        "category": "connectivity",
    },
    # -------------------------------------------------------------------------
    # BATCH OPERATIONS (3 tools)
    # -------------------------------------------------------------------------
    {
        "name": "batch_ping",
        "prompt": "Ping 8.8.8.8, 1.1.1.1, and 9.9.9.9 concurrently.",
        "expected_tools": ["batch_ping"],
        "category": "batch",
    },
    {
        "name": "batch_port_check",
        "prompt": "Check if ports 80, 443, and 8080 are open on google.com.",
        "expected_tools": ["batch_port_check"],
        "category": "batch",
    },
    {
        "name": "batch_dns_lookup",
        "prompt": "Look up DNS records for google.com, github.com, and cloudflare.com at the same time.",
        "expected_tools": ["batch_dns_lookup"],
        "category": "batch",
    },
    # -------------------------------------------------------------------------
    # LOCAL NETWORK INFO (5 tools)
    # -------------------------------------------------------------------------
    {
        "name": "get_interfaces",
        "prompt": "List all network interfaces on this machine with their IP addresses.",
        "expected_tools": ["get_interfaces"],
        "category": "local",
    },
    {
        "name": "get_routes",
        "prompt": "Show me the routing table for this system.",
        "expected_tools": ["get_routes"],
        "category": "local",
    },
    {
        "name": "get_dns_config",
        "prompt": "What DNS servers is this system configured to use?",
        "expected_tools": ["get_dns_config"],
        "category": "local",
    },
    {
        "name": "get_arp_table",
        "prompt": "Show me the ARP table with IP to MAC address mappings.",
        "expected_tools": ["get_arp_table"],
        "category": "local",
    },
    {
        "name": "get_connections",
        "prompt": "List all active network connections on this system.",
        "expected_tools": ["get_connections"],
        "category": "local",
    },
    # -------------------------------------------------------------------------
    # EXTERNAL INTEL (2 tools)
    # -------------------------------------------------------------------------
    {
        "name": "rdap_lookup_ip",
        "prompt": "Look up RDAP/WHOIS information for the IP 1.1.1.1.",
        "expected_tools": ["rdap_lookup"],
        "category": "external_intel",
    },
    {
        "name": "rdap_lookup_domain",
        "prompt": "Get RDAP registration info for the domain cloudflare.com.",
        "expected_tools": ["rdap_lookup"],
        "category": "external_intel",
    },
    {
        "name": "asn_lookup",
        "prompt": "What ASN does the IP 8.8.8.8 belong to?",
        "expected_tools": ["asn_lookup"],
        "category": "external_intel",
    },
    {
        "name": "asn_lookup_cloudflare",
        "prompt": "Find the ASN and network information for 1.1.1.1.",
        "expected_tools": ["asn_lookup"],
        "category": "external_intel",
    },
    # -------------------------------------------------------------------------
    # PLANNING TOOLS - CIDR/Subnet (9 tools)
    # -------------------------------------------------------------------------
    {
        "name": "cidr_info",
        "prompt": "Give me information about the CIDR block 192.168.1.0/24 including network address, broadcast, and usable hosts.",
        "expected_tools": ["cidr_info"],
        "category": "planning",
    },
    {
        "name": "ip_in_subnet",
        "prompt": "Is the IP 192.168.1.50 within the subnet 192.168.1.0/24?",
        "expected_tools": ["ip_in_subnet"],
        "category": "planning",
    },
    {
        "name": "subnet_split",
        "prompt": "Split the network 10.0.0.0/16 into /24 subnets. Show me the first few.",
        "expected_tools": ["subnet_split"],
        "category": "planning",
    },
    {
        "name": "cidr_summarize",
        "prompt": "Summarize these subnets into the smallest CIDR blocks: 192.168.0.0/24, 192.168.1.0/24, 192.168.2.0/24, 192.168.3.0/24.",
        "expected_tools": ["cidr_summarize"],
        "category": "planning",
    },
    {
        "name": "check_overlaps",
        "prompt": "Check if these subnets overlap: 10.0.0.0/16, 10.0.1.0/24, 192.168.0.0/24.",
        "expected_tools": ["check_overlaps"],
        "category": "planning",
    },
    {
        "name": "plan_subnets",
        "prompt": "Plan subnets for 10.0.0.0/16 with these requirements: 50 hosts for servers, 200 hosts for clients, 10 hosts for management.",
        "expected_tools": ["plan_subnets"],
        "category": "planning",
    },
    {
        "name": "validate_vlan_map",
        "prompt": "Validate this VLAN map for overlaps: VLAN 10 is 192.168.10.0/24, VLAN 20 is 192.168.20.0/24, VLAN 30 is 192.168.10.0/25.",
        "expected_tools": ["validate_vlan_map"],
        "category": "planning",
    },
    {
        "name": "ip_in_vlan",
        "prompt": "Given VLAN 10 is 192.168.10.0/24 and VLAN 20 is 192.168.20.0/24, is the IP 192.168.10.50 in VLAN 10?",
        "expected_tools": ["ip_in_vlan"],
        "category": "planning",
    },
    {
        "name": "find_vlan_for_ip",
        "prompt": "Given VLAN 10 is 192.168.10.0/24 and VLAN 20 is 192.168.20.0/24, which VLAN does 192.168.20.100 belong to?",
        "expected_tools": ["find_vlan_for_ip"],
        "category": "planning",
    },
    # -------------------------------------------------------------------------
    # PCAP ANALYSIS (8 tools) - Require pcap file, skipped by default
    # -------------------------------------------------------------------------
    {
        "name": "pcap_summary",
        "prompt": "Analyze the pcap file at /tmp/test.pcap and give me a summary.",
        "expected_tools": ["pcap_summary"],
        "category": "pcap",
        "requires_file": True,
    },
    {
        "name": "get_conversations",
        "prompt": "Show me the network conversations in /tmp/test.pcap.",
        "expected_tools": ["get_conversations"],
        "category": "pcap",
        "requires_file": True,
    },
    {
        "name": "analyze_throughput",
        "prompt": "Analyze the throughput in the pcap file /tmp/test.pcap.",
        "expected_tools": ["analyze_throughput"],
        "category": "pcap",
        "requires_file": True,
    },
    {
        "name": "find_tcp_issues",
        "prompt": "Find any TCP issues like retransmissions or resets in /tmp/test.pcap.",
        "expected_tools": ["find_tcp_issues"],
        "category": "pcap",
        "requires_file": True,
    },
    {
        "name": "analyze_dns_traffic",
        "prompt": "Analyze DNS traffic in the pcap file /tmp/test.pcap.",
        "expected_tools": ["analyze_dns_traffic"],
        "category": "pcap",
        "requires_file": True,
    },
    {
        "name": "filter_packets",
        "prompt": "Filter packets from /tmp/test.pcap to show only traffic on port 443.",
        "expected_tools": ["filter_packets"],
        "category": "pcap",
        "requires_file": True,
    },
    {
        "name": "get_protocol_hierarchy",
        "prompt": "Show the protocol hierarchy breakdown for /tmp/test.pcap.",
        "expected_tools": ["get_protocol_hierarchy"],
        "category": "pcap",
        "requires_file": True,
    },
    {
        "name": "custom_scapy_filter",
        "prompt": "Run a custom scapy filter on /tmp/test.pcap to find all ICMP packets.",
        "expected_tools": ["custom_scapy_filter"],
        "category": "pcap",
        "requires_file": True,
    },
]


# =============================================================================
# SYSTEM PROMPT
# =============================================================================

SYSTEM_PROMPT = """
You are a Network Diagnostic Specialist. Use your available tools to answer questions.

Rules:
1. Use the appropriate tool to answer each question.
2. Be concise in your response.
3. Report the key findings from the tool output.
""".strip()


# =============================================================================
# HELPERS
# =============================================================================


def get_prompts(
    categories: list[str] | None = None,
    include_pcap: bool = False,
) -> list[dict]:
    """Filter evaluation prompts by category and pcap requirement."""
    prompts = EVAL_PROMPTS

    # Filter out pcap tests unless explicitly included
    if not include_pcap:
        prompts = [p for p in prompts if not p.get("requires_file", False)]

    # Filter by category if specified
    if categories:
        prompts = [p for p in prompts if p.get("category") in categories]

    return prompts


def run_eval(
    model_id: str,
    host: str = "http://localhost:11434",
    categories: list[str] | None = None,
    include_pcap: bool = False,
    debug: bool = False,
) -> list[dict]:
    """Run evaluation prompts and collect results."""
    results = []
    prompts = get_prompts(categories, include_pcap)

    if not prompts:
        print("No prompts to run with current filters.")
        return results

    # Create MCP client
    network_mcp_client = MCPClient(
        lambda: stdio_client(
            StdioServerParameters(
                command="uvx",
                args=["network-mcp"],
            )
        )
    )

    model = OllamaModel(
        host=host,
        model_id=model_id,
        max_tokens=8192,  # Increased for thinking models
        temperature=0.1,  # Low temp for deterministic tool use
    )

    # Create tool tracker hook
    tool_tracker = ToolTracker()

    with network_mcp_client:
        mcp_tools = network_mcp_client.list_tools_sync()

        for i, eval_item in enumerate(prompts, 1):
            print(f"[{i}/{len(prompts)}] Running: {eval_item['name']}...")

            # Clear tracker for each prompt
            tool_tracker.clear()

            # Fresh agent per prompt with tool tracking hook
            agent = Agent(
                model=model,
                system_prompt=SYSTEM_PROMPT,
                tools=mcp_tools,
                hooks=[tool_tracker],
            )

            try:
                # Run the prompt
                result = agent(eval_item["prompt"])

                # Get tool calls from the hook tracker
                tool_calls = tool_tracker.tool_calls.copy()
                tools_used = tool_tracker.get_tool_names()

                # Debug output
                if debug:
                    print(f"    DEBUG: Hook tracked {len(tool_calls)} tool calls: {tools_used}")

                # Check if expected tools were called
                expected = set(eval_item["expected_tools"])
                actual = set(tools_used)
                passed = bool(expected & actual)  # At least one expected tool called

                results.append(
                    {
                        "name": eval_item["name"],
                        "category": eval_item.get("category", "unknown"),
                        "prompt": eval_item["prompt"],
                        "expected_tools": eval_item["expected_tools"],
                        "tools_called": tool_calls,
                        "tools_used": tools_used,
                        "passed": passed,
                        "response": str(result),
                        "error": None,
                    }
                )

                status = "PASS" if passed else "FAIL"
                print(f"    {status} - Tools used: {tools_used}")

            except Exception as e:
                results.append(
                    {
                        "name": eval_item["name"],
                        "category": eval_item.get("category", "unknown"),
                        "prompt": eval_item["prompt"],
                        "expected_tools": eval_item["expected_tools"],
                        "tools_called": [],
                        "tools_used": [],
                        "passed": False,
                        "response": None,
                        "error": str(e),
                    }
                )
                print(f"    ERROR - {e}")

    return results


def generate_report(results: list[dict], model_id: str) -> str:
    """Generate a markdown report from evaluation results."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    pass_rate = (100 * passed // total) if total > 0 else 0

    # Group results by category
    categories = {}
    for r in results:
        cat = r.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(r)

    # Build category summary
    cat_summary = []
    for cat, cat_results in categories.items():
        cat_passed = sum(1 for r in cat_results if r["passed"])
        cat_total = len(cat_results)
        cat_summary.append(f"  - **{cat}**: {cat_passed}/{cat_total}")

    lines = [
        "# Network MCP Evaluation Report",
        "",
        f"**Model:** `{model_id}`",
        f"**Date:** {timestamp}",
        f"**Results:** {passed}/{total} passed ({pass_rate}%)",
        "",
        "## Summary by Category",
        "",
        *cat_summary,
        "",
        "---",
        "",
    ]

    # Output results grouped by category
    for cat, cat_results in categories.items():
        cat_passed = sum(1 for r in cat_results if r["passed"])
        cat_total = len(cat_results)
        lines.append(f"# {cat.upper()} ({cat_passed}/{cat_total})")
        lines.append("")

        for r in cat_results:
            status = "PASS" if r["passed"] else "FAIL"
            emoji = "\u2705" if r["passed"] else "\u274c"

            lines.append(f"## {emoji} {r['name']} ({status})")
            lines.append("")
            lines.append(f"**Prompt:** {r['prompt']}")
            lines.append("")
            lines.append(f"**Expected tools:** `{', '.join(r['expected_tools'])}`")
            lines.append("")
            lines.append(f"**Tools called:** `{', '.join(r['tools_used']) or 'None'}`")
            lines.append("")

            if r["tools_called"]:
                lines.append("**Tool calls:**")
                lines.append("```json")
                lines.append(json.dumps(r["tools_called"], indent=2))
                lines.append("```")
                lines.append("")

            if r["error"]:
                lines.append(f"**Error:** `{r['error']}`")
                lines.append("")
            elif r["response"]:
                lines.append("**Response:**")
                lines.append("")
                # Truncate long responses
                response = r["response"]
                if len(response) > 1000:
                    response = response[:1000] + "... (truncated)"
                lines.append(response)
                lines.append("")

            lines.append("---")
            lines.append("")

    return "\n".join(lines)


# =============================================================================
# MAIN
# =============================================================================

CATEGORIES = [
    "capabilities",
    "connectivity",
    "batch",
    "local",
    "external_intel",
    "planning",
    "pcap",
]


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate model performance on Network MCP tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python eval_agent.py --model qwen3:4b
  python eval_agent.py --model llama3.2:3b --category connectivity
  python eval_agent.py --model mistral --category planning local
  python eval_agent.py --model qwen3:4b --include-pcap --pcap-file /tmp/capture.pcap

Categories: {", ".join(CATEGORIES)}
        """,
    )
    parser.add_argument(
        "--model",
        type=str,
        default="qwen3:4b-thinking-2507-q4_K_M",
        help="Ollama model ID (default: qwen3:4b)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="http://localhost:11434",
        help="Ollama host URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: eval_<model>_<timestamp>.md)",
    )
    parser.add_argument(
        "--category",
        type=str,
        nargs="+",
        choices=CATEGORIES,
        default=None,
        help="Run only specific categories (default: all except pcap)",
    )
    parser.add_argument(
        "--include-pcap",
        action="store_true",
        help="Include pcap analysis tests (requires --pcap-file)",
    )
    parser.add_argument(
        "--pcap-file",
        type=str,
        default="/tmp/test.pcap",
        help="Path to pcap file for pcap tests (default: /tmp/test.pcap)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available evaluation prompts and exit",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debug info about message structure",
    )
    args = parser.parse_args()

    # List mode
    if args.list:
        prompts = get_prompts(args.category, args.include_pcap)
        print(f"Available prompts ({len(prompts)}):\n")
        for p in prompts:
            req = " [requires file]" if p.get("requires_file") else ""
            print(f"  [{p['category']}] {p['name']}{req}")
        return

    # Update pcap file path in prompts if specified
    if args.include_pcap and args.pcap_file != "/tmp/test.pcap":
        for p in EVAL_PROMPTS:
            if p.get("requires_file"):
                p["prompt"] = p["prompt"].replace("/tmp/test.pcap", args.pcap_file)

    print("Network MCP Tool Evaluation")
    print(f"Model: {args.model}")
    if args.category:
        print(f"Categories: {', '.join(args.category)}")
    print("-" * 60)

    results = run_eval(
        args.model,
        args.host,
        categories=args.category,
        include_pcap=args.include_pcap,
        debug=args.debug,
    )

    if not results:
        print("No results to report.")
        return

    print("-" * 60)

    # Generate report
    report = generate_report(results, args.model)

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_model = args.model.replace(":", "_").replace("/", "_")
        output_path = Path(f"eval_{safe_model}_{timestamp}.md")

    output_path.write_text(report)
    print(f"Report saved to: {output_path}")

    # Summary
    passed = sum(1 for r in results if r["passed"])
    print(f"Results: {passed}/{len(results)} passed")


if __name__ == "__main__":
    main()
