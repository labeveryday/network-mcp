#!/usr/bin/env python3
"""
Intelligent Incident Response Demo

A self-contained demo showcasing an AI agent that:
1. Monitors network connectivity
2. Automatically diagnoses outages (not just alerts)
3. Speaks findings with waveform visualization
4. Generates a findings report

Perfect for video demos and presentations.

Usage:
    python incident_demo.py

The demo runs 6 checks automatically:
    Check 1-2: UP (baseline)
    Check 3-4: DOWN (triggers diagnostics + spoken alert)
    Check 5-6: UP (recovery alert)

Then generates a findings report.

Prerequisites:
    pip install strands-agents strands-agents-tools pygame
    AWS credentials configured (for Bedrock and Polly)
"""

import random
import time
from datetime import datetime

from speak_waveform import create_speak_tool
from strands import Agent, tool
from strands.models import BedrockModel
from strands_tools import editor, use_agent

# =============================================================================
# CONFIGURATION
# =============================================================================

TARGET = "8.8.8.8"
MAX_CHECKS = 6
CHECK_INTERVAL = 5  # seconds
MODEL_ID = "us.anthropic.claude-sonnet-4-20250514-v1:0"

# Demo pattern: True=UP, False=DOWN
# 2 UP → 2 DOWN → UP forever
DEMO_PATTERN = [True, True, False, False]


# =============================================================================
# MOCK NETWORK TOOLS
# =============================================================================


class DemoState:
    """Tracks demo state across tool calls."""

    ping_count = 0
    events = []  # Timeline of events
    diagnostics = None  # Diagnostic findings
    alerts = []  # Spoken alerts


def get_demo_state(check_num: int) -> bool:
    """Returns True if network should be UP for this check."""
    if check_num <= len(DEMO_PATTERN):
        return DEMO_PATTERN[check_num - 1]
    return True  # UP after pattern ends


@tool
def ping(target: str, count: int = 4) -> dict:
    """Ping a target host to check connectivity."""
    DemoState.ping_count += 1
    is_up = get_demo_state(DemoState.ping_count)

    if not is_up:
        return {
            "success": False,
            "target": target,
            "error": "Request timeout - no response from host",
            "packets_sent": count,
            "packets_received": 0,
            "packet_loss_percent": 100.0,
            "summary": f"Target {target} is unreachable. 0/{count} packets received.",
        }

    avg_latency = round(random.uniform(12.0, 22.0), 1)
    return {
        "success": True,
        "target": target,
        "resolved_ip": target,
        "packets_sent": count,
        "packets_received": count,
        "packet_loss_percent": 0.0,
        "avg_latency_ms": avg_latency,
        "summary": f"{target} is reachable. {count}/{count} packets, avg latency {avg_latency}ms",
    }


@tool
def traceroute(target: str, max_hops: int = 30) -> dict:
    """Trace the network path to a target."""
    return {
        "success": True,
        "target": target,
        "hops": [
            {"hop": 1, "ip": "192.168.1.1", "hostname": "router.local", "latency_ms": 1.2},
            {"hop": 2, "ip": "10.0.0.1", "hostname": "gateway.isp.net", "latency_ms": 8.5},
            {
                "hop": 3,
                "ip": "72.14.215.85",
                "hostname": "isp-core-router.net",
                "latency_ms": None,
                "status": "timeout",
            },
            {"hop": 4, "ip": "*", "hostname": "*", "status": "no response"},
            {"hop": 5, "ip": "*", "hostname": "*", "status": "no response"},
        ],
        "completed": False,
        "summary": f"Traceroute to {target} failed. Path dies at hop 3 (72.14.215.85 - isp-core-router.net). Likely ISP routing issue.",
    }


@tool
def dns_lookup(hostname: str, record_type: str = "A") -> dict:
    """Look up DNS records for a hostname."""
    return {
        "success": True,
        "hostname": hostname,
        "record_type": record_type,
        "records": ["142.250.80.46", "142.250.80.47"],
        "ttl": 300,
        "summary": f"DNS lookup successful. {hostname} resolves to 142.250.80.46",
    }


@tool
def get_interfaces() -> dict:
    """Get local network interface information."""
    return {
        "success": True,
        "interfaces": [
            {"name": "en0", "status": "up", "ipv4": "192.168.1.100", "mac": "a1:b2:c3:d4:e5:f6"},
            {"name": "lo0", "status": "up", "ipv4": "127.0.0.1"},
        ],
        "summary": "2 interfaces active. Primary: en0 (192.168.1.100) - status UP",
    }


@tool
def get_routes() -> dict:
    """Get routing table information."""
    return {
        "success": True,
        "routes": [
            {"destination": "default", "gateway": "192.168.1.1", "interface": "en0"},
            {"destination": "192.168.1.0/24", "gateway": "link", "interface": "en0"},
        ],
        "default_gateway": "192.168.1.1",
        "summary": "Default gateway: 192.168.1.1 via en0. Routing table looks healthy.",
    }


# =============================================================================
# AGENT PROMPTS
# =============================================================================

MONITOR_PROMPT = """
You are a Network Monitor Agent. Your job is to monitor network connectivity and coordinate incident response when issues are detected.

## Your Tools
- ping: Test connectivity to the primary target
- use_agent: Spawn a diagnostic sub-agent when issues are detected
- speak: Announce alerts using Amazon Polly (with waveform visualization)

## Your Workflow

### On Each Check:
1. Ping the target
2. Determine if the state changed (UP→DOWN or DOWN→UP)

### When State Changes to DOWN:
1. Spawn a diagnostic agent using use_agent with this prompt:
   "Run network diagnostics for {target}. Execute these checks:
   1. traceroute to {target} - find where the path fails
   2. dns_lookup for google.com - verify DNS is working
   3. ping 1.1.1.1 - check if other targets are reachable
   4. get_interfaces - check local network interfaces
   5. get_routes - check routing table
   Analyze the results and provide a brief diagnostic summary."

2. After receiving the diagnostic summary, speak a BRIEF alert (2-3 sentences max):
   - State the target is DOWN
   - Key finding (where it fails)
   - Likely cause

### When State Changes to UP:
1. Speak a brief recovery alert: "Network restored. {target} is now reachable."

### When State Unchanged:
- Just report briefly in text, no speech needed

## Important Rules
- Only speak on STATE CHANGES
- Keep spoken alerts BRIEF (under 15 seconds of speech)
- Be concise in text responses
""".strip()


# =============================================================================
# MAIN DEMO
# =============================================================================


def run_demo():
    """Run the incident response demo."""
    print("=" * 60)
    print("INTELLIGENT INCIDENT RESPONSE DEMO")
    print("=" * 60)
    print(f"Target: {TARGET}")
    print(f"Checks: {MAX_CHECKS} (auto-stops after demo cycle)")
    print(f"Model: {MODEL_ID}")
    print()
    print("Demo will show:")
    print("  1. Normal monitoring (2 checks)")
    print("  2. Outage detection + automatic diagnostics")
    print("  3. Spoken alert with waveform visualization")
    print("  4. Recovery detection + spoken alert")
    print("  5. Findings report generated at end")
    print("=" * 60)
    print()

    # Create tools
    speak = create_speak_tool()
    network_tools = [ping, traceroute, dns_lookup, get_interfaces, get_routes]

    # Create model
    model = BedrockModel(
        model_id=MODEL_ID,
        temperature=0.1,
        max_tokens=2048,
    )

    # State tracking
    last_state = None
    start_time = datetime.now()

    for check_num in range(1, MAX_CHECKS + 1):
        print(f"\n[Check #{check_num}] ", end="", flush=True)

        # Build state context
        if last_state is None:
            state_ctx = "This is the first check. No previous state."
        elif last_state:
            state_ctx = "Previous state: UP (target was reachable)"
        else:
            state_ctx = "Previous state: DOWN (target was unreachable)"

        prompt = f"""
Check #{check_num}: Monitor {TARGET}

{state_ctx}

1. Ping {TARGET}
2. If state changed to DOWN: spawn diagnostic agent, then speak BRIEF alert
3. If state changed to UP: speak brief recovery alert
4. If state unchanged: just report briefly (no speech)
"""

        # Create fresh agent for this check
        agent = Agent(
            model=model,
            system_prompt=MONITOR_PROMPT.format(target=TARGET),
            tools=[speak, use_agent] + network_tools,
        )

        try:
            result = agent(prompt)
            response_text = str(result).lower()

            # Determine new state
            if (
                "unreachable" in response_text
                or "down" in response_text
                or "failed" in response_text
                or "timeout" in response_text
            ):
                new_state = False
            elif (
                "reachable" in response_text or "success" in response_text or "up" in response_text
            ):
                new_state = True
            else:
                new_state = last_state

            # Record event
            state_label = "UP" if new_state else "DOWN"
            changed = last_state is not None and new_state != last_state

            event = {
                "check": check_num,
                "state": state_label,
                "changed": changed,
                "time": datetime.now().strftime("%H:%M:%S"),
            }

            if changed and not new_state:
                event["action"] = "Diagnostics triggered, alert spoken"
                DemoState.diagnostics = {
                    "failure_point": "Hop 3 (72.14.215.85 - isp-core-router.net)",
                    "dns_status": "Working",
                    "other_targets": "Reachable",
                    "local_network": "Healthy",
                    "root_cause": "ISP routing issue",
                }
            elif changed and new_state:
                event["action"] = "Recovery alert spoken"
            else:
                event["action"] = "Monitoring (no state change)"

            DemoState.events.append(event)
            last_state = new_state
            print()

        except Exception as e:
            print(f"Error: {e}")
            DemoState.events.append(
                {
                    "check": check_num,
                    "state": "ERROR",
                    "changed": False,
                    "action": str(e),
                    "time": datetime.now().strftime("%H:%M:%S"),
                }
            )

        # Wait between checks (except for last one)
        if check_num < MAX_CHECKS:
            time.sleep(CHECK_INTERVAL)

    # Generate findings report
    print("\n" + "=" * 60)
    print("GENERATING FINDINGS REPORT...")
    print("=" * 60)

    end_time = datetime.now()
    duration = (end_time - start_time).seconds

    generate_report(start_time, end_time, duration)


def generate_report(start_time, end_time, duration):
    """Generate findings report using strands editor tool."""

    # Build timeline table
    timeline_rows = []
    for event in DemoState.events:
        timeline_rows.append(
            f"| {event['check']} | {event['time']} | {event['state']} | "
            f"{'Yes' if event['changed'] else 'No'} | {event['action']} |"
        )
    timeline_table = "\n".join(timeline_rows)

    # Build diagnostics section
    if DemoState.diagnostics:
        diag = DemoState.diagnostics
        diagnostics_section = f"""## Diagnostic Findings

When the outage was detected, the agent automatically ran comprehensive diagnostics:

| Check | Result |
|-------|--------|
| Traceroute | Failed at {diag["failure_point"]} |
| DNS Resolution | {diag["dns_status"]} |
| Alternate Targets | {diag["other_targets"]} |
| Local Network | {diag["local_network"]} |

**Root Cause Analysis:** {diag["root_cause"]}

**Recommended Actions:**
1. Contact ISP - Report the routing failure at the identified hop
2. Wait and retry - ISP routing issues often resolve within 15-30 minutes
3. Check ISP status page - Look for reported outages in your area
"""
    else:
        diagnostics_section = "## Diagnostic Findings\n\nNo outage detected during this demo run."

    report_content = f"""# Incident Response Demo Report

**Generated:** {end_time.strftime("%Y-%m-%d %H:%M:%S")}
**Target:** {TARGET}
**Duration:** {MAX_CHECKS} checks over {duration} seconds

## Executive Summary

This demo showcases an AI-powered incident response agent that goes beyond simple "up/down" alerts.
When an outage is detected, the agent automatically:

1. Spawns a diagnostic sub-agent to investigate
2. Runs traceroute, DNS, and connectivity checks
3. Analyzes findings to determine root cause
4. Speaks a contextual alert with actionable information

## Timeline

| Check | Time | State | Changed | Action |
|-------|------|-------|---------|--------|
{timeline_table}

{diagnostics_section}

## Key Takeaways

- **Reduced MTTR:** Engineers get root cause analysis, not just "it's down"
- **Automated Diagnostics:** AI runs the troubleshooting playbook automatically
- **Actionable Alerts:** Spoken alerts include specific findings and recommendations
- **Multi-Agent Architecture:** Monitor agent orchestrates diagnostic sub-agent

## Architecture

```
┌─────────────────┐     ┌──────────────────┐
│  Monitor Agent  │────▶│ Diagnostic Agent │
│  (ping, alert)  │     │ (traceroute, DNS)│
└────────┬────────┘     └──────────────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  Network MCP    │     │   Amazon Polly   │
│  (30+ tools)    │     │  (Neural Voice)  │
└─────────────────┘     └──────────────────┘
```

---
*Generated by Intelligent Incident Response Demo*
"""

    # Write report using editor tool
    report_filename = f"incident_report_{end_time.strftime('%Y%m%d_%H%M%S')}.md"

    # Create agent just for writing the report
    model = BedrockModel(model_id=MODEL_ID, temperature=0.1, max_tokens=1024)
    writer_agent = Agent(
        model=model,
        system_prompt="You are a report writer. Use the editor tool to save the report.",
        tools=[editor],
    )

    writer_agent(f"Save this report to '{report_filename}':\n\n{report_content}")

    print(f"\nReport saved to: {report_filename}")
    print("\nDemo complete!")


if __name__ == "__main__":
    run_demo()
