"""
MCP Network Diagnostic Specialist Agent Example
This example shows how to use the Network MCP Server with an Ollama model.
Usage:
    cd examples
    python ollama_agent.py

Prerequisites:
- pip install strands-agents strands-agents-tools 'strands-agents[ollama]'
- ollama installed: https://ollama.com/download
- model loaded: ollama pull qwen3:4b-thinking-2507-q4_K_M
NOTE: You can use other models, but you need to change the model in the code.
"""

from pprint import pprint

from mcp import StdioServerParameters, stdio_client
from strands import Agent
from strands.models.ollama import OllamaModel
from strands.tools.mcp import MCPClient
from strands_tools import current_time, editor

# =============================================================================
# AGENT CONFIGURATION
# =============================================================================

SYSTEM_PROMPT = """
You are a Network Diagnostic Specialist. Your goal is to troubleshoot network connectivity and analyze traffic using your available tools.

# OPERATIONAL RULES
1. THINK FIRST: Before calling any tool, explain your reasoning in a <thinking> block. Identify which tool is most efficient for the next step.
2. STEP-BY-STEP: Perform one action at a time. Wait for tool results before proposing further tests.
3. PREFER EFFICIENCY: Use 'capabilities' first to see available system tools. Use 'batch' tools when checking multiple targets to save time.
4. BE PRECISE: Use exact IPs and hostnames. If a tool fails, analyze the error before retrying.

# DIAGNOSTIC WORKFLOW
- Connectivity Issues: Start with 'ping' or 'batch_ping'. If packets are lost, use 'mtr' or 'traceroute' to find the failure hop.
- DNS Issues: Use 'dns_lookup' or 'batch_dns_lookup' to verify resolution.
- Service Issues: Use 'port_check' to verify if a daemon is listening.
- Local Health: Use 'get_interfaces', 'get_routes', and 'get_connections' to check the local environment.
- Traffic Analysis: When analyzing PCAPs, use 'pcap_summary' first, then 'find_tcp_issues' for specific performance bottlenecks.

# OUTPUT FORMAT
- All reasoning must be in <thinking> blocks.
- Tool calls must follow the standard MCP format.
- Summarize results clearly for the user after tools provide data.
""".strip()

# =============================================================================
# MODEL SELECTION
# =============================================================================

MODEL = OllamaModel(
    host="http://localhost:11434",
    model_id="qwen3:4b-thinking-2507-q4_K_M",  # https://ollama.com/library/qwen3:4b-thinking-2507-q4_K_M
    max_tokens=64000,
    temperature=0.3,
)


# =============================================================================
# MCP CLIENTS
# =============================================================================

network_mcp_client = MCPClient(
    lambda: stdio_client(
        StdioServerParameters(
            command="uvx",
            args=["network-mcp"],
            autoApprove=[
                "capabilities",
            ],
        )
    )
)

# =============================================================================
# MAIN
# =============================================================================

print("Welcome to the Network Diagnostic Specialist!")
print("-" * 60)
print("Commands: /exit, /quit, /model, /tools")
print("-" * 60 + "\n")

if __name__ == "__main__":
    with network_mcp_client:
        # Get tools from MCP servers
        mcp_tools = network_mcp_client.list_tools_sync()

        agent = Agent(
            model=MODEL,
            system_prompt=SYSTEM_PROMPT,
            tools=[editor, current_time] + mcp_tools,
        )

        while True:
            try:
                prompt = input("> ")
            except (KeyboardInterrupt, EOFError):
                print("\n")
                break

            if not prompt.strip():
                continue

            if prompt in ("/exit", "/quit"):
                print("Exiting...")
                print("-" * 60)
                print("Thank you for using the Network Diagnostic Specialist!")
                print("-" * 60)
                print("Agent Metrics: ")
                pprint(agent.event_loop_metrics)
                break

            if prompt == "/model":
                print(f"Model: {agent.model.config}")
                continue

            if prompt == "/tools":
                print("Tools: ")
                pprint(agent.tool_names)
                continue

            print("Agent Response: ", end="")
            agent(prompt)
            print("\n")
