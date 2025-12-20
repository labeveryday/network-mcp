# Network MCP Examples

Examples showing how to use the Network MCP server with AI agents.

## Prerequisites

### For Ollama Examples

1. **Install Ollama**: https://ollama.com/download

2. **Pull a model**:
   ```bash
   ollama pull qwen3:8b
   ```

3. **Install dependencies**:
   ```bash
   pip install strands-agents strands-agents-tools 'strands-agents[ollama]'
   ```

### For Bedrock Examples

1. **AWS credentials configured**:
   ```bash
   aws configure
   ```

2. **Model access enabled** in Amazon Bedrock console

3. **Install dependencies**:
   ```bash
   pip install strands-agents strands-agents-tools
   ```

> **Note:** The `incident-demo/` requires additional dependencies: `pip install pygame`

### Common

Install network-mcp:
```bash
pip install network-mcp
```

## Examples

### 1. Interactive Agent (`ollama_agent.py`)

A chat-based network diagnostic agent using Ollama. Ask questions and it will use the appropriate tools.

```bash
python ollama_agent.py
```

**Commands:**
- `/exit` or `/quit` - Exit the agent
- `/model` - Show current model config
- `/tools` - List available tools

**Example prompts:**
```
> Ping 8.8.8.8
> What's my public IP?
> Check if port 443 is open on github.com
> Show my network interfaces
```

### 2. Incident Response Demo (`incident-demo/`)

An AI agent that diagnoses network outages, not just alerts about them. Perfect for video demos - self-contained, auto-stops, includes waveform visualization for spoken alerts.

```bash
cd incident-demo
python demo.py
```

Demo shows:
1. Normal monitoring (2 checks)
2. Outage detection + automatic diagnostics
3. Spoken alert with waveform visualization
4. Recovery detection
5. Generates a findings report

See [`incident-demo/README.md`](incident-demo/README.md) for full documentation.

### 3. Evaluation Script (`eval_agent.py`)

Test how well different Ollama models use the network tools. Uses Strands Agents hooks to track tool calls.

**Basic usage:**
```bash
python eval_agent.py --model qwen3:8b
```

**Test specific categories:**
```bash
python eval_agent.py --model qwen3:8b --category connectivity
python eval_agent.py --model qwen3:8b --category planning local
```

**Debug mode (shows tool tracking):**
```bash
python eval_agent.py --model qwen3:8b --debug --category local
```

**List available tests:**
```bash
python eval_agent.py --list
```

**Output:** Generates a markdown report like `eval_qwen3_8b_20251219_143022.md`

## Tool Categories

| Category | Description | Example Tools |
|----------|-------------|---------------|
| `capabilities` | System capabilities check | capabilities |
| `connectivity` | Network reachability tests | ping, dns_lookup, port_check, traceroute, mtr |
| `batch` | Concurrent operations | batch_ping, batch_port_check, batch_dns_lookup |
| `local` | Local network info | get_interfaces, get_routes, get_dns_config |
| `external_intel` | IP/domain intelligence | rdap_lookup, asn_lookup |
| `planning` | Subnet/CIDR planning | cidr_info, subnet_split, plan_subnets |
| `pcap` | Packet capture analysis | pcap_summary, find_tcp_issues, analyze_throughput |

## Tested Models

| Model | Size | Tool Calling |
|-------|------|--------------|
| `qwen3:8b` | 8B | Good |
| `qwen3:4b` | 4B | Basic |
| `llama3.1:8b` | 8B | Basic |

Run the eval script to test your preferred model.

## Troubleshooting

**"Connection refused" error:**
- Make sure Ollama is running: `ollama serve`

**"Model not found" error:**
- Pull the model first: `ollama pull <model_id>`

**Tools not being called:**
- Smaller models may struggle with tool selection when many tools are available
- Try a larger model or use the `--debug` flag to see what's happening
- The eval script uses hooks to reliably track tool calls

**Pcap tests failing:**
- Ensure the pcap file exists and is readable
- Check that the path is in the allowed pcap paths (see main README)
