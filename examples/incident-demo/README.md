# Intelligent Incident Response Demo

An AI agent that diagnoses network outages, not just alerts about them.

**Perfect for video demos and presentations.**

## Quick Start

```bash
cd examples/incident-demo
python demo.py
```

The demo runs automatically:
- 6 checks total (auto-stops)
- Waveform visualization pops up when alerts are spoken
- Generates a findings report at the end

## What Happens

| Check | State | Agent Action |
|-------|-------|--------------|
| 1-2 | UP | Establishes baseline |
| 3-4 | DOWN | Spawns diagnostic sub-agent, speaks alert |
| 5-6 | UP | Speaks recovery alert |
| End | - | Generates markdown findings report |

## Prerequisites

```bash
pip install strands-agents strands-agents-tools pygame
```

AWS credentials configured for:
- Amazon Bedrock (Claude Sonnet 4)
- Amazon Polly (neural TTS)

## Files

| File | Purpose |
|------|---------|
| `demo.py` | Main demo script (self-contained) |
| `speak_waveform.py` | Waveform visualization for spoken alerts |

## The Problem This Solves

Traditional monitoring:
```
Alert: 8.8.8.8 is unreachable
```

This demo:
```
Alert: Target is down. Traceroute fails at hop 3, the ISP gateway.
DNS is working. Other targets are reachable. This is an ISP routing
issue, not a local problem. Recommended: Contact ISP or wait for
auto-recovery.
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐
│  Monitor Agent  │────▶│ Diagnostic Agent │
│  (ping, alert)  │     │ (traceroute, DNS)│
└────────┬────────┘     └──────────────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│  Mock Tools     │     │   Amazon Polly   │
│  (demo data)    │     │  + Waveform Viz  │
└─────────────────┘     └──────────────────┘
```

## Business Value

- **Reduced MTTR** - Engineers get root cause, not just "it's down"
- **Better on-call** - Context before you even open your laptop
- **AI handles diagnostics** - Humans focus on fixing

## Video Recording Tips

1. **Window setup**: Position terminal and leave room for waveform popup
2. **Audio**: Ensure system volume is audible for Polly voice
3. **Timing**: Demo runs ~30 seconds with 5-second intervals
4. **Report**: Generated report makes good B-roll

## Customization

Edit `demo.py` to change:

```python
TARGET = "8.8.8.8"       # Target being monitored
MAX_CHECKS = 6           # Number of checks before auto-stop
CHECK_INTERVAL = 5       # Seconds between checks
DEMO_PATTERN = [True, True, False, False]  # UP/DOWN pattern
```

## Sample Output

```
============================================================
INTELLIGENT INCIDENT RESPONSE DEMO
============================================================
Target: 8.8.8.8
Checks: 6 (auto-stops after demo cycle)
Model: us.anthropic.claude-sonnet-4-20250514-v1:0

Demo will show:
  1. Normal monitoring (2 checks)
  2. Outage detection + automatic diagnostics
  3. Spoken alert with waveform visualization
  4. Recovery detection + spoken alert
  5. Findings report generated at end
============================================================

[Check #1] 8.8.8.8 is reachable. 4/4 packets, avg latency 15.2ms

[Check #2] 8.8.8.8 is reachable. 4/4 packets, avg latency 18.1ms

[Check #3] Target unreachable. Running diagnostics...
🔊 Speaking... [waveform popup appears]

[Check #4] Target still unreachable. No action (same state).

[Check #5] Target recovered!
🔊 Speaking... [waveform popup appears]

[Check #6] 8.8.8.8 is reachable. Monitoring continues.

============================================================
GENERATING FINDINGS REPORT...
============================================================
Report saved to: incident_report_20251219_143052.md

Demo complete!
```
