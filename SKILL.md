---
name: btsnoop-analyzer
description: Analyze Bluetooth btsnoop/HCI traces using the btsnoop-analyzer pipeline. Runs detection, filtering, annotation, and diagnostics scripts, then performs LLM analysis using the agent's own capabilities.
license: LGPL-2.1
compatibility: opencode
metadata:
  audience: bluetooth-developers
  workflow: debugging
---

## What I do

I analyze Bluetooth btsnoop trace files using the btsnoop-analyzer pipeline.
The pipeline runs four deterministic analysis steps via Python scripts, then
I perform the final diagnostic analysis myself — no external LLM API keys
needed.

## When to use me

Use this skill when:
- You have a btsnoop log file and need to understand what happened
- A Bluetooth connection is failing and you need to diagnose why
- You need to verify GATT service/characteristic discovery
- Audio streaming (LE Audio or A2DP) is not working correctly
- Pairing or bonding is failing
- You need to understand the sequence of HCI events in a trace

## Usage with AI Coding Assistants

This file can be used as custom instructions for several AI coding
assistants. Each client has its own mechanism for loading project-level
instructions.

### OpenCode

Load the skill on-demand inside a session:

```
/skill btsnoop-analyzer
```

Or register it in your `opencode.json` configuration:

```json
{
  "skills": {
    "btsnoop-analyzer": {
      "path": "/path/to/btsnoop-analyzer/SKILL.md"
    }
  }
}
```

Then load it in any session with `/skill btsnoop-analyzer`.

### Claude Code

Claude Code reads `CLAUDE.md` files automatically. A symlink is
provided at the repository root:

```
CLAUDE.md -> SKILL.md
```

Claude Code will include the instructions in every conversation started
from this project directory. You can also reference it from an existing
`CLAUDE.md` using an import:

```markdown
@SKILL.md
```

### GitHub Copilot

Copilot reads instructions from `.github/copilot-instructions.md` and
`AGENTS.md` files. Both are provided as symlinks:

```
AGENTS.md                       -> SKILL.md
.github/copilot-instructions.md -> SKILL.md
```

The instructions are included automatically in Copilot Chat and Copilot
agent mode (VS Code, CLI).

### Cursor

Cursor reads project rules from `.cursor/rules/`. A symlink is provided:

```
.cursor/rules/btsnoop-analyzer.md -> SKILL.md
```

The rule uses `agent_requested` activation, so Cursor loads it when
trace analysis is relevant to the conversation.

### Windsurf

Windsurf reads workspace rules from `.windsurf/rules/` and also
supports `AGENTS.md`. Both are provided as symlinks:

```
.windsurf/rules/btsnoop-analyzer.md -> SKILL.md
AGENTS.md                           -> SKILL.md
```

The workspace rule uses `model_decision` activation.

### Typical session

Once the instructions are loaded (by any client), provide a btsnoop
trace and the agent will walk through the full pipeline:

```
Analyze this trace: /tmp/btsnoop_hci.log
```

The agent decodes the trace, runs detection, annotation, filtering, and
diagnostics, then writes the final diagnostic report itself.

## Prerequisites

- `btmon` must be installed (from BlueZ) or built from source
- Python 3 with no additional dependencies (scripts use stdlib only)
- The btsnoop-analyzer repository (this repo) checked out locally

## Pipeline Overview

The analysis runs a 5-step pipeline. See [ARCHITECTURE.md](ARCHITECTURE.md)
for the full architecture, pipeline diagram, annotator hierarchy, and
file map.

| Step | Script | Output | Documentation |
|------|--------|--------|---------------|
| 1 | `detect.py` | `detect.md` | [doc/step1-detection.md](doc/step1-detection.md) |
| 2 | `prefilter.py` | `filter.md` | [doc/step2-prefilter.md](doc/step2-prefilter.md) |
| 3 | `annotate.py` | `annotate.md` | [doc/step3-annotation.md](doc/step3-annotation.md) |
| 4 | `diagnose.py` | `diagnose.md` | [doc/step4-diagnostics.md](doc/step4-diagnostics.md) |
| 5 | LLM (you) | `analyze.md` | [doc/step5-analysis.md](doc/step5-analysis.md) |

The JSON rule system driving detection, annotation, and diagnostics is
documented in [rules/RULES.md](rules/RULES.md).

## Workflow

### Step 0: Decode the trace

First, decode the btsnoop trace file with btmon:

```sh
btmon -T -r /path/to/trace.log > /tmp/decoded.txt
```

Only add `-I` if you need to debug codec frames (isochronous data).
Otherwise avoid it — it generates large volumes of data that must be
filtered out:

```sh
btmon -T -I -r /path/to/trace.log > /tmp/decoded.txt
```

Similarly, `-A`/`--a2dp` and `-S`/`--sco` decode A2DP and SCO audio
traffic respectively. Only use them when audio data itself needs
inspection — they add significant volume otherwise:

```sh
btmon -T -A -r /path/to/trace.log > /tmp/decoded.txt   # A2DP audio
btmon -T -S -r /path/to/trace.log > /tmp/decoded.txt   # SCO audio
```

Optionally get summary statistics:

```sh
btmon -a /path/to/trace.log
```

If the user wants MAC addresses anonymized:

```sh
scripts/anonymize.sh < /tmp/decoded.txt > /tmp/decoded-anon.txt
```

### Step 1: Detection

Auto-detect the protocol area of interest by scanning the trace for
protocol-specific patterns:

```sh
python3 scripts/detect.py < /tmp/decoded.txt
```

This prints detected areas with scores. Areas with errors are flagged.
The highest-scoring area with errors is typically the right focus area.

Read the output to determine the focus area. Map it to one of these
canonical focus strings:

- `Connection issues`
- `Controller enumeration`
- `Pairing / Security`
- `GATT discovery`
- `Audio / LE Audio`
- `Audio / A2DP`
- `Audio / HFP`
- `L2CAP channel issues`
- `Advertising / Scanning`
- `Disconnection analysis`
- `Channel Sounding`

### Step 2-4: Annotation, Filtering, and Diagnostics

Run the annotator with the detected focus area:

```sh
python3 scripts/annotate.py --focus "FOCUS_AREA" < /tmp/decoded.txt
```

This produces three outputs to stderr:
- **Filter** (Step 2): Packet counts, time span, budget usage
- **Annotation** (Step 3): Key Frames table with semantic tags
- **Diagnostics** (Step 4): Absence warnings, stream summaries, state tables

Read all three outputs carefully. They contain the deterministic analysis
that informs the final diagnostic report.

### Alternative: Full pipeline with output files

For convenience, you can run the full pipeline (steps 1-4) using
`analyze.py` without an LLM provider. This writes per-step markdown
files to an output directory:

```sh
mkdir -p /tmp/results

python3 scripts/analyze.py \
    --trace-url "file:///path/to/trace.log" \
    --description "USER_DESCRIPTION" \
    --focus "FOCUS_OR_GENERAL" \
    --btmon-path btmon \
    --docs-path /path/to/bluez/doc/btmon.rst \
    --output-dir /tmp/results \
    --provider github
```

Note: Step 5 (LLM analysis) will fail without API keys, but that is
expected — steps 1-4 will still complete and write their output files.

See [README.md](README.md) for local usage examples and GitHub Action
configuration.

### Step 5: Analysis (you are the LLM)

After running steps 1-4, you have all the information needed to produce
the diagnostic report yourself. Read the step outputs and the relevant
btmon protocol documentation, then write the analysis.

Load the focus-specific documentation from the BlueZ repository. The
full mapping of focus areas to documentation files is in
[doc/step5-analysis.md](doc/step5-analysis.md). Quick reference:

| Focus Area | Documentation File |
|---|---|
| Connection issues | `doc/btmon-connections.rst` |
| Controller enumeration | `doc/btmon-hci-init.rst` |
| Pairing / Security | `doc/btmon-smp.rst` |
| GATT discovery | `doc/btmon-gatt.rst` |
| Audio / LE Audio | `doc/btmon-le-audio.rst` |
| Audio / A2DP | `doc/btmon-a2dp.rst` (included in `btmon-classic-audio.rst`) |
| Audio / HFP | `doc/btmon-hfp.rst` (included in `btmon-classic-audio.rst`) |
| L2CAP channel issues | `doc/btmon-l2cap.rst` |
| Advertising / Scanning | `doc/btmon-advertising.rst` |
| Disconnection analysis | `doc/btmon-connections.rst` |
| Channel Sounding | `doc/btmon-cs.rst` |

Also read `doc/debugging.rst` (and its includes `doc/debugging-failures.rst`,
`doc/debugging-cross-layer.rst`) for failure patterns and cross-layer
correlation techniques.

Structure your analysis report as:

```markdown
## Diagnostic Report

| Field | Value |
|-------|-------|
| **Focus area** | <detected or user-specified area> |
| **Auto-detected** | Yes/No |
| **Verdict** | PASS / FAIL / INCONCLUSIVE |

> **One-line summary:** <what happened in one sentence>

### Event Timeline

| # | Timestamp | Event | Details |
|--:|----------:|-------|---------|
| <frame> | <time> | <event> | <details> |

### Issues Found

1. **<Issue title>** (Frame #N, <timestamp>)
   - <description with specific handle values, opcodes, error codes>
   - <root cause explanation>

### Recommendations

- <actionable debugging suggestions>
```

**Verdict definitions:**
- **PASS**: All operations succeed, streaming completes normally,
  connection ends with graceful disconnect (reason 0x13 or 0x16)
- **FAIL**: Actual errors, rejects, unexpected disconnections, or
  protocol violations found
- **INCONCLUSIVE**: Trace is incomplete or ambiguous

**Important rules:**
- Reference actual handle values, opcodes, error codes, and frame
  numbers from the trace
- `Attribute Not Found (0x0a)` during GATT discovery is normal, not
  an error
- Normal ISO/CIS data streaming volume is expected for LE Audio
- Graceful disconnects (reason 0x13, 0x16) are not failures
- Cross-reference annotations from Step 3 with raw trace using frame
  numbers
- Check absence warnings from Step 4 as likely root causes

## Output format reference

Quick reference for reading btmon output:

| Prefix | Meaning |
|--------|---------|
| `<` | Host → Controller (HCI commands, ACL/SCO/ISO data TX) |
| `>` | Controller → Host (HCI events, ACL/SCO/ISO data RX) |
| `@` | Management interface traffic (kernel ↔ userspace) |
| `=` | System notes (open/close/index events) |

Right-side metadata format:
```
#N [hciX] HH:MM:SS.UUUUUU
```
Where N = frame number, hciX = controller index, timestamp = microsecond
precision.

## Important notes

- Always anonymize MAC addresses in reports (use `00:11:22:33:44:55` format)
- Frame numbers (`#N`) are stable identifiers; use them when referencing events
- For LE Audio, you **must** use `-I` flag to see isochronous data
  (only needed when debugging codec frames; omit otherwise to reduce noise)
