# Architecture

This document describes the 5-step analysis pipeline from issue
submission to posted diagnostic report.

## Pipeline Overview

```
 Issue opened          Workflow trigger         Build btmon
 (trace + desc) ──────> analyze-trace.yml ──────> bluez/monitor/btmon
                                                       │
                         ┌─────────────────────────────┘
                         v
                    btmon -r trace.log
                         │
                         v
                   Decoded text ──> anonymize (optional)
                         │
                         v
              ┌─ Step 1: Detection (detect.py) ─────────> detect.md
              │          │
              │          v
              │  Step 2: Filter (annotate.py prefilter) ─> filter.md
              │          │
              │          v
              │  Step 3: Annotation (annotate.py) ──────> annotate.md
              │          │
              │          v
              │  Step 4: Diagnostics (annotate.py) ─────> diagnose.md
              │          │
              │          v
              │  Step 5: LLM Analysis (analyze.py) ─────> analyze.md
              │          │
              └──────────v
                    Post 5 comments on issue
```

Each step writes a separate markdown file to `results/` and gets
posted as its own GitHub issue comment.

## Issue Submission and Workflow

Users open a GitHub issue using the `analyze-trace.yml` issue template.
The form collects:

- **Trace file** — dragged-and-dropped btsnoop/HCI trace (`.log`,
  `.snoop`, `.btsnoop`, `.cfa`)
- **Description** — free-text scenario description
- **Focus area** — dropdown selecting a protocol area (or "General" for
  auto-detection)
- **Privacy options** — opt-out of MAC anonymization, acknowledgement
  of third-party LLM processing

The `analyze-trace.yml` GitHub Actions workflow fires on `issues.opened`
and `issues.reopened`. It:

1. Parses the issue body to extract the trace URL, description, focus
   area, and anonymization preference
2. Posts an "analyzing..." comment so the user knows processing started
3. Builds `btmon` from the BlueZ upstream repository
4. Downloads and decodes the trace with `btmon -r`
5. Optionally anonymizes MAC addresses (sequential pseudonyms)
6. Runs the 5-step pipeline via `scripts/analyze.py`
7. Posts each step's output as a separate issue comment

## Step 1: Detection (`detect.py` → `results/detect.md`)

Auto-detects which protocol area is most relevant in the trace.

`detect.py` defines protocol areas, each with:

- **Activity patterns** — regexes indicating a protocol is present
  (e.g., AVDTP signaling for A2DP, CIS events for LE Audio)
- **Error patterns** — regexes matching protocol-specific failures
- **Absence checks** — expected-but-missing events (e.g., "PA sync
  established but BIG Info never received" for broadcast)

Areas are scored by activity count and error presence. The top-scoring
area with errors is preferred. When the user selects "General (full
analysis)", `select_focus()` picks the best area — preferring audio
protocols over background noise like advertising/HCI init.

**Output:** A markdown comment showing detected areas, scores, and the
chosen focus.

**Standalone usage:**

```bash
btmon -r trace.log | python3 scripts/detect.py
```

## Step 2: Filter (`annotate.py` prefilter → `results/filter.md`)

Produces a summary of the prefiltering results: how the raw trace was
reduced to fit within the LLM's context budget.

The filter step reports:

- **Packet counts** — total, key, context, skipped
- **Time span** — first to last packet timestamp
- **Budget usage** — characters used vs. limit

For focus areas with a dedicated annotator, the `prefilter()` function
does protocol-aware packet selection:

- **Key packets** — signaling, state changes → included with full body
- **Context packets** — bulk data (ISO, A2DP media) → header only
- **Skipped packets** — unrelated traffic → gap markers

For areas without an annotator, `clip_for_focus()` uses pattern-based
extraction around matched lines. For "General", simple truncation.

**Output:** A markdown comment with packet breakdown and budget stats.

**Standalone usage (prefilter):**

```bash
btmon -r trace.log | python3 scripts/annotate.py --focus "Audio / A2DP"
```

## Step 3: Annotation (`annotate.py` → `results/annotate.md`)

Produces a **Key Frames** table listing signaling packets with
timestamps, protocol tags, and one-line semantic descriptions.

Each annotator understands its protocol's expected flow and tags
packets with:

- **Tags** — protocol/profile short names: `AVDTP`, `ASCS`, `CIS`,
  `HCI`, `L2CAP`, `SBC`, etc. Multi-tag for cross-layer events.
- **Priority** — `key` (signaling), `context` (bulk data), `skip`
- **Annotations** — decoded one-line descriptions

### Available Annotators

| Annotator | Focus Areas | What it Tracks |
|-----------|-------------|----------------|
| LE Audio (unicast) | Audio / LE Audio | CIG/CIS lifecycle, ASE state, ISO data path |
| LE Audio (broadcast) | Audio / LE Audio | PA sync, BIG sync, BASE parsing, PAST |
| A2DP | Audio / A2DP | AVDTP signaling, SBC/AAC config, media data flow |
| HFP | Audio / HFP | RFCOMM setup, AT commands, SCO connections |
| Connection | Connection issues, Disconnection | LE/BR connection lifecycle, disconnect reasons |
| Pairing | Pairing / Security | SMP pairing, key exchange, bonding |
| Advertising | Advertising / Scanning | ADV reports, scan params, extended advertising |
| GATT | GATT discovery | Service/characteristic discovery, ATT operations |

**Output:** A markdown table of up to 50 key frames with `#`, timestamp,
tags, and description columns.

## Step 4: Diagnostics (`annotate.py` → `results/diagnose.md`)

Produces a **Diagnostics** table combining two sources:

1. **Graceful disconnect packets** — HCI Disconnect commands that were
   intentionally initiated (with frame number and timestamp)
2. **Annotator diagnostics** — protocol-level observations without
   specific frame numbers:
   - `STREAM:` — audio stream summary (codec, config, peak state)
   - `CONFIG:` — codec/transport configuration details
   - `STATE:` — state transition tables (multi-line, shown as code blocks)
   - `ABSENCE:` — expected events that never occurred (:warning:)
   - `NOTE:` / `INFO:` — informational observations (:information_source:)

**Output:** A markdown table with `#`, timestamp, tags, and diagnostic
columns. Annotator diagnostics use `-` for frame/timestamp.

## Step 5: LLM Analysis (`analyze.py` → `results/analyze.md`)

Sends the prefiltered trace + documentation to an LLM for structured
analysis.

### Documentation Loading

The `FOCUS_DOCS` dict maps focus areas to BlueZ documentation files
(e.g., `btmon-le-audio.rst`, `btmon-a2dp.rst`). Focus-specific docs
are loaded instead of the full `btmon.rst` to stay within context
limits.

### Prompt Construction

- **System prompt** — LLM role as Bluetooth protocol analyst +
  documentation in a `<btmon-documentation>` block + detected
  absence-based errors
- **User prompt** — User description, focus area, prefiltered trace
  in a code block, and output format instructions from `templates.py`

### Output Templates (`templates.py`)

Each focus area has a structured fill-in-the-blank template that forces
consistent output. Templates define exact section headings, field
labels, and table formats:

- **Audio Streams table** — shared by A2DP and LE Audio templates:
  stream ID, direction, codec, peak state, config
- **A2DP template** — AVDTP state transitions, media stats, latency
- **LE Audio template** — CIG/CIS parameters, ASE state transitions,
  ISO data path
- **General template** — connection timeline, protocol analysis, issues

### LLM Providers

| Provider | API Endpoint | Auth | Default Model |
|----------|-------------|------|---------------|
| GitHub Models | `models.github.ai/inference` | `GH_MODELS_TOKEN` or `GITHUB_TOKEN` | `openai/gpt-4o-mini` |
| OpenAI | `api.openai.com/v1` | `OPENAI_API_KEY` | `gpt-4o` |
| Anthropic | `api.anthropic.com/v1` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-20250514` |

### Context Budgets

| Provider | Trace limit | Docs limit |
|----------|------------|------------|
| GitHub Models (free) | 16K chars | 4K chars |
| OpenAI | 100K chars | 50K chars |
| Anthropic | 100K chars | 50K chars |

**Output:** The LLM's structured diagnostic report, wrapped in a
"Step 5: LLM Analysis" heading. The workflow appends a footer with
btsnoop-analyzer attribution.

## File Map

```
btsnoop-analyzer/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   └── analyze-trace.yml    # Issue form: trace upload, description, focus
│   └── workflows/
│       └── analyze-trace.yml    # CI workflow: build btmon, run 5-step pipeline
├── scripts/
│   ├── analyze.py               # Main entry: decode, anonymize, orchestrate pipeline
│   ├── detect.py                # Step 1: area scoring, absence checks, log clipping
│   ├── annotate.py              # Steps 2-4: packet parser, annotators, prefilter
│   ├── templates.py             # Step 5: structured output templates per focus area
│   └── anonymize.sh             # Shell-based MAC anonymization (standalone use)
├── tests/
│   ├── conftest.py              # pytest fixtures (decoded trace texts)
│   ├── test_annotate_a2dp.py    # A2DP annotator tests (23 tests)
│   ├── test_annotate_leaudio.py # LE Audio annotator tests (22 tests)
│   ├── test_detect.py           # Detection and focus selection tests
│   ├── test_invalid.py          # Edge case tests (empty, garbage, wrong focus)
│   └── fixtures/                # Decoded btmon trace fixtures
│       ├── a2dp.txt
│       ├── le_audio_cis.txt
│       └── broadcast.txt
├── results/                     # Pipeline output (created at runtime)
│   ├── detect.md                # Step 1 output
│   ├── filter.md                # Step 2 output
│   ├── annotate.md              # Step 3 output
│   ├── diagnose.md              # Step 4 output
│   └── analyze.md               # Step 5 output
├── ARCHITECTURE.md              # This file
└── README.md                    # User-facing setup and usage docs
```
