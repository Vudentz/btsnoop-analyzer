# Architecture

This document describes the analysis pipeline from issue submission to
posted diagnostic report.

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
              ┌──── General? ─── yes ──> detect.py (auto-detect area)
              │          │
              │          no
              │          │
              v          v
         annotate.py ── prefilter ──> prefiltered log
              │                            │
              │    (fallback)              │
              v          │                 v
         clip_for_focus  │          load_docs (focus-specific RST)
              │          │                 │
              └──────────┘                 v
                                    build_prompt
                                    (system + user + template)
                                         │
                                         v
                                    LLM API call
                                    (github / openai / anthropic)
                                         │
                                         v
                                    Post comment on issue
```

## Stages

### 1. Issue Submission

Users open a GitHub issue using the `analyze-trace.yml` issue template.
The form collects:

- **Trace file** — dragged-and-dropped btsnoop/HCI trace (`.log`,
  `.snoop`, `.btsnoop`, `.cfa`)
- **Description** — free-text scenario description
- **Focus area** — dropdown selecting a protocol area (or "General" for
  auto-detection)
- **Privacy options** — opt-out of MAC anonymization, acknowledgement
  of third-party LLM processing

### 2. Workflow Trigger

The `analyze-trace.yml` GitHub Actions workflow fires on `issues.opened`
and `issues.reopened`. It gates on the presence of the privacy
acknowledgement checkbox text to avoid triggering on non-template issues.

The workflow:

1. Parses the issue body with `actions/github-script` to extract the
   trace URL, description, focus area, and anonymization preference
2. Posts an "analyzing..." comment so the user knows processing started
3. Installs BlueZ build dependencies and builds `btmon` from upstream
4. Runs `scripts/analyze.py` with the parsed parameters
5. Posts the analysis result (or an error message) as a comment

### 3. Trace Download and Decoding (`analyze.py`)

`analyze.py` is the main entry point. It:

1. **Downloads** the trace file from the GitHub attachment URL
2. **Decodes** it with `btmon -r <trace>`, producing human-readable
   HCI packet output
3. **Anonymizes** MAC addresses if requested — each unique address maps
   to a sequential pseudonym (`00:00:00:00:00:01`, `:02`, ...)

### 4. Auto-Detection (`detect.py`)

When the user selects "General (full analysis)", the analyzer runs
auto-detection to identify the most relevant protocol area.

`detect.py` defines protocol areas, each with:

- **Activity patterns** — regexes that indicate a protocol is present
  (e.g., AVDTP signaling packets for A2DP, CIS events for LE Audio)
- **Error patterns** — regexes matching protocol-specific failures
- **Absence checks** — expected-but-missing events (e.g., "PA sync
  established but BIG Info never received" for broadcast)

Areas are scored by a combination of activity count and error presence.
The top-scoring area with errors is preferred; if none have errors, the
highest activity area wins.

The detected area's focus string maps to the same FOCUS_DOCS keys used
by explicit user selections, so the rest of the pipeline is identical.

### 5. Annotation and Prefiltering (`annotate.py`)

This is the most complex stage. For focus areas that have a dedicated
annotator, the raw decoded trace is parsed into structured packets and
then annotated with protocol-aware semantic labels.

#### Packet Parsing

The parser splits btmon output into `Packet` objects by matching header
lines with the direction marker (`<`, `>`, `@`, `=`), summary text,
frame number (`#N`), HCI adapter (`[hciN]`), and timestamp. Indented
lines following each header become the packet's body.

Key parsing detail: LE Meta Event sub-event names (like
`LE Connected Isochronous Stream Established`) appear in the packet
body, not the summary line. Annotators use `full = summary + body_text`
for pattern matching.

#### Focus-Specific Annotators

Each annotator understands its protocol's expected flow and tags packets
with:

- **Semantic labels** — e.g., `[CIS_ESTABLISHED]`, `[AVDTP_START]`,
  `[PA_SYNC_ESTABLISHED]`, `[BIG_SYNC_ESTABLISHED]`
- **Priority levels** — `key` (include full body), `context` (header
  only), or `skip` (omit entirely)
- **Annotations** — one-line descriptions for the LLM

Available annotators:

| Annotator | Focus Areas | What it Tracks |
|-----------|-------------|----------------|
| LE Audio (unicast) | Audio / LE Audio | CIG/CIS lifecycle, ASE state, ISO data path |
| LE Audio (broadcast) | Audio / LE Audio | PA sync, BIG sync, BASE parsing, PAST |
| A2DP | Audio / A2DP | AVDTP signaling, SBC/AAC config, media data flow |
| HFP | Audio / HFP | RFCOMM setup, AT commands, SCO connections |
| Connection | Connection issues, Disconnection | LE/BR connection lifecycle, disconnection reasons |
| Pairing | Pairing / Security | SMP pairing, key exchange, bonding |
| Advertising | Advertising / Scanning | ADV reports, scan parameters, extended advertising |
| GATT | GATT discovery | Service/characteristic discovery, ATT operations |

Each annotator also performs **absence detection** — checking for
expected protocol events that never appeared (e.g., "CIS Request sent
but CIS Established never received").

#### Prefilter Output Format

The `prefilter()` function produces a budget-aware text block:

```
=== Focus: Audio / A2DP ===
=== Diagnostics: ===
  - High latency spike: 56ms at #12345

=== Key event timeline: ===
  0.000s  [AVDTP_DISCOVER]  AVDTP Discover
  1.234s  [AVDTP_SET_CONFIG]  Set Configuration (SBC, 44100Hz)
  ...

=== Prefiltered btmon log:
[Key packets with full body, context packets header-only,
 skip markers like "[... 500 packets skipped ...]"]
```

The output is sized to fit within the provider's context limits
(default 24K chars for GitHub Models, 100K for OpenAI/Anthropic).

#### Fallback: Pattern-Based Clipping

For focus areas without a dedicated annotator, `clip_for_focus()` from
`detect.py` extracts log sections around pattern-matched lines using
btmon packet boundaries. This is less precise but still reduces the
trace to relevant sections.

### 6. Documentation Loading (`analyze.py`)

The `FOCUS_DOCS` dict maps focus area strings to BlueZ documentation
files:

```python
FOCUS_DOCS = {
    "Audio / LE Audio": ["btmon-le-audio.rst"],
    "Audio / A2DP":     ["btmon-a2dp.rst"],
    "Audio / HFP":      ["btmon-hfp.rst"],
    "Connection issues": ["btmon-connections.rst"],
    ...
}
```

Focus-specific doc files are loaded instead of the full `btmon.rst` to
stay within context limits. The docs describe protocol flows, expected
packet sequences, error codes, and analysis techniques — giving the LLM
a reference for interpreting the trace.

### 7. Prompt Construction (`analyze.py`, `templates.py`)

The prompt has two parts:

- **System prompt** — Sets the LLM's role as a Bluetooth protocol
  analyst, includes the documentation as a `<btmon-documentation>` block,
  and adds notes about prefiltered output format and detected
  absence-based errors
- **User prompt** — Contains the user's description, focus area, the
  decoded/prefiltered trace in a code block, and output format
  instructions from `templates.py`

#### Output Templates (`templates.py`)

Each focus area has a structured fill-in-the-blank template that forces
consistent output regardless of the LLM used. Templates define exact
section headings, field labels, and table formats. Examples:

- **A2DP template** — Codec configuration table, AVDTP state machine
  transitions, media data statistics, latency analysis
- **LE Audio template** — CIG/CIS parameters, ASE state transitions,
  ISO data path setup, BIG sync status
- **General template** — Connection timeline, protocol analysis, issues
  found, recommendations

### 8. LLM Call (`analyze.py`)

Three providers are supported:

| Provider | API Endpoint | Auth | Default Model |
|----------|-------------|------|---------------|
| GitHub Models | `models.github.ai/inference` | `GH_MODELS_TOKEN` or `GITHUB_TOKEN` | `openai/gpt-4o-mini` |
| OpenAI | `api.openai.com/v1` | `OPENAI_API_KEY` | `gpt-4o` |
| Anthropic | `api.anthropic.com/v1` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-20250514` |

Context budgets per provider:

| Provider | Trace limit | Docs limit |
|----------|------------|------------|
| GitHub Models (free) | 24K chars | 4K chars |
| OpenAI | 100K chars | 50K chars |
| Anthropic | 100K chars | 50K chars |

### 9. Result Posting

The LLM response is written to `analysis-result.md` and posted as a
GitHub issue comment by the workflow. On failure, an error comment with
a link to the workflow run is posted instead.

## File Map

```
btsnoop-analyzer/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   └── analyze-trace.yml    # Issue form: trace upload, description, focus
│   └── workflows/
│       └── analyze-trace.yml    # CI workflow: build btmon, run analysis, post comment
├── scripts/
│   ├── analyze.py               # Main entry: download, decode, anonymize, prompt, call LLM
│   ├── detect.py                # Auto-detection: area scoring, absence checks, log clipping
│   ├── annotate.py              # Packet parser + 8 focus-specific annotators + prefilter
│   ├── templates.py             # Structured output templates per focus area
│   └── anonymize.sh             # Shell-based MAC anonymization (standalone use)
├── ARCHITECTURE.md              # This file
└── README.md                    # User-facing setup and usage docs
```
