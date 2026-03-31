# Architecture

This document describes the 5-step analysis pipeline from issue
submission to posted diagnostic report.  Detailed documentation for
each step is in separate files under `doc/`.

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
              │  Step 2: Filter (prefilter.py) ──────────> filter.md
              │          │
              │          v
              │  Step 3: Annotation (annotate.py) ──────> annotate.md
              │          │
              │          v
              │  Step 4: Diagnostics (diagnose.py) ─────> diagnose.md
              │          │
              │          v
              │  Step 5: LLM Analysis (analyze.py) ─────> analyze.md
              │          │
              └──────────v
                    Post 5 comments on issue
```

Each step writes a separate markdown file to `results/` and gets
posted as its own GitHub issue comment.

## Step Summaries

### Step 1: Detection

Auto-detects which protocol area is most relevant by scanning every
trace line against patterns loaded from JSON rule files.  Areas are
scored (`errors * 10 + activity`), and `select_focus()` picks the
best focus — preferring error areas, then audio areas, with
multi-audio coexistence and advertising interference detection.

**Details:** [doc/step1-detection.md](doc/step1-detection.md)

### Step 2: Prefilter

Reduces the annotated trace to fit within the LLM's context budget.
Produces a three-section output: summary header (packet counts,
diagnostics), annotations section (timeline + decoded meanings), and
raw btmon packets (key = full body, context = header-only, skip =
gap markers).  Budget exhaustion drops context first, then switches
key packets to header-only.

**Details:** [doc/step2-prefilter.md](doc/step2-prefilter.md)

### Step 3: Annotation

Parses btmon output into Packet objects, then applies focus-specific
annotators.  9 annotators extend `RuleMatchAnnotator`, which combines
declarative JSON rules (pattern matching, variable extraction, flag
setting) with procedural hooks (state machines, byte decoding,
cross-packet correlation).

**Details:** [doc/step3-annotation.md](doc/step3-annotation.md)

### Step 4: Diagnostics

Formats annotator observations into a structured table: graceful
disconnect packets, absence-based errors (`:warning:`), stream/config
summaries, state transition tables, and informational notes
(`:information_source:`).

**Details:** [doc/step4-diagnostics.md](doc/step4-diagnostics.md)

### Step 5: LLM Analysis

Sends the prefiltered trace + focus-specific BlueZ documentation to
an LLM with a structured fill-in-the-blank template.  10 templates
enforce consistent output with strict formatting rules (verdict
definitions, issue format, recommendations).

**Details:** [doc/step5-analysis.md](doc/step5-analysis.md)

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

## Annotator Hierarchy

All 9 annotators extend `RuleMatchAnnotator`, which combines
declarative JSON match_rules with procedural hooks:

```
Annotator (base)
  └── RuleMatchAnnotator (JSON rules + hooks)
        ├── LEAudioAnnotator     (all hooks)
        ├── A2DPAnnotator        (all hooks)
        ├── HFPAnnotator         (5 rules + 3 hooks)
        ├── SMPAnnotator         (11 rules + 1 hook)
        ├── ConnectionsAnnotator (4 rules + 2 hooks)
        ├── DisconnectionAnnotator (4 rules + 1 hook)
        ├── L2CAPAnnotator       (all hooks)
        ├── AdvertisingAnnotator (5 rules, pure declarative)
        └── HCIInitAnnotator     (6 rules + 1 hook)
```

## JSON Rule System

Declarative rules are defined in `rules/*.json` and compiled at
import time by `rules.py`.  Each rule file defines:

- **`detect`** — activity/error patterns and absence checks for Step 1
- **`annotate.match_rules`** — packet-matching rules with tags,
  priority, annotations, variable extraction, and flag setting
- **`annotate.hooks`** — named hooks for procedural logic
- **`diagnose.absence_checks`** — flag-based absence detection
- **`diagnose.notes`** — counter/flag-conditional notes

Rule format specification: [rules/RULES.md](rules/RULES.md)

## File Map

```
btsnoop-analyzer/
├── action.yml                   # Reusable GitHub Action definition
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   └── analyze-trace.yml    # Issue form: trace upload, description, focus
│   └── workflows/
│       └── analyze-trace.yml    # CI workflow: uses action.yml, posts comments
├── scripts/
│   ├── analyze.py               # Main entry: decode, anonymize, orchestrate pipeline
│   ├── detect.py                # Step 1: area scoring, absence checks, log clipping
│   ├── annotate.py              # Step 3: packet annotators (9), annotation formatting
│   ├── prefilter.py             # Step 2: budget-aware trace filtering
│   ├── diagnose.py              # Step 4: diagnostics formatting
│   ├── templates.py             # Step 5: structured output templates per focus area
│   ├── packet.py                # Shared types: Packet, Diagnostic, parse_packets()
│   ├── rules.py                 # JSON rule loader, RuleSet, MatchCondition compilation
│   └── anonymize.sh             # Shell-based MAC anonymization (standalone use)
├── rules/
│   ├── RULES.md                 # Rule format specification
│   ├── a2dp.json                # detect + 3 diagnose absence checks
│   ├── advertising.json         # detect + 5 match_rules (pure declarative)
│   ├── connections.json         # detect + 4 match_rules + 2 hooks
│   ├── disconnection.json       # detect + 4 match_rules + 1 hook
│   ├── hci_init.json            # detect + 6 match_rules + 1 hook
│   ├── hfp.json                 # detect + 5 match_rules + 3 hooks + 1 absence
│   ├── l2cap.json               # detect + 0 match_rules + 1 hook
│   ├── le_audio.json            # detect + 6 diagnose absence + 1 note
│   └── smp.json                 # detect + 11 match_rules + 1 hook + 2 absence
├── doc/
│   ├── github-action.md         # GitHub Action usage documentation
│   ├── step1-detection.md       # Detection logic deep-dive
│   ├── step2-prefilter.md       # Prefilter logic deep-dive
│   ├── step3-annotation.md      # Annotation logic deep-dive
│   ├── step4-diagnostics.md     # Diagnostics logic deep-dive
│   └── step5-analysis.md        # LLM prompting logic deep-dive
├── tests/
│   ├── conftest.py              # pytest fixtures (decoded trace texts)
│   ├── test_annotate_a2dp.py    # A2DP annotator tests (23 tests)
│   ├── test_annotate_leaudio.py # LE Audio annotator tests (31 tests)
│   ├── test_detect.py           # Detection and focus selection tests (31 tests)
│   ├── test_invalid.py          # Edge case tests (12 tests)
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
