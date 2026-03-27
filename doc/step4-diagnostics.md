# Step 4: Diagnostics

Diagnostics formats the annotator's protocol-level observations and
graceful disconnect detection into a structured markdown table.  It
combines two sources: packets tagged as graceful disconnects, and
`Diagnostic` objects produced by annotator `finalize()` methods.

**Source files:** `scripts/diagnose.py`, `scripts/packet.py`
**Output:** `results/diagnose.md`

## Diagnostic Class

```python
class Diagnostic:
    message: str          # e.g. "ABSENCE: PA sync but no BIG Info"
    frame: int | None     # packet frame number, if associated
    timestamp: float | None  # packet timestamp, if associated
    tags: list[str]       # protocol tags (e.g. ["ASCS"])
```

`Diagnostic` behaves like a string for backward compatibility
(`startswith()`, `split()`, `__contains__`, etc.) but carries
optional packet reference metadata for structured rendering.

## Diagnostic Sources

### 1. Graceful Disconnect Packets

Any packet whose annotation contains `"Graceful disconnect"` is
extracted from the annotated packet list.  These are intentional
disconnects identified by the annotator:

- **Local-initiated:** `HCI Command: Disconnect` with direction `<`.
- **Disconnect Complete** with `Status: Success` and a graceful reason
  code: `Remote User Terminated` (0x13) or `Connection Terminated By
  Local Host` (0x16).

Graceful disconnects appear as rows in the diagnostics table with
their actual frame number and timestamp.

### 2. Declarative Absence Checks

Defined in the `diagnose.absence_checks` section of JSON rule files:

```json
{
  "condition_flag": "saw_pa_sync",
  "missing_flag": "saw_big_info",
  "message": "PA sync established but BIG Info never received"
}
```

During `RuleMatchAnnotator.finalize()`:
1. For each absence check, read `condition_flag` and `missing_flag`
   from the annotator instance.
2. If `condition_flag` is True and `missing_flag` is False, emit
   `Diagnostic("ABSENCE: {message}")`.

These detect protocol flows that started but never completed.

### 3. Declarative Notes

Defined in the `diagnose.notes` section of JSON rule files:

```json
{
  "condition": {
    "counter": "cis_data_count",
    "op": "gt",
    "value": 0
  },
  "message": "NOTE: {cis_data_count} ISO/CIS data packets streamed"
}
```

`DiagnoseNote.evaluate(annotator)` supports two condition types:

| Type | JSON | Evaluation |
|------|------|------------|
| Counter | `{"counter": "name", "op": "gt", "value": 0}` | `getattr(annotator, name) > 0` |
| Flag | `{"flag": "name", "value": true}` | `getattr(annotator, name) == true` |

Supported operators: `gt`, `gte`, `eq`, `lt`, `lte`.

`DiagnoseNote.format_message(annotator)` interpolates `{variable}`
placeholders from annotator attributes.

### 4. Procedural Diagnostics

Complex annotators (LEAudio, A2DP) produce additional diagnostics
in their `finalize()` methods:

**LE Audio:**
- `STREAM:` lines -- one per ASE ID with codec, peak state, config,
  direction.
- `NOTE:` for ISO data packet count.
- Declarative absence checks for CIS flow (6 checks) and a
  counter-based note for daemon restarts.

**A2DP:**
- `CONFIG:` lines -- per-SEID codec config summary.
- `STREAM:` lines -- per-SEID with direction, codec, peak state, config.
- `STATE:` tables -- per-SEID AVDTP state transition history (multi-line).
- `INFO:` for streaming session count and media data packet count.
- Declarative absence checks for AVDTP flow (3 checks).

**HFP:**
- Declarative absence check for SCO completion.

**SMP:**
- Declarative absence checks for pairing completion (2 checks).

## Diagnostic Categories

The formatting code recognizes these message prefixes:

| Prefix | Emoji | Meaning |
|--------|-------|---------|
| `ABSENCE:` | :warning: | Expected event never occurred |
| `NOTE:` | :information_source: | Informational observation |
| `INFO:` | :information_source: | Informational observation |
| `STREAM:` | (none) | Audio stream summary |
| `CONFIG:` | (none) | Codec/transport configuration |
| `STATE:` | (none) | State transition table (multi-line) |

## Markdown Output

`format_diagnostics_markdown(packets, diags)` produces:

```markdown
## Step 4: Diagnostics

| # | Timestamp | Tags | Diagnostic |
|--:|----------:|------|------------|
| #47 | 12.345s | `HCI` | Graceful disconnect handle=64: Remote User Terminated |
| #4 | 0.123s | `ASCS` | STREAM: id=1 dir=? codec=LC3 state=Streaming config=48kHz, 10ms |
| - | - | - | :warning: ABSENCE: PA sync established but BIG Info never received |
```

### Multi-line Diagnostics

State transition tables (containing newlines) are rendered with the
first line in the table row and the remainder in a fenced code block
below:

```markdown
| #10 | 5.678s | `AVDTP` | STATE: SEID 1 AVDTP state transitions: |

\`\`\`
       5.678s          idle -> configured  (Set Configuration Accept)
       6.789s    configured -> open         (Open Accept)
       7.890s          open -> streaming    (Start Accept)
\`\`\`
```

### Empty Diagnostics

When no graceful disconnects or annotator diagnostics exist:
```markdown
No diagnostics generated.
```
