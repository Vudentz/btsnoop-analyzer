# Step 2: Prefilter

Prefiltering reduces a decoded btmon trace to fit within the LLM's
context budget while preserving the most diagnostically important
packets.  The output is a structured document with three clearly
separated sections that the LLM can cross-reference.

**Source files:** `scripts/prefilter.py`, `scripts/annotate.py`
**Output:** `results/filter.md`

## Prerequisites

Prefiltering runs after annotation (Step 3 logically, but executed
first in the pipeline).  The orchestrator (`analyze.py`) calls
`annotate_trace()` before `prefilter()`, passing the pre-annotated
packets and diagnostics.  This avoids parsing and annotating twice.

When pre-annotated packets are not available (e.g. standalone use),
`prefilter()` calls `annotate_trace()` internally.

## Packet Priority Classification

Each packet has a `priority` field set by the annotator:

| Priority | Meaning | Prefilter Treatment |
|----------|---------|---------------------|
| `key` | Protocol signaling, state changes, errors | Full body included |
| `context` | Bulk data, periodic events, informational | Header-only (body stripped) |
| `skip` | Unrelated traffic | Replaced with gap markers |

Annotators use `_tag()` with priority escalation: a packet can only
be promoted (`skip` -> `context` -> `key`), never demoted by a
subsequent tag call.

## Three-Section Output Structure

The prefiltered output has three sections separated by `===` headers:

### Section 1: Summary Header

```
=== Prefiltered btmon log: {focus} ===
Total packets: 342, Key: 28, Context: 14, Skipped: 300
Time span: 0.000s - 45.230s (45.2s)

Diagnostics:
  * ABSENCE: PA sync established but BIG Info never received
  * STREAM: id=1 dir=? codec=LC3 state=Streaming config=48kHz, 10ms, 100oct
```

Contains packet counts, time span, and the full diagnostics list
from the annotator.

### Section 2: Annotations

```
=== Annotations ===

Key event timeline:
     0.123s  #4      PA sync established (Success)
     1.456s  #22     BIG Info received -- BIG exists on this PA train
     ...

Per-packet annotations (frame -> decoded meaning [tags]):
  #4        0.123s  PA sync established (Success)  [PA]
  #22       1.456s  BIG Info received  [BIG]
  ...
```

Two sub-sections:
- **Key event timeline** -- up to 30 key packets with timestamp,
  frame number, and annotation.  Capped to prevent the annotation
  section from consuming the entire budget.
- **Per-packet annotation table** -- up to 60 packets (key + context)
  with frame number, timestamp, annotation, and protocol tags.

### Section 3: Raw Trace

```
=== Raw btmon packets ===

> HCI Event: LE Meta Event (0x3e) plen 40   #4 [hci0] 0.123
        LE Periodic Advertising Sync Established (0x0e)
        Status: Success (0x00)
        ...

[... 12 packets skipped ...]

> HCI Event: LE Meta Event (0x3e) plen 62   #22 [hci0] 1.456
        LE BIG Info Advertising Report
        ...
```

Contains raw btmon packet output with no annotation markers.  Key
packets include full body; context packets show header only.  Gaps
between included packets show `[... N packets skipped ...]` markers.

## Budget Allocation

The `max_chars` parameter (default 24000, provider-dependent) sets the
total character budget.  Allocation:

1. **Overhead** = len(header) + len(annotations) + 200 (separators)
2. **Trace budget** = max_chars - overhead

If trace budget < 1000 characters, the raw trace section is omitted
entirely and only the header + annotations are returned.

### Budget Exhaustion Strategy

When building the raw trace section, packets are processed in order:

1. Each packet's cost is estimated: `len(formatted) + 50` (gap marker
   overhead).
2. If a **context** packet exceeds remaining budget: **drop it**.
3. If a **key** packet exceeds budget: **switch to header-only**
   (strip body, reducing cost).
4. If even header-only exceeds budget: emit
   `[... budget exhausted, N key packets total ...]` and stop.

This ensures key packets are always preferred over context packets,
and partial information (header-only) is preferred over omission.

## Gap Markers

When consecutive included packets have skipped packets between them,
a gap marker is inserted:

```
[... 47 packets skipped ...]
```

The count reflects only packets with `priority == "skip"` in the gap,
not context packets that were dropped for budget reasons.

## Packet Formatting

Two formatting functions:

- `_format_packet(pkt, include_body=True)` -- prepends annotation
  header (`### annotation [tags]`) before the raw btmon header.
  Used in earlier designs; currently unused in the three-section output.
- `_format_packet_raw(pkt, include_body=True)` -- raw btmon output
  only (header + body lines).  Used for the raw trace section.

## Filter Markdown (`format_filter_markdown`)

Produces the Step 2 GitHub comment showing prefilter statistics:

```markdown
## Step 2: Filter

**Focus:** Audio / LE Audio
**Total packets:** 342
**Key:** 28 | **Context:** 14 | **Skipped:** 300
**Time span:** 0.000s - 45.230s (45.2s)
**Budget:** 18,432 / 24,000 chars (76% used)
```

Optionally includes the prefiltered trace text in a collapsible
`<details>` block for easy copy/paste inspection.

## When Prefilter Is Not Used

For focus areas without a dedicated annotator, the pipeline falls
back to:

1. **Pattern-based clipping** via `clip_for_focus()` (see
   [Step 1: Detection](step1-detection.md#log-clipping)).
2. **Simple truncation** via `truncate_for_context()` -- keeps 60%
   from the start and 40% from the end of the trace.

For `"General (full analysis)"` focus, only simple truncation is used.
