# Step 1: Detection

Detection auto-identifies which Bluetooth protocol area is most
relevant in a decoded btmon trace.  It scans every line against
declarative patterns loaded from JSON rule files, scores each area,
and selects a focus for the remaining pipeline steps.

**Source files:** `scripts/detect.py`, `scripts/rules.py`, `rules/*.json`
**Output:** `results/detect.md`

## Rule Loading

Detection patterns are defined in JSON rule files under `rules/`.  At
import time, `detect.py` calls `rules.load_rules()` which:

1. Reads every `*.json` file in `rules/`, sorted alphabetically.
2. Compiles each file into a `RuleSet` via `compile_rule_file()`.
3. Validates uniqueness (no two rule files may share a `name` or `focus`).
4. Caches the result globally so subsequent calls are free.

Each `RuleSet` has a `detect` section containing:

- **`activity`** -- regex patterns indicating the protocol is present
  (e.g. `AVDTP:` for A2DP, `Periodic Advertising` for LE Audio broadcast).
- **`errors`** -- regex patterns matching protocol-specific failures
  (e.g. `Status:.*(?!Success)`, `REJECTED`, `FAILED`).
- **`absence_checks`** -- prerequisite/expected pairs that detect
  protocol-flow breaks (see below).

Only rule files with at least one detect pattern produce an `AreaDef`.
Rule files that are annotation-only (e.g. `disconnection.json`) are
skipped during detection.

### AreaDef Structure

```python
@dataclass
class AreaDef:
    name: str           # e.g. "a2dp", "le_audio"
    focus: str          # e.g. "Audio / A2DP", "Audio / LE Audio"
    activity: list      # regex pattern strings
    errors: list        # regex pattern strings
    absence_checks: list  # AbsenceCheck objects
```

The `AREAS` list and `_COMPILED` dict are built once at module level
from the loaded rule sets.  `_COMPILED` stores pre-compiled
`re.Pattern` objects indexed by area name to avoid recompilation on
every `detect()` call.

## Init Command Filtering

HCI initialization commands (Set Event Mask, Read Local Supported
Codecs, etc.) list protocol and codec names in their body text.  For
example, "Read Local Supported Codecs" includes lines like "LC3" and
"aptX" which would cause false-positive activity matches for audio
areas.

The `_build_skip_set()` function marks these lines for exclusion:

1. Walk through all lines sequentially.
2. When a packet header matches `_INIT_COMMAND_RE`, mark it and all
   subsequent body lines (indented lines before the next header) as
   skip.
3. Also handle Command Complete responses that echo the init command
   name in a body line -- mark the echoed line and its continuation.

The resulting `skip` set is consulted during the main scan loop.
Lines in the skip set are silently ignored for both activity and error
pattern matching.

### Commands Filtered

The `_INIT_COMMAND_RE` pattern matches:
- `Set Event Mask`
- `Read Local Supported Codec`
- `Read Local Supported Features`
- `Read BD ADDR`
- `Read Buffer Size`

## Scanning Algorithm

`detect(text)` processes the full decoded btmon output:

```
lines = text.splitlines()
skip = _build_skip_set(lines)

for each AreaDef in AREAS:
    for each line (not in skip):
        if any activity pattern matches -> activity_count++, record line
        if any error pattern matches   -> error_count++, record line
    for each absence_check:
        if prerequisite matches somewhere but expected matches nowhere
            -> record absence error message
```

Each area produces a `DetectedArea` with:
- `activity_count` / `activity_lines`
- `error_count` / `error_lines`
- `absence_errors` (list of message strings)

Results are sorted by score (highest first).  Only areas with at
least one match are returned.

## Scoring Formula

```
score = (error_count + len(absence_errors)) * 10 + activity_count
```

Errors are weighted **10x** over activity.  This means an area with
even one error (score >= 10) outranks an area with up to 9 activity
matches (score 9).  This ensures the pipeline focuses on areas where
something went wrong rather than areas with high traffic volume.

## Absence Checks

Absence checks detect protocol-flow breaks where a prerequisite event
appeared but an expected follow-up never did:

```json
{
  "prerequisite": "Periodic Advertising Sync Established.*Success",
  "expected": "BIG Info|Isochronous Group Info",
  "message": "PA sync established but BIG Info never received"
}
```

The check scans the full trace (respecting the skip set):
1. If `prerequisite` regex matches at least one line: `has_prereq = True`
2. If `expected` regex matches at least one line: `has_expected = True`
3. If `has_prereq and not has_expected`: fire the absence error.

Absence errors count as errors in the scoring formula, so they can
promote an otherwise low-scoring area to the top.

## Focus Selection

`select_focus(results)` chooses the best focus area from detection
results.  It returns `(focus_string, absence_errors, coexistence_notes)`.

### Selection Rules (in priority order)

1. **Error areas first** -- If any area has errors, pick the
   highest-scoring error area.

2. **Audio areas preferred** -- Among error-free results, audio areas
   (`a2dp`, `hfp`, `le_audio`) are preferred over background areas
   (`advertising`, `hci_init`).

3. **Multi-audio coexistence** -- When multiple audio areas are active
   and the second-highest scores >= 30% of the top's score, use the
   combined `"Audio"` focus (loads all three audio annotators and
   documentation files).

4. **Fallback** -- If no areas detected at all, return
   `"General (full analysis)"`.

### Advertising Coexistence Detection

`_check_adv_coexistence()` fires when advertising activity count
exceeds 50 events alongside an active audio session.  The threshold
(`_ADV_COEXISTENCE_THRESHOLD = 50`) flags cases where active scanning
may cause controller scheduling conflicts with audio data delivery.

The coexistence note is added to `absence_errors` and passed to the
LLM as an investigation hint.

## Log Clipping

After focus selection, the pipeline clips the trace to reduce size
for LLM consumption.

### `clip(text, area_name, context_packets=5, max_chars=30000)`

Pattern-based clipping for areas without a dedicated annotator:

1. Find all line indices matching the area's activity + error patterns.
2. Build a packet boundary index (lines starting with `<`, `>`, `@`,
   `=`, or a timestamp).
3. For each match, expand to include the full containing packet plus
   `context_packets` packets before and after.
4. Merge overlapping windows.
5. Join selected ranges with `[... N lines skipped ...]` gap markers.
6. If result exceeds `max_chars`, truncate keeping 60% head / 35% tail.

### `clip_for_focus(text, focus, ...)`

Maps focus area strings to area names and calls `clip()`.  For the
combined `"Audio"` focus, clips all three audio areas separately
(each getting `max_chars // 3`) and joins them with section headers.

## Markdown Output

`format_markdown()` produces the Step 1 GitHub comment:

- Shows whether focus was auto-detected or user-selected.
- Renders a table: Area | Score | Activity | Errors | Absence Issues.
- Error areas get a `:warning:` marker.
- Absence errors are listed in a separate "Absence-Based Issues"
  section with area attribution.

## Standalone Usage

```bash
# Pipe decoded trace to detect.py
btmon -r trace.log | python3 scripts/detect.py

# Output shows detected areas with scores and clip ratio
```
