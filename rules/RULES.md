# Rule File Specification

This document specifies the JSON rule format used by the btsnoop-analyzer
pipeline.  Rules replace hardcoded pattern matching with declarative
configuration files that can be edited without modifying Python code.

## Overview

Each Bluetooth protocol area gets one JSON file in `rules/`.  A rule
file contains three top-level sections corresponding to pipeline steps:

| Section      | Pipeline Step           | Purpose                              |
|-------------|-------------------------|--------------------------------------|
| `detect`    | Step 1 (Detection)      | Identify which protocol areas appear |
| `annotate`  | Step 3 (Annotation)     | Tag packets with semantic labels     |
| `diagnose`  | Step 4 (Diagnostics)    | Generate post-scan diagnostic checks |

Step 2 (Prefilter) consumes the output of Step 3 -- it uses packet
priorities and tags set by annotation rules, so it has no dedicated
rule section.  Step 5 (LLM Analysis) uses templates from `templates.py`
and is not rule-driven.

## File Organization

```
rules/
  le_audio.json       Audio / LE Audio (unicast CIS + broadcast BIG)
  a2dp.json           Audio / A2DP (AVDTP signaling + media)
  hfp.json            Audio / HFP (RFCOMM + SCO)
  connections.json    Connection issues (LE + BR/EDR lifecycle)
  smp.json            Pairing / Security (SMP + encryption)
  l2cap.json          L2CAP channel issues
  advertising.json    Advertising / Scanning
  hci_init.json       Controller enumeration (HCI init sequence)
  disconnection.json  Disconnection analysis
  RULES.md            This specification
```

The loader reads all `*.json` files from `rules/` at startup.  File
names are informational; the `name` and `focus` fields inside each
file are authoritative.

## Top-Level Structure

```json
{
  "name": "le_audio",
  "focus": "Audio / LE Audio",
  "init_filter": [ ... ],
  "detect":   { ... },
  "annotate": { ... },
  "diagnose": { ... }
}
```

### Required Fields

| Field   | Type   | Description                                    |
|---------|--------|------------------------------------------------|
| `name`  | string | Short identifier (lowercase, underscore-separated). Must be unique across all rule files. |
| `focus` | string | Focus area string matching `FOCUS_DOCS` keys in `analyze.py` and `ANNOTATORS` keys. Must be unique. |

### Optional Fields

| Field         | Type     | Description                                    |
|--------------|----------|------------------------------------------------|
| `init_filter` | string[] | Shared init command filter patterns (regex). Applied to both detect and annotate steps. Per-step overrides are possible via `detect.init_filter` or `annotate.init_filter`. |

### Optional Sections

All three sections (`detect`, `annotate`, `diagnose`) are optional.
A rule file may define any combination.  For example, a detection-only
area would omit `annotate` and `diagnose`.

### Design Decisions

The following decisions were made during spec review:

1. **Shared `init_filter`**: The top-level `init_filter` field is shared
   between detect and annotate steps to avoid duplication.  Per-step
   overrides (`detect.init_filter`, `annotate.init_filter`) take
   precedence when specified.

2. **Two absence check mechanisms**: Both `detect.absence_checks`
   (regex-based, Step 1) and `diagnose.absence_checks` (flag-based,
   Step 4) are kept.  Use detect-time checks for early focus area
   selection; use diagnose-time checks for precise post-annotation
   validation.

3. **Hook ordering**: Hooks run first, then match_rules.  No
   interleaving needed — a hook returning `True` claims the packet.

4. **`diagnose.notes` conditions**: Use structured condition objects
   instead of mini-expression strings.  See `diagnose.notes` section.

5. **No `all_of_matches`**: Dropped to simplify the spec.  The
   existing `direction` field + `all_of` on a single field covers
   all real use cases (e.g., MGMT detection uses `direction: "@"` +
   `all_of: ["MGMT", "bluetoothd"]`).

---

## Section 1: `detect`

Controls Step 1 (Detection).  The detector scans every line of decoded
btmon output and counts matches against these patterns.

```json
{
  "detect": {
    "activity": [ ... ],
    "errors": [ ... ],
    "absence_checks": [ ... ],
    "init_filter": [ ... ]
  }
}
```

### `detect.activity`

Type: `string[]` (regex patterns)

Patterns indicating this protocol is present in the trace.  Each
string is a Python `re` regex.  The detector counts lines matching
any activity pattern (at most one match per line).

```json
"activity": [
  "AVDTP:",
  "Media Codec:",
  "PSM: 25"
]
```

The activity count feeds the area score: `score = errors * 10 + activity`.

### `detect.errors`

Type: `string[]` (regex patterns)

Patterns indicating a failure or error in this protocol area.  Same
counting semantics as activity patterns.

```json
"errors": [
  "Response Reject",
  "Error code:",
  "AVDTP:.*Abort"
]
```

### `detect.absence_checks`

Type: `object[]`

Detects errors when an expected protocol event is absent.  If the
`prerequisite` regex matches at least one line but the `expected`
regex matches none, the `message` is reported as an absence error.

```json
"absence_checks": [
  {
    "prerequisite": "Periodic Advertising Sync (?:Established|Transfer Received)",
    "expected": "(?:BIG Info|Isochronous Group Info) Advertising Report",
    "message": "PA synced but BIG Info never received -- BIG does not exist on this PA train"
  }
]
```

| Field          | Type   | Required | Description                     |
|---------------|--------|:--------:|---------------------------------|
| `prerequisite` | string | yes      | Regex that must match at least one line |
| `expected`     | string | yes      | Regex that should follow; absence = error |
| `message`      | string | yes      | Human-readable diagnostic message |

### `detect.init_filter`

Type: `string[]` (regex patterns)

Patterns identifying HCI init commands whose body text should be
excluded from activity/error scanning.  Init commands like
`LE Set Event Mask` list protocol names in their body, causing
false-positive detection matches.

```json
"init_filter": [
  "Set Event Mask",
  "Read Local Supported Codec",
  "Read Local Supported Features",
  "Read BD ADDR",
  "Read Buffer Size"
]
```

Lines matching init_filter patterns (header or body) are added to a
skip set and excluded from all pattern scanning.

---

## Section 2: `annotate`

Controls Step 3 (Annotation).  The annotator iterates over parsed
`Packet` objects and applies match rules to assign tags, priority,
and one-line annotations.

```json
{
  "annotate": {
    "init_filter": [ ... ],
    "match_rules": [ ... ],
    "hooks": [ ... ]
  }
}
```

### `annotate.init_filter`

Type: `string[]` (regex patterns)

Per-step override of the top-level `init_filter`.  If omitted, the
shared top-level `init_filter` is used.  Packets whose full text
(header + body) matches any init_filter pattern are skipped by the
annotator -- no tags, no priority change.

This prevents init command body text from triggering false annotation
matches.

### `annotate.match_rules`

Type: `object[]`

Declarative packet matching rules.  Each rule tests a condition
against the packet and, if matched, calls `_tag()` to assign tags,
priority, and annotation.  Rules are evaluated in order; a packet
may match multiple rules unless `exclusive: true` is set.

```json
"match_rules": [
  {
    "id": "pa_sync_established",
    "match": {
      "field": "full",
      "contains": "Periodic Advertising Sync Established"
    },
    "tags": ["PA"],
    "priority": "key",
    "annotation": "PA sync established ({status})",
    "extract": {
      "status": {
        "pattern": "Status:\\s*(\\S+)",
        "field": "body",
        "default": "?"
      }
    },
    "set_flag": "saw_pa_sync"
  }
]
```

#### Match Rule Fields

| Field        | Type     | Required | Default  | Description |
|-------------|----------|:--------:|----------|-------------|
| `id`        | string   | no       | —        | Optional unique identifier for debugging and cross-referencing. |
| `match`     | object   | yes      | —        | Condition to test against the packet. See [Match Conditions](#match-conditions). |
| `tags`      | string[] | yes      | —        | Tag(s) to assign (e.g. `["PA"]`, `["CIS", "HCI"]`). |
| `priority`  | string   | no       | `"key"`  | Priority level: `"key"`, `"context"`, or `"skip"`. Only escalates (never downgrades). |
| `annotation`| string   | no       | `""`     | One-line annotation template. Supports `{variable}` interpolation from `extract`. |
| `extract`   | object   | no       | —        | Named regex extractions from packet text. See [Extract](#extract). |
| `set_flag`  | string   | no       | —        | Boolean flag name to set on the annotator instance (e.g. `"saw_pa_sync"`). Used by `diagnose.absence_checks`. |
| `exclusive` | bool     | no       | `false`  | If true, stop evaluating further match_rules for this packet after this rule matches. |
| `direction` | string   | no       | —        | Filter by packet direction: `"<"`, `">"`, `"@"`, `"="`. If omitted, matches any direction. |

#### Match Conditions

The `match` object supports several condition types.  Exactly one
condition key must be present alongside `field`.

| Key         | Type   | Description |
|-------------|--------|-------------|
| `field`     | string | Which text to search: `"summary"`, `"body"`, `"full"` (summary + body). Required. |
| `contains`  | string | Substring match (case-sensitive). Fastest check. |
| `pattern`   | string | Python `re` regex match (uses `re.search`). |
| `all_of`    | string[] | All substrings must be present (AND logic). |
| `any_of`    | string[] | At least one substring must be present (OR logic). |
| `not_contains` | string | Substring must NOT be present (negation guard). Can combine with `contains` or `pattern`. |

**Compound conditions**: `not_contains` can be combined with
`contains` or `pattern` in the same match object.  Both the positive
and negative conditions must be satisfied.

```json
"match": {
  "field": "full",
  "contains": "Advertising Report",
  "not_contains": "Isochronous Group Info"
}
```

**Direction filtering**: Use the `direction` field on the rule to
filter by packet direction, combined with `all_of` for multi-keyword
matching on a single field:

```json
{
  "direction": "@",
  "match": {
    "field": "summary",
    "all_of": ["MGMT", "bluetoothd"]
  }
}
```

#### Extract

The `extract` object defines named variables extracted from the
packet via regex.  Variable names become available for `{variable}`
interpolation in the `annotation` template.

```json
"extract": {
  "status": {
    "pattern": "Status:\\s*(\\S+.*?)\\s*(?:\\(|$)",
    "field": "body",
    "default": "?"
  },
  "handle": {
    "pattern": "Handle:\\s*(\\d+)",
    "field": "body",
    "default": "?"
  }
}
```

| Field     | Type   | Required | Default     | Description |
|-----------|--------|:--------:|-------------|-------------|
| `pattern` | string | yes      | —           | Python regex with one capture group `(...)`. |
| `field`   | string | no       | `"body"`    | Where to search: `"summary"`, `"body"`, `"full"`. |
| `default` | string | no       | `""`        | Value when the regex doesn't match. |

#### set_flag

When a rule matches, sets a boolean flag on the annotator instance.
Flag names follow the convention `saw_<event>` (e.g. `saw_pa_sync`,
`saw_big_info`).  These flags are consumed by `diagnose.absence_checks`
to detect missing protocol events.

```json
"set_flag": "saw_pa_sync"
```

Multiple rules can set the same flag (any match sets it to true).

### `annotate.hooks`

Type: `string[]`

Names of procedural Python hooks that must run during annotation for
this area.  Hooks handle logic too complex for declarative rules:
state machines, deduplication, byte-level decoding, etc.

```json
"hooks": [
  "ase_state_machine",
  "avdtp_state_machine",
  "mgmt_restart_detection",
  "pa_report_dedup",
  "big_info_dedup",
  "iso_data_sampling",
  "media_data_sampling",
  "disconnect_classification"
]
```

Hooks are registered in Python code (the annotator class) and
referenced by name in the rule file.  The rule loader validates that
all referenced hooks exist.  This keeps the rule file as the single
source of truth for what runs during annotation, while the procedural
implementation stays in Python.

Each hook is called with `(annotator, pkt, body_text, full_text)` and
returns `True` if it handled the packet (stopping further rule
evaluation when combined with hook ordering).

#### Available Hooks

| Hook Name                  | Area(s)        | Description |
|---------------------------|----------------|-------------|
| `ase_state_machine`       | LE Audio       | ASE Control Point buffering, confirmation, LTV decoding, state tracking |
| `mgmt_restart_detection`  | LE Audio       | MGMT Close/Open pairing for bluetoothd crash detection |
| `pa_report_dedup`         | LE Audio       | PA Report BASE hash deduplication (first=key, repeats=context) |
| `big_info_dedup`          | LE Audio       | BIG Info dedup (first=key, repeats=context) |
| `iso_data_sampling`       | LE Audio       | ISO data packet counting and sparse tagging (first 2 + every 500th) |
| `avdtp_state_machine`     | A2DP           | AVDTP signaling parsing, SEID tracking, state transitions, codec config extraction |
| `media_data_sampling`     | A2DP           | A2DP media packet counting and sparse tagging |
| `disconnect_classification` | All (base)   | Graceful vs non-graceful disconnect detection |

---

## Section 3: `diagnose`

Controls Step 4 (Diagnostics).  Runs after all packets have been
annotated.  Checks boolean flags set during annotation and generates
diagnostic messages.

```json
{
  "diagnose": {
    "absence_checks": [ ... ],
    "notes": [ ... ],
    "hooks": [ ... ]
  }
}
```

### `diagnose.absence_checks`

Type: `object[]`

Protocol flow completion checks.  Each check tests whether a
prerequisite event was seen but an expected follow-up was not.

```json
"absence_checks": [
  {
    "condition_flag": "saw_pa_sync",
    "missing_flag": "saw_big_info",
    "message": "ABSENCE: PA sync established but BIG Info Advertising Report never received -- BIG does not exist on this PA train, or broadcaster has not started it."
  }
]
```

| Field            | Type   | Required | Description |
|-----------------|--------|:--------:|-------------|
| `condition_flag` | string | yes      | Flag that must be `true` (set by `annotate.match_rules[].set_flag`). |
| `missing_flag`   | string | yes      | Flag that must be `false` for the diagnostic to fire. |
| `message`        | string | yes      | Diagnostic message. Should start with `ABSENCE:` prefix. |

### `diagnose.notes`

Type: `object[]`

Conditional informational notes.  Unlike absence_checks, these fire
when a flag IS set (positive condition) or based on counter thresholds.

```json
"notes": [
  {
    "condition": {
      "counter": "daemon_restarts",
      "op": "gt",
      "value": 0
    },
    "message": "NOTE: bluetoothd restarted {daemon_restarts} time(s) during this trace (MGMT Close/Open cycle detected).  This may indicate a daemon crash or intentional restart."
  }
]
```

| Field       | Type   | Required | Description |
|------------|--------|:--------:|-------------|
| `condition` | object | yes      | Structured condition object. See below. |
| `message`   | string | yes      | Diagnostic message template. Supports `{variable}` from annotator counters. |

#### Condition Object

| Field     | Type           | Required | Description |
|-----------|----------------|:--------:|-------------|
| `counter` | string         | yes*     | Counter name on the annotator instance. |
| `flag`    | string         | yes*     | Boolean flag name on the annotator instance. |
| `op`      | string         | no       | Comparison operator: `"gt"`, `"gte"`, `"eq"`, `"lt"`, `"lte"`. Default: `"eq"`. Only used with `counter`. |
| `value`   | number/boolean | no       | Value to compare against. Default: `true` for flags, `0` for counters. |

*Exactly one of `counter` or `flag` must be present.

### `diagnose.hooks`

Type: `string[]`

Names of procedural Python hooks that run during finalization.  These
generate diagnostics too complex for declarative rules (e.g., STREAM
summaries, state transition tables, broadcast/unicast demotion).

```json
"hooks": [
  "stream_summary",
  "iso_data_summary",
  "broadcast_unicast_demotion",
  "avdtp_state_table",
  "codec_config_summary",
  "session_count_summary"
]
```

#### Available Diagnose Hooks

| Hook Name                    | Area(s)  | Description |
|-----------------------------|----------|-------------|
| `stream_summary`            | LE Audio, A2DP | Emit `STREAM:` lines for audio streams table |
| `iso_data_summary`          | LE Audio | Emit ISO data packet count `NOTE:` |
| `broadcast_unicast_demotion`| LE Audio | Demote unicast-only key frames to context when broadcast dominates |
| `avdtp_state_table`         | A2DP     | Emit per-SEID `STATE:` transition tables |
| `codec_config_summary`      | A2DP     | Emit `CONFIG:` lines for codec configurations |
| `session_count_summary`     | A2DP     | Emit streaming session and media data `INFO:` notes |

---

## Tags

Tags are short uppercase identifiers assigned to packets during
annotation.  A packet can have multiple tags (e.g., `["CIS", "HCI"]`).
Tags serve three purposes:

1. **Semantic labeling** — identifies the protocol layer or profile
2. **Prefilter budgeting** — tags drive priority decisions
3. **Template population** — tags are shown in the LLM analysis output

### Tag Registry

Tags are implicitly defined by their use in `match_rules[].tags`.
The following tags are currently in use:

| Tag        | Meaning                              | Areas Using It       |
|-----------|--------------------------------------|----------------------|
| `PA`      | Periodic Advertising (sync, reports)  | LE Audio             |
| `BIG`     | Broadcast Isochronous Group           | LE Audio             |
| `BASS`    | Broadcast Audio Scan Service          | LE Audio             |
| `MGMT`    | BlueZ Management interface            | LE Audio             |
| `ASCS`    | Audio Stream Control Service          | LE Audio             |
| `ASE_CP`  | ASE Control Point writes              | LE Audio             |
| `ASE_STATE`| ASE state notifications              | LE Audio             |
| `CIG`     | Connected Isochronous Group           | LE Audio             |
| `CIS`     | Connected Isochronous Stream          | LE Audio             |
| `ISO_DATA`| Isochronous data packets              | LE Audio             |
| `PACS`    | Published Audio Capabilities          | LE Audio             |
| `AVDTP`   | Audio/Video Distribution Transport    | A2DP                 |
| `A2DP`    | Advanced Audio Distribution           | A2DP                 |
| `RFCOMM`  | RFCOMM serial channel                 | HFP                  |
| `HFP`     | Hands-Free Profile AT commands        | HFP                  |
| `SCO`     | Synchronous Connection Oriented       | HFP                  |
| `SMP`     | Security Manager Protocol             | Pairing / Security   |
| `L2CAP`   | Logical Link Control and Adaptation   | L2CAP, A2DP, HFP     |
| `HCI`     | Host Controller Interface             | All areas            |
| `LE`      | Low Energy (BLE)                      | LE Audio, Advertising, L2CAP, Connections |
| `ERROR`   | Error/failure marker                  | LE Audio, HFP, SMP, Connections, L2CAP |

### Tag Scope Across Pipeline Steps

Tags interact with different pipeline steps:

| Tag         | detect | annotate | prefilter | diagnose |
|------------|:------:|:--------:|:---------:|:--------:|
| `PA`       | flags  | assign   | budget    | absence  |
| `BIG`      | flags  | assign   | budget    | absence  |
| `BASS`     | —      | assign   | broadcast check | — |
| `MGMT`     | counter| assign   | —         | note     |
| `ASCS`     | flags  | assign   | demote    | stream   |
| `ASE_CP`   | —      | assign   | demote    | —        |
| `ASE_STATE`| —      | assign   | demote    | —        |
| `PACS`     | —      | assign   | demote    | —        |
| `CIS`      | flags  | assign   | —         | absence  |
| `ISO_DATA` | flags  | assign   | —         | note     |
| `AVDTP`    | flags  | assign   | —         | state/config |
| `A2DP`     | flags  | assign   | —         | note     |
| `ERROR`    | —      | assign   | —         | —        |
| `HCI`      | —      | assign   | —         | —        |
| `LE`       | —      | assign   | —         | —        |

Legend:
- **flags** — sets boolean flags for absence checks
- **assign** — tag is assigned to packets
- **budget** — tag influences prefilter budget allocation
- **demote** — tag set triggers priority demotion (key → context)
- **absence** — tag's flag is checked in absence diagnostics
- **note** — tag's counter produces informational diagnostic
- **stream** — tag's data feeds STREAM summary lines
- **state/config** — tag's data feeds STATE/CONFIG summary lines
- **broadcast check** — tag presence indicates broadcast-dominant trace

---

## Priority Levels

Packets have a priority that controls prefilter behavior:

| Priority  | Prefilter Behavior                    | When Used |
|-----------|---------------------------------------|-----------|
| `key`     | Full body included in LLM context     | Signaling, state changes, errors |
| `context` | Header-only, dropped first on budget  | Bulk data (ISO, media), repeats |
| `skip`    | Omitted entirely (gap markers)        | Unrelated traffic |

Priority only escalates: `skip(0) < context(1) < key(2)`.  If two
rules match the same packet, the higher priority wins.

---

## Annotation Template Interpolation

Annotation strings support `{variable}` placeholders populated from
`extract` results:

```json
"annotation": "PA sync established ({status})"
```

If `extract.status` captured `"Success"`, the annotation becomes
`"PA sync established (Success)"`.

Unresolved variables fall back to the extract's `default` value (or
empty string if no default).

---

## Rule Evaluation Order

### Within a single area

1. **Init filter** — packets matching `annotate.init_filter` are
   skipped entirely (no rules or hooks run).
2. **Hooks** — procedural hooks in `annotate.hooks` run first (in
   listed order).  A hook returning `True` means it handled the
   packet.
3. **Match rules** — `annotate.match_rules` are evaluated in array
   order.  All matching rules fire unless a rule sets `exclusive: true`
   (which stops further rule evaluation for that packet).

### Across areas

When multiple annotators run (e.g., `focus = "Audio"` runs A2DP +
HFP + LE Audio), they execute sequentially on the same packet list.
Tags and priorities accumulate.  Rules with `not pkt.tags` guards
(expressed as match conditions) prevent double-tagging.

---

## Example: Complete Rule File

```json
{
  "name": "le_audio",
  "focus": "Audio / LE Audio",

  "init_filter": [
    "Set Event Mask",
    "Read Local Supported Codec",
    "Read Local Supported Features",
    "Read BD ADDR",
    "Read Buffer Size"
  ],

  "detect": {
    "activity": [
      "ASE Control Point",
      "(?:BIG|Isochronous Group) Create Sync",
      "Periodic Advertising Sync Established"
    ],
    "errors": [
      "CIS Established.*Status:(?!.*Success)",
      "(?:BIG|Isochronous Group) Sync Lost"
    ],
    "absence_checks": [
      {
        "prerequisite": "Periodic Advertising Sync (?:Established|Transfer Received)",
        "expected": "(?:BIG Info|Isochronous Group Info) Advertising Report",
        "message": "PA synced but BIG Info never received"
      }
    ]
  },

  "annotate": {
    "match_rules": [
      {
        "id": "pa_sync_established",
        "match": {
          "field": "full",
          "any_of": [
            "Periodic Advertising Sync Established",
            "Periodic Advertising Sync Transfer Received"
          ]
        },
        "tags": ["PA"],
        "priority": "key",
        "annotation": "PA sync established ({status})",
        "extract": {
          "status": {
            "pattern": "Status:.*?(Success|\\S+)",
            "field": "body",
            "default": "?"
          }
        },
        "set_flag": "saw_pa_sync"
      },
      {
        "id": "big_info_first",
        "match": {
          "field": "full",
          "any_of": [
            "BIG Info Advertising Report",
            "Isochronous Group Info Advertising Report"
          ]
        },
        "tags": ["BIG"],
        "priority": "key",
        "annotation": "BIG Info received -- BIG exists on this PA train",
        "set_flag": "saw_big_info"
      },
      {
        "id": "le_connection",
        "match": {
          "field": "full",
          "any_of": [
            "LE Enhanced Connection Complete",
            "LE Connection Complete"
          ]
        },
        "tags": ["HCI", "LE"],
        "priority": "key",
        "annotation": "LE connection: {status}",
        "extract": {
          "status": {
            "pattern": "Status:.*?(Success|\\S+)",
            "field": "body",
            "default": "?"
          }
        }
      }
    ],
    "hooks": [
      "ase_state_machine",
      "mgmt_restart_detection",
      "pa_report_dedup",
      "big_info_dedup",
      "iso_data_sampling",
      "disconnect_classification"
    ]
  },

  "diagnose": {
    "absence_checks": [
      {
        "condition_flag": "saw_pa_sync",
        "missing_flag": "saw_big_info",
        "message": "ABSENCE: PA sync established but BIG Info Advertising Report never received -- BIG does not exist on this PA train, or broadcaster has not started it."
      },
      {
        "condition_flag": "saw_create_cis",
        "missing_flag": "saw_cis_established",
        "message": "ABSENCE: Create CIS sent but CIS Established never received."
      }
    ],
    "notes": [
      {
        "condition": {
          "counter": "daemon_restarts",
          "op": "gt",
          "value": 0
        },
        "message": "NOTE: bluetoothd restarted {daemon_restarts} time(s) during this trace (MGMT Close/Open cycle detected).  This may indicate a daemon crash or intentional restart."
      }
    ],
    "hooks": [
      "stream_summary",
      "iso_data_summary",
      "broadcast_unicast_demotion"
    ]
  }
}
```

---

## Validation

The rule loader (`scripts/rules.py`) validates all rule files at
load time:

1. **Required fields** — `name` and `focus` must be present.
2. **Unique names** — no two rule files share the same `name` or `focus`.
3. **Regex compilation** — all regex patterns in `detect.*`, `annotate.init_filter`, `match.pattern`, and `extract.*.pattern` are compiled with `re.compile()`.  Invalid regex raises an error at load time.
4. **Match structure** — each `match` object must have a `field` and exactly one condition key (`contains`, `pattern`, `any_of`, `all_of`).  `not_contains` is a modifier, not a standalone condition.
5. **Hook existence** — all hook names in `annotate.hooks` and `diagnose.hooks` must reference registered Python hooks.
6. **Tag consistency** — a warning is emitted if `set_flag` is referenced in `diagnose.absence_checks` but never set by any `annotate.match_rules`.

---

## Backward Compatibility

The rule system is designed for incremental adoption:

- **Existing Python annotators continue to work**.  An annotator class
  can mix rule-driven match_rules with procedural `annotate_packet()`
  logic.  Match rules are evaluated first; any packet not fully
  handled by rules falls through to the Python method.
- **Public API is preserved**.  `annotate_trace()`, `prefilter()`,
  `detect()`, and all `format_*_markdown()` functions keep their
  signatures.  Callers (including `analyze.py` and tests) see no
  change.
- **Rule files are additive**.  Adding a new rule file for a new
  protocol area automatically registers it for detection and
  annotation without modifying Python code.

---

## Adding a New Protocol Area

To add support for a new Bluetooth protocol:

1. Create `rules/<area_name>.json` with `name`, `focus`, and at least
   a `detect` section with activity patterns.
2. Add focus-specific documentation to `FOCUS_DOCS` in `analyze.py`.
3. Optionally add `annotate.match_rules` for packet tagging.
4. Optionally add `diagnose.absence_checks` for flow validation.
5. If the protocol requires procedural logic, create a Python hook
   and reference it in `annotate.hooks` or `diagnose.hooks`.
6. Add a test fixture and test class in `tests/`.

No changes to `detect.py`, `annotate.py`, or the pipeline
orchestration are needed.
