# Step 3: Annotation

Annotation parses a decoded btmon trace into structured packets, then
applies focus-specific annotators that tag each packet with semantic
labels, priority levels, and one-line descriptions.  The annotated
packets drive both prefiltering (Step 2) and diagnostics (Step 4).

**Source files:** `scripts/annotate.py`, `scripts/packet.py`, `scripts/rules.py`
**Output:** `results/annotate.md`

## Packet Parsing

`parse_packets(text)` in `packet.py` splits decoded btmon output into
`Packet` objects using two regexes:

### HEADER_RE (primary)

Matches standard btmon packet headers:
```
> HCI Event: LE Meta Event (0x3e) plen 20   #474 [hci0] 156.992
< HCI Command: Disconnect (0x01|0x0006)      #123 [hci0] 42.001
@ MGMT Event: Device Connected               {0x0001} [hci0] 57.056
```

Captures: direction (`<`, `>`, `@`, `=`), summary text, optional
frame number (`#N`), and timestamp (float seconds).

### META_RE (fallback)

Matches `=` meta-lines that lack `[hciN]`:
```
= bluetoothd: src/device.c:connect_cb()     57.058
```

### Packet Structure

```python
@dataclass
class Packet:
    line_start: int      # 0-based line index
    line_end: int        # inclusive last line
    direction: str       # '<', '>', '@', '='
    summary: str         # header text after direction
    frame: int           # #N frame number, -1 if absent
    timestamp: float     # seconds
    body: list           # indented body lines

    # Set by annotators:
    tags: list           # semantic labels (e.g. ["ASCS", "ASE_CP"])
    priority: str        # "key", "context", "skip"
    annotation: str      # one-line description
```

Body lines are all non-header lines following a header until the next
header line.  The parser assigns packets sequentially -- every body
line belongs to the most recently started packet.

### Helper Methods

- `body_contains(pattern)` -- regex search across body lines.
- `body_search(pattern)` -- returns the first regex Match in body.
- `full_text_contains(pattern)` -- searches header + body.

These are used by `MatchCondition` (declarative rules) and hook code.

## Annotator Hierarchy

```
Annotator (base)
  └── RuleMatchAnnotator (declarative + procedural)
        ├── LEAudioAnnotator
        ├── A2DPAnnotator
        ├── HFPAnnotator
        ├── SMPAnnotator
        ├── ConnectionsAnnotator
        ├── DisconnectionAnnotator
        ├── L2CAPAnnotator
        ├── AdvertisingAnnotator
        └── HCIInitAnnotator
```

### Annotator (base class)

Provides:
- `annotate(packets)` -- iterates packets calling `annotate_packet()`,
  then calls `finalize()`.
- `_tag(pkt, tags, priority, annotation)` -- adds tags, sets annotation
  (appends with `; ` if existing), and escalates priority
  (`skip` < `context` < `key`).
- `_is_graceful_disconnect(pkt)` -- recognizes intentional disconnects
  (local-initiated `HCI Command: Disconnect`, or Disconnect Complete
  with reason `Remote User Terminated` / `Connection Terminated By
  Local Host`).
- `_tag_disconnect(pkt, handle)` -- tags disconnect packets, using
  `context` priority for graceful and `key` for non-graceful.

### RuleMatchAnnotator (declarative base)

Extends `Annotator` with JSON-driven rule evaluation:

1. **`__init__`** -- loads the `RuleSet` for `self.name` via
   `get_rule_set()`.
2. **`annotate_packet(pkt)`** -- calls `_run_hooks(pkt)` first.
   If hook returns `True`, match_rules are skipped.  Otherwise,
   `_apply_match_rules(pkt)` evaluates declarative rules.
3. **`_apply_match_rules(pkt)`** -- iterates `match_rules` in order:
   - Direction filter (skip if `rule.direction` doesn't match `pkt.direction`).
   - Match condition test (`rule.match.test(pkt)`).
   - Variable extraction (`rule.extracts`) and annotation template
     interpolation.
   - Tag application with priority.
   - Flag setting (`rule.set_flag` -> `setattr(self, flag, True)`).
   - Exclusive rule stops further rule evaluation for this packet.
4. **`finalize(packets)`** -- evaluates `diagnose.absence_checks`
   and `diagnose.notes` from the RuleSet (see Step 4).

## Declarative Match Rules

Match rules are defined in the `annotate.match_rules` array of each
JSON rule file.  Each rule has:

```json
{
  "id": "smp_pairing_request",
  "match": {
    "field": "full",
    "contains": "Pairing Request"
  },
  "tags": ["SMP"],
  "priority": "key",
  "annotation": "SMP Pairing Request",
  "set_flag": "saw_pairing_req",
  "exclusive": true
}
```

### Match Condition Types

| Type | JSON Key | Behavior |
|------|----------|----------|
| Substring | `contains` | `substring in text` |
| Regex | `pattern` | `re.search(pattern, text)` |
| All substrings | `all_of` | `all(s in text for s in list)` |
| Any substring | `any_of` | `any(s in text for s in list)` |

Each condition also supports `not_contains` as a negative guard
(matched text must NOT contain the specified substring).

### Field Selection

- `"summary"` -- packet header text only.
- `"body"` -- joined body lines.
- `"full"` -- summary + newline + body.

### Variable Extraction

Rules can extract values from packet text for annotation interpolation:

```json
"extract": {
  "reason": {
    "pattern": "Reason:\\s*(.+)",
    "field": "body",
    "default": "?"
  }
},
"annotation": "Disconnect: {reason}"
```

The `ExtractDef` class compiles the regex at rule load time.  At
match time, group 1 of the first match replaces `{name}` in the
annotation template.

### Flags

Rules can set boolean flags on the annotator instance:
```json
"set_flag": "saw_pairing_req"
```

These flags are used by `diagnose.absence_checks` to detect when an
expected event never occurred (e.g. `saw_pairing_req` is True but
`saw_encrypt` is False means pairing started but encryption never
completed).

## Procedural Hooks

Complex annotators override `_run_hooks(pkt)` for logic that cannot
be expressed declaratively:

- **State machine tracking** (A2DP AVDTP states, LE Audio ASE states)
- **Cross-packet correlation** (AVDTP label -> SEID mapping)
- **Raw byte decoding** (ASE CP opcode parsing, LTV codec config)
- **Deduplication** (PA Report BASE hashing, BIG Info repeat detection)
- **Buffered confirmation** (ASE CP handle confirmation via valid
  opcode sequences)

Hooks return `True` to indicate the packet was fully handled (skip
declarative rules) or `False` to fall through to match_rules.

## Annotator Details

### LEAudioAnnotator

The most complex annotator, handling both unicast CIS and broadcast
BIG flows.

**Hooks (all logic in `_run_hooks`):**

| Hook Area | What It Does |
|-----------|--------------|
| Init filter | Skips HCI init commands that list codec names |
| MGMT daemon restart | Detects `@ MGMT Close: bluetoothd` + `@ MGMT Open: bluetoothd` sequences |
| PA sync | Tags Periodic Advertising Sync Established/Transfer, Create Sync |
| PA Reports | Hashes BASE data for dedup; first unique = key, repeats = context |
| BIG Info | First = key, subsequent repeats = context |
| BIG sync | Tags BIG Create Sync, Established (with status), Lost, Terminate |
| ASE CP (decoded) | Tags ASE Control Point when btmon can decode GATT operations |
| ASE CP (raw ATT) | Buffers raw ATT Write Commands/Notifications, confirms ASE CP handle via valid opcode sequences |
| ASE state | Tags ASE state notifications, tracks per-ASE peak state |
| CIG/CIS | Tags Set CIG Parameters, Create CIS, CIS Established, Accept, Request |
| ISO data path | Tags Setup ISO with Data Path extraction |
| ISO/CIS data | Counts CIS data packets; tags first 2 + every 500th as context |
| BASS | Tags Add/Modify/Remove Source operations |
| Codec info | Tags LC3 codec configuration in PACS |
| Connection events | Tags LE connection complete, disconnects |

**ASE CP Raw ATT Buffering:**

When GATT discovery is absent, btmon shows raw ATT operations instead
of decoded LE Audio GATT.  The annotator:

1. Buffers ATT Write Commands whose first data byte matches an ASE CP
   opcode (0x01-0x08) and second byte is a plausible `num_ase` (1-8).
2. Groups candidates by ATT handle.
3. Confirms when a handle has >= 2 writes with valid ASE state machine
   transitions (first must be Config Codec = 0x01).
4. On confirmation, retroactively tags all buffered packets and
   switches to immediate tagging for subsequent packets.

**LTV Byte Decoding:**

For Config Codec (0x01) writes, parses Codec Configuration LTV bytes:
- Type 0x01: Sampling Frequency (8kHz - 384kHz)
- Type 0x02: Frame Duration (7.5ms, 10ms)
- Type 0x03: Audio Channel Allocation (4-byte bitmask)
- Type 0x04: Octets per Codec Frame
- Type 0x05: Codec Frames Blocks per SDU

**Broadcast Subcategory Demotion:**

In `finalize()`, when the trace is broadcast-dominant (PA/BIG/BASS
activity present, no ASE state progression), unicast-only key frames
(PACS, ASCS, ASE_CP, ASE_STATE tags) are demoted to context priority
to avoid wasting the LLM's output budget on irrelevant frames.

**Per-ASE Stream Tracking:**

Tracks `_ase_streams[ase_id]` with codec, config, state, direction.
Peak state (highest rank reached: Codec Configured < QoS Configured
< Enabling < Streaming) is recorded separately in `_ase_peak_state`.
Used to produce `STREAM:` diagnostic lines in finalize.

### A2DPAnnotator

Tracks the AVDTP signaling state machine and extracts codec
configuration.

**Hooks (all AVDTP logic in `_run_hooks` -> `_annotate_avdtp`):**

| Hook Area | What It Does |
|-----------|--------------|
| AVDTP signaling | Dispatches to signal-specific handlers (Discover, Get Capabilities, Set Configuration, Open, Start, Suspend, Close, Abort, Delay Report) |
| L2CAP for AVDTP | Tags L2CAP connections on PSM 25 |
| Media data | Counts ACL packets with dlen > 200; tags first 2 + every 500th as context |
| Connection events | Tags Connection Complete, disconnects |
| Latency monitoring | Flags Number of Completed Packets with latency >= 20ms |

**AVDTP State Machine:**

Per-SEID tracking: `Idle -> Configured -> Open -> Streaming`.
State transitions are recorded with timestamp, old state, new state,
and trigger command for the `STATE:` diagnostic table.

**Label-SEID Correlation:**

AVDTP responses don't always include the SEID.  The annotator stores
a `label -> SEID` mapping from command packets and uses it to resolve
SEIDs in response packets.

**Codec Config Parsing:**

`_parse_codec_config()` extracts from Set Configuration body:
- Media Codec name (SBC, AAC, vendor)
- Frequency, Channel Mode, Bitpool range
- AAC: Object Type, Bitrate, VBR, Channels
- Vendor: Vendor ID, Vendor Specific Codec ID

**Discover Response Parsing:**

`_parse_discover_response()` extracts SEP info: SEID, Media Type,
SEP Type (SNK/SRC), In Use flag.  Stored in `_discovered_seps` for
direction inference in STREAM diagnostics.

### HFPAnnotator

**Hooks:**

| Hook | What It Does |
|------|--------------|
| RFCOMM | Tags SABM/UA setup, UIH data (AT commands), DISC teardown |
| SCO Complete | Tags Synchronous Connection Complete with status |
| Disconnect | Tags disconnect with graceful/error distinction |

**Match rules (5):** AT command patterns (+BRSF, +BAC, +BCS, +CIND,
+CHLD) tagged as `[RFCOMM, HFP]` with decoded annotations.

### SMPAnnotator

**Hooks (1):** Encryption Change event with status extraction.

**Match rules (11):** Pairing Request/Response, Confirm/Random values,
Public Key, DHKey Check, Identity Resolving Key, Identity Address,
Signing Info, Pairing Failed, Security Request.  Each sets a flag
(e.g. `saw_pairing_req`, `saw_confirm`, `saw_pubkey`).

### ConnectionsAnnotator

**Hooks (2):** Connection Complete (extracts handle + role + status),
Disconnect (extracts handle, classifies graceful/error).

**Match rules (4):** Create Connection, LE Create Connection,
Connection Parameter Update, Read Remote Features.

### DisconnectionAnnotator

**Hooks (1):** Disconnect with handle extraction and graceful
classification.

**Match rules (4):** Create Connection, LE Create Connection,
Connection Complete, Disconnect Complete -- all with handle and status
extraction.

### L2CAPAnnotator

**Hooks (1, all procedural):** Comprehensive L2CAP handler:
Connection Request/Response (with PSM), Configuration
Request/Response, Disconnection Request, Command Reject, LE CoC
Request/Response, generic PSM references.

**Match rules:** None (all logic in hooks).

### AdvertisingAnnotator

**Pure declarative** -- no hooks, no custom finalize.

**Match rules (5):** Extended Advertising Report, Set Advertising
Parameters, Set Scan Parameters, Set Advertising Enable, Set Scan
Enable.  Tags and annotations extracted from packet text.

### HCIInitAnnotator

**Custom `annotate_packet` flow:** Runs declarative rules first via
`_apply_match_rules()`.  If no rule matched (packet still untagged),
falls through to `_run_hooks()`.

**Hooks (1):** Command Complete/Status with non-Success status ->
tags as command failure.

**Match rules (6):** Read Local Version, Read BD ADDR, Read Local
Supported Commands, Set Event Mask, Read Local Supported Features,
LE Read Local P-256 Public Key.

## Annotator Registry

The `ANNOTATORS` dict maps focus area strings to annotator classes:

```python
ANNOTATORS = {
    "Audio / LE Audio": LEAudioAnnotator,
    "Audio / A2DP": A2DPAnnotator,
    "Audio / HFP": HFPAnnotator,
    "Pairing / Security": SMPAnnotator,
    "Connection issues": ConnectionsAnnotator,
    "L2CAP channel issues": L2CAPAnnotator,
    "Advertising / Scanning": AdvertisingAnnotator,
    "Controller enumeration": HCIInitAnnotator,
    "Disconnection analysis": DisconnectionAnnotator,
}
```

`get_annotator("Audio")` returns a list of all three audio annotators
(`[A2DPAnnotator, HFPAnnotator, LEAudioAnnotator]`), which are run
sequentially on the same packet list.

## annotate_trace()

The top-level entry point:

1. Parse packets via `parse_packets(text)`.
2. Look up annotator via `get_annotator(focus)`.
3. If annotator is a list (Audio focus), run each sequentially on the
   same packets, merging diagnostics.
4. Return `(packets, diagnostics, annotator_found)`.

## Annotation Markdown (`format_annotation_markdown`)

Produces the Step 3 GitHub comment:

- Packet counts (total, key, context, skipped) and time span.
- **Key Frames** table: `| # | Timestamp | Tags | Description |`
- Capped at 50 rows.  Shows `... and N more` if truncated.

## Summary Table

| Annotator | Match Rules | Hooks | Diagnose Absence | Diagnose Notes |
|-----------|:-----------:|:-----:|:----------------:|:--------------:|
| HCIInitAnnotator | 6 | 1 | -- | -- |
| AdvertisingAnnotator | 5 | 0 | -- | -- |
| SMPAnnotator | 11 | 1 | 2 | -- |
| ConnectionsAnnotator | 4 | 2 | -- | -- |
| DisconnectionAnnotator | 4 | 1 | -- | -- |
| L2CAPAnnotator | 0 | 1 | -- | -- |
| HFPAnnotator | 5 | 3 | 1 | -- |
| LEAudioAnnotator | 0 | all | 6 | 1 |
| A2DPAnnotator | 0 | all | 3 | -- |
