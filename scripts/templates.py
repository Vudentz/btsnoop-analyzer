"""
templates.py - Diagnostic output templates for btsnoop trace analysis.

Provides structured fill-in-the-blank templates that force consistent
output regardless of which LLM is used.  Each template defines the
exact sections, headings, field labels, and table formats the model
must produce.

Templates are selected by focus area string (matching FOCUS_DOCS keys
in analyze.py).  When no area-specific template exists, the general
template is used.
"""

# ---------------------------------------------------------------------------
# Base template: common header and footer wrapping every report
# ---------------------------------------------------------------------------

_HEADER = """\
## Diagnostic Report

| Field | Value |
|-------|-------|
| **Focus area** | {focus} |
| **Auto-detected** | {auto_detected} |
| **Verdict** | {verdict} |

> **One-line summary:** {summary}\
"""

_FOOTER = """\
### Recommendations

{recommendations}

---
*Report generated from btmon trace analysis.*\
"""

# ---------------------------------------------------------------------------
# Common Audio Streams section -- shared by all audio-area templates.
# The diagnostics include STREAM: lines that the LLM uses to fill this.
# ---------------------------------------------------------------------------

_AUDIO_STREAMS = """
### Audio Streams

| ID | Direction | Codec | State | Configuration |
|----|-----------|-------|-------|---------------|
{stream_rows}
"""

# ---------------------------------------------------------------------------
# General (no area-specific template)
# ---------------------------------------------------------------------------

GENERAL = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Details |
|---|-----------|-------|---------|
{timeline_rows}

### Protocol Analysis

{protocol_analysis}

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# A2DP
# ---------------------------------------------------------------------------

A2DP = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Details |
|---|-----------|-------|---------|
{timeline_rows}
""" + _AUDIO_STREAMS + """
### AVDTP Signaling Sequence

| Step | Command / Response | SEID | Status | Notes |
|------|--------------------|------|--------|-------|
{avdtp_rows}

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# HFP
# ---------------------------------------------------------------------------

HFP = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Details |
|---|-----------|-------|---------|
{timeline_rows}

### RFCOMM Setup

| Field | Value |
|-------|-------|
| **L2CAP PSM** | 3 |
| **L2CAP CID** | {rfcomm_cid} |
| **RFCOMM DLCI** | {rfcomm_dlci} |
| **SABM/UA completed** | {sabm_ua_ok} |

### SLC Establishment (AT Commands)

| # | Direction | AT Command | Response | Notes |
|---|-----------|------------|----------|-------|
{at_cmd_rows}

### Codec Negotiation

| Field | Value |
|-------|-------|
| **AT+BAC codecs offered** | {bac_codecs} |
| **+BCS codec selected** | {bcs_codec} |
| **HCI codec ID** | {hci_codec_id} |
| **Voice Setting** | {voice_setting} |
| **Air coding format** | {air_coding} |

### SCO/eSCO Connection

| Field | Value |
|-------|-------|
| **Setup command** | {sco_setup_cmd} |
| **Connection handle** | {sco_handle} |
| **Link type** | {sco_link_type} |
| **Air mode** | {sco_air_mode} |
| **Status** | {sco_status} |

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# LE Audio
# ---------------------------------------------------------------------------

LE_AUDIO = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Details |
|---|-----------|-------|---------|
{timeline_rows}
""" + _AUDIO_STREAMS + """
### CIS/BIG Setup

| Field | Value |
|-------|-------|
| **Transport** | {transport_type} |
| **CIG/BIG ID** | {group_id} |
| **CIS/BIS handle(s)** | {stream_handles} |
| **ISO data path** | {iso_data_path} |
| **Status** | {cis_big_status} |

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# Combined Audio (A2DP + LE Audio together)
# ---------------------------------------------------------------------------

AUDIO = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Details |
|---|-----------|-------|---------|
{timeline_rows}
""" + _AUDIO_STREAMS + """
### Protocol Analysis

{protocol_analysis}

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------

CONNECTIONS = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Handle | Address | Status |
|---|-----------|-------|--------|---------|--------|
{timeline_rows}

### Active Connections

| Handle | Type | Address | Role | Encryption |
|--------|------|---------|------|------------|
{connection_rows}

### Disconnections

| Handle | Timestamp | Reason code | Reason text |
|--------|-----------|-------------|-------------|
{disconnection_rows}

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# SMP / Pairing
# ---------------------------------------------------------------------------

SMP = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Details |
|---|-----------|-------|---------|
{timeline_rows}

### Pairing Parameters

| Field | Initiator | Responder |
|-------|-----------|-----------|
| **IO Capability** | {init_io_cap} | {resp_io_cap} |
| **Auth Requirements** | {init_auth_req} | {resp_auth_req} |
| **Max Key Size** | {init_key_size} | {resp_key_size} |

### Pairing Flow

| # | Direction | PDU | Notes |
|---|-----------|-----|-------|
{pairing_rows}

| Field | Value |
|-------|-------|
| **Method** | {pairing_method} |
| **Secure Connections** | {secure_connections} |
| **Encryption status** | {encryption_status} |

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# L2CAP
# ---------------------------------------------------------------------------

L2CAP = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Details |
|---|-----------|-------|---------|
{timeline_rows}

### L2CAP Channels

| PSM | Source CID | Dest CID | Protocol | Result | MTU |
|-----|-----------|----------|----------|--------|-----|
{channel_rows}

### Signaling Issues

{signaling_issues}

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# Advertising / Scanning
# ---------------------------------------------------------------------------

ADVERTISING = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Details |
|---|-----------|-------|---------|
{timeline_rows}

### Devices Seen

| # | Address | Name | RSSI | Key Services / Flags |
|---|---------|------|------|----------------------|
{device_rows}

### Advertising Configuration (Local)

| Field | Value |
|-------|-------|
| **Advertising type** | {adv_type} |
| **Interval** | {adv_interval} |
| **Data contents** | {adv_data} |

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# Controller Enumeration / HCI Init
# ---------------------------------------------------------------------------

HCI_INIT = _HEADER + """

### Initialization Stages

| Stage | Description | Status |
|-------|-------------|--------|
| 1 | Core HCI setup (version, buffer sizes, features) | {stage1_status} |
| 2 | LE setup (features, buffer sizes, adv/scan params) | {stage2_status} |
| 3 | Event masks and filters | {stage3_status} |
| 4 | Vendor-specific commands | {stage4_status} |

### Controller Identity

| Field | Value |
|-------|-------|
| **BD Address** | {bd_addr} |
| **HCI Version** | {hci_version} |
| **LMP Version** | {lmp_version} |
| **Manufacturer** | {manufacturer} |
| **Supported commands** | {supported_cmds} |

### Buffer Configuration

| Field | ACL | SCO | LE ACL | ISO |
|-------|-----|-----|--------|-----|
| **Max packet length** | {acl_mtu} | {sco_mtu} | {le_acl_mtu} | {iso_mtu} |
| **Total packets** | {acl_pkts} | {sco_pkts} | {le_acl_pkts} | {iso_pkts} |

### Key Features

{features_list}

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# Disconnection Analysis
# ---------------------------------------------------------------------------

DISCONNECTION = _HEADER + """

### Connection Timeline

| # | Timestamp | Event | Handle | Details |
|---|-----------|-------|--------|---------|
{timeline_rows}

### Disconnection Events

| # | Timestamp | Handle | Address | Reason code | Reason text | Initiator |
|---|-----------|--------|---------|-------------|-------------|-----------|
{disconnection_rows}

### Pre-Disconnection Activity

{pre_disconnect_activity}

### Issues Found

{issues}

""" + _FOOTER

# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

# Map focus area strings to templates.  The key must match the focus
# strings used in FOCUS_DOCS (analyze.py) and AreaDef.focus (detect.py).
TEMPLATES = {
    "General (full analysis)":  GENERAL,
    "Audio / A2DP":             A2DP,
    "Audio / HFP":              HFP,
    "Audio / LE Audio":         LE_AUDIO,
    "Audio":                    AUDIO,
    "Connection issues":        CONNECTIONS,
    "Controller enumeration":   HCI_INIT,
    "Pairing / Security":       SMP,
    "GATT discovery":           GENERAL,   # no GATT-specific template yet
    "L2CAP channel issues":     L2CAP,
    "Advertising / Scanning":   ADVERTISING,
    "Disconnection analysis":   DISCONNECTION,
}


def get_template(focus):
    """Return the diagnostic template for the given focus area.

    Falls back to GENERAL if no area-specific template exists.
    """
    return TEMPLATES.get(focus, GENERAL)


def template_instructions(focus, auto_detected=False):
    """Return the LLM instruction text for producing structured output.

    This includes the template itself and strict formatting rules the
    model must follow.
    """
    template = get_template(focus)

    # Fill in the metadata fields that are known at prompt time
    template = template.replace("{focus}", focus)
    template = template.replace(
        "{auto_detected}", "Yes" if auto_detected else "No"
    )

    return f"""\
You MUST produce your output by filling in the template below.  Follow
these rules strictly:

1. **Reproduce every heading and table exactly as shown.**  Do not add,
   remove, rename, or reorder any section.
2. **Replace each {{placeholder}} with the value extracted from the trace.**
   If a value cannot be determined, write `N/A`.
3. **Table rows marked with {{..._rows}}** should be expanded to as many
   rows as needed.  Keep the column structure identical.
4. **The Verdict field** must be exactly one of: `PASS`, `FAIL`, or
   `INCONCLUSIVE`.
   - `PASS` — the protocol flow completed without errors. A clean
     connection/setup/streaming/disconnect cycle with all operations
     returning Success is a PASS, even if many data packets were
     transferred. Graceful disconnects (Remote User Terminated,
     Connection Terminated By Local Host) are normal and do NOT
     indicate failure.
   - `FAIL` — actual errors, rejects, non-Success status codes, or
     unexpected disconnections were found in the trace.
   - `INCONCLUSIVE` — the trace is incomplete or ambiguous.
5. **The one-line summary** must be a single sentence (max 120 characters).
6. **Issues Found** must use this exact format for each issue:
   ```
   **Issue N: <short title>**
   - **Timestamp:** <value from trace>
   - **What happened:** <specific values: handles, opcodes, error codes>
   - **Why it matters:** <impact on user experience or protocol compliance>
   - **Root cause:** <most likely explanation, or "Unknown" if uncertain>
   ```
   If no issues are found, write: `No issues found.`
7. **Recommendations** must be a numbered list.  Each item must be a
   concrete, actionable step (not generic advice).  If there are no
   recommendations, write: `No recommendations.`
 8. **Audio Streams table** — fill one row per stream endpoint from the
    `STREAM:` diagnostics.  The ID column is the SEID (A2DP) or ASE ID
    (LE Audio).  Direction is Sink/Source.  State is the last known
    protocol state.  Configuration includes codec parameters (frequency,
    channel mode, bitpool, frame duration, octets per frame, etc.).
    If a `STREAM:` line shows `dir=?`, you may infer the direction from
    surrounding trace context (e.g. ASE operations, SEP types); if you
    do, append `(inferred)` to the direction value in the table.
9. Do NOT add any text outside the template structure.  No preamble,
   no closing remarks, no apologies.

<output-template>
{template}
</output-template>"""
