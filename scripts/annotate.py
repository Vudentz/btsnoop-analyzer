#!/usr/bin/env python3
"""
annotate.py - Focus-area-specific trace annotation and prefiltering.

Parses decoded btmon output into structured packets, then applies
focus-specific annotators that:
  1. Tag key packets with semantic labels (e.g. [PA_ESTABLISHED])
  2. Mark error/failure packets
  3. Produce a budget-aware prefiltered log with annotations that
     an LLM can consume efficiently

Each annotator understands the protocol flow for its area and can
detect absence-based issues (expected events that never appeared).

Usage as a module:
    from annotate import prefilter

Usage standalone (for debugging):
    python3 scripts/annotate.py --focus "Audio / LE Audio" < decoded.txt
"""

import re
import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

# Matches btmon packet header lines.  Captures:
#   direction  - <, >, @, = or first word
#   summary    - the rest of the header text (command/event name, etc.)
#   frame      - frame number (#N), may be absent for meta lines
#   timestamp  - float seconds at end of line
#
# Examples:
#   > HCI Event: LE Meta Event (0x3e) plen 20   #474 [hci0] 156.992633
#   < HCI Command: LE BIG Create Sync ...        #123 [hci0] 42.001
#   @ MGMT Event: Device Connected ...          {0x0001} [hci0] 57.056
#   = bluetoothd: src/device.c:foo()                      57.058
#   > LE-CIS: Handle 2304 SN 4.. flags 0x02 ...  #26 [hci0] 63.636
#   > ACL: Handle 2048 flags 0x02 dlen 7         #1 [hci0] 62.880
HEADER_RE = re.compile(
    r'^([<>@=])\s+'           # direction marker
    r'(.+?)'                  # summary (non-greedy)
    r'(?:\s+#(\d+))?'         # optional frame number
    r'\s+\[hci\d+\]\s+'       # [hciN] (specific match avoids eating [addr..])
    r'(\d+\.\d+)\s*$'         # timestamp
)

# Fallback for = lines that have no [hciN] but end with a timestamp
META_RE = re.compile(
    r'^([=])\s+'
    r'(.+?)'
    r'\s+(\d+\.\d+)\s*$'
)


@dataclass
class Packet:
    """A single btmon packet/event with its body lines."""
    line_start: int          # 0-based line index in the full text
    line_end: int            # inclusive last line index
    direction: str           # '<', '>', '@', '='
    summary: str             # header text after direction marker
    frame: int = -1          # #N frame number, -1 if absent
    timestamp: float = 0.0   # seconds
    body: list = field(default_factory=list)  # indented body lines

    # Set by annotators:
    tags: list = field(default_factory=list)       # semantic labels
    priority: str = "skip"   # "key", "context", "skip"
    annotation: str = ""     # one-line annotation for the LLM

    @property
    def text(self):
        """Full packet text (header + body)."""
        return "\n".join([self.header_line] + self.body)

    @property
    def header_line(self):
        """Reconstruct the first line (used in output)."""
        # We store the raw header line during parsing instead
        return self._raw_header

    def body_contains(self, pattern):
        """Check if any body line matches the regex pattern."""
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        for line in self.body:
            if pattern.search(line):
                return True
        return False

    def body_search(self, pattern):
        """Return the first body line matching pattern, or None."""
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        for line in self.body:
            m = pattern.search(line)
            if m:
                return m
        return None

    def full_text_contains(self, pattern):
        """Check header + body for pattern."""
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        if pattern.search(self._raw_header):
            return True
        return self.body_contains(pattern)


def parse_packets(text):
    """Parse decoded btmon output into a list of Packet objects.

    Lines that don't belong to any packet (e.g. the initial
    "Bluetooth monitor ver" line) are silently skipped.
    """
    lines = text.splitlines()
    packets = []
    current = None

    for i, line in enumerate(lines):
        # Try to match a packet header
        m = HEADER_RE.match(line)
        if not m:
            m = META_RE.match(line)

        if m:
            # Start a new packet
            if current is not None:
                current.line_end = i - 1
                packets.append(current)

            groups = m.groups()
            direction = groups[0]
            summary = groups[1].strip()

            if len(groups) == 4:
                # HEADER_RE: direction, summary, frame, timestamp
                frame = int(groups[2]) if groups[2] else -1
                timestamp = float(groups[3])
            else:
                # META_RE: direction, summary, timestamp
                frame = -1
                timestamp = float(groups[2])

            current = Packet(
                line_start=i,
                line_end=i,
                direction=direction,
                summary=summary,
                frame=frame,
                timestamp=timestamp,
            )
            current._raw_header = line
        elif current is not None:
            # Body line of the current packet
            current.body.append(line)

    if current is not None:
        current.line_end = len(lines) - 1
        packets.append(current)

    return packets


# ---------------------------------------------------------------------------
# Base annotator
# ---------------------------------------------------------------------------

class Annotator:
    """Base class for focus-specific packet annotators.

    Subclasses override ``annotate_packet()`` to tag individual packets
    and ``finalize()`` to run absence checks or flow-level analysis
    after all packets have been seen.
    """

    # Human-readable name for the annotator
    name = "base"

    def annotate(self, packets):
        """Run the full annotation pass over a list of packets.

        Returns a list of diagnostic messages (absence errors, flow
        issues, etc.) discovered during finalization.
        """
        for pkt in packets:
            self.annotate_packet(pkt)
        return self.finalize(packets)

    def annotate_packet(self, pkt):
        """Tag a single packet.  Override in subclasses."""
        pass

    def finalize(self, packets):
        """Post-scan analysis (absence checks, flow validation).

        Returns a list of diagnostic message strings.
        Override in subclasses.
        """
        return []

    @staticmethod
    def _tag(pkt, tag, priority="key", annotation=""):
        """Helper to add a tag and upgrade priority."""
        pkt.tags.append(tag)
        if annotation:
            if pkt.annotation:
                pkt.annotation += "; " + annotation
            else:
                pkt.annotation = annotation
        # Priority escalation: skip < context < key
        rank = {"skip": 0, "context": 1, "key": 2}
        if rank.get(priority, 0) > rank.get(pkt.priority, 0):
            pkt.priority = priority

    # Reason codes that indicate graceful (intentional) disconnection.
    # These are NOT flagged as errors.
    GRACEFUL_REASONS = re.compile(
        r"Remote User Terminated|"
        r"Connection Terminated By Local Host|"
        r"0x13\b|0x16\b"
    )

    @classmethod
    def _is_graceful_disconnect(cls, pkt):
        """Return True if this Disconnect packet is a graceful teardown.

        Graceful disconnects are:
        - HCI Command: Disconnect (direction '<') — local host initiated
        - Disconnect Complete with Success and a graceful reason code
        """
        body_text = "\n".join(pkt.body)

        # Local-initiated Disconnect command is always graceful
        if pkt.direction == "<" and "HCI Command: Disconnect" in pkt.summary:
            return True

        # Disconnect Complete with graceful reason
        if "Disconnect Complete" in pkt.summary:
            if "Success" in body_text and cls.GRACEFUL_REASONS.search(body_text):
                return True

        return False

    def _tag_disconnect(self, pkt, handle="?"):
        """Tag a disconnect packet, distinguishing graceful from error.

        Graceful disconnects get priority=context (informational).
        Non-graceful disconnects get priority=key (potential issue).
        """
        body_text = "\n".join(pkt.body)
        reason_m = re.search(r"Reason:\s*(.+)", body_text)
        reason = reason_m.group(1).strip() if reason_m else "?"

        if self._is_graceful_disconnect(pkt):
            if handle != "?":
                ann = f"Graceful disconnect handle={handle}: {reason}"
            else:
                ann = f"Graceful disconnect: {reason}"
            self._tag(pkt, "GRACEFUL_DISCONNECT", priority="context",
                      annotation=ann)
        else:
            if handle != "?":
                ann = f"Disconnect handle={handle}: {reason}"
            else:
                ann = f"Disconnect: {reason}"
            self._tag(pkt, "DISCONNECT", annotation=ann)


# ---------------------------------------------------------------------------
# LE Audio annotator
# ---------------------------------------------------------------------------

class LEAudioAnnotator(Annotator):
    """Annotator for LE Audio traces (unicast CIS + broadcast BIG)."""

    name = "le_audio"

    # ASE Control Point opcodes (BAP spec Table 5.2)
    _ASE_OPCODES = {
        0x01: "Config Codec",
        0x02: "Config QoS",
        0x03: "Enable",
        0x04: "Receiver Start Ready",
        0x05: "Disable",
        0x06: "Receiver Stop Ready",
        0x07: "Update Metadata",
        0x08: "Release",
    }

    def __init__(self):
        self.saw_pa_sync = False
        self.saw_big_info = False
        self.saw_big_create_sync = False
        self.saw_big_sync_established = False
        self.saw_cis_established = False
        self.saw_ase_control = False
        self.saw_set_cig = False
        self.saw_create_cis = False
        self.saw_setup_iso = False
        self.saw_iso_data = False
        self.saw_coding_format = False
        self.cis_data_count = 0
        self.ase_cp_handle = None   # handle used for ASE Control Point writes
        self.ase_state_handle = None  # handle used for ASE state notifications

    @staticmethod
    def _extract_att_data(body_lines):
        """Extract ATT handle and first data bytes from body lines.

        Returns (handle_str, data_bytes) or (None, None).
        handle_str is e.g. "0x0095", data_bytes is a list of ints.
        """
        handle = None
        data_bytes = []
        in_data = False
        for line in body_lines:
            stripped = line.strip()
            hm = re.match(r'Handle:\s*(0x[0-9a-fA-F]+)', stripped)
            if hm and handle is None:
                handle = hm.group(1)
            if re.match(r'Data\[\d+\]:', stripped):
                in_data = True
                continue
            if in_data:
                # Data lines look like: "01 02 03 ... <ascii>"
                # Extract hex bytes (stop at double-space or ASCII)
                hex_part = re.match(r'((?:[0-9a-fA-F]{2}\s+)+)', stripped)
                if hex_part:
                    data_bytes.extend(
                        int(b, 16) for b in hex_part.group(1).split()
                    )
                in_data = False
        return handle, data_bytes

    def _try_decode_ase_cp_write(self, pkt, body_text):
        """Check if pkt is an ATT Write Command to the ASE Control Point.

        btmon doesn't decode LE Audio GATT-level operations; it only
        shows raw ATT: Write Command with hex data.  We decode the ASE
        Control Point opcode from the first byte of the data payload.

        Returns True if the packet was tagged as an ASE operation.
        """
        if "ATT: Write Command" not in body_text:
            return False
        handle, data = self._extract_att_data(pkt.body)
        if not handle or not data:
            return False
        opcode = data[0]
        op_name = self._ASE_OPCODES.get(opcode)
        if op_name is None:
            return False
        # Validate: second byte should be num_ase (1-4 typical)
        if len(data) >= 2 and not (1 <= data[1] <= 8):
            return False
        self.ase_cp_handle = handle
        self._tag(pkt, "ASE_CONTROL",
                  annotation=f"ASE Control Point: {op_name}")
        self.saw_ase_control = True
        return True

    def _try_decode_ase_notification(self, pkt, body_text):
        """Check if pkt is an ATT notification related to ASE state.

        ASE CP response notifications come from the CP handle (0x0095).
        ASE state notifications come from a different handle (0x0089)
        on the same ACL connection.

        Returns True if the packet was tagged.
        """
        if "ATT: Handle Value Notification" not in body_text:
            return False
        handle, data = self._extract_att_data(pkt.body)
        if not handle or not data:
            return False

        if self.ase_cp_handle and handle == self.ase_cp_handle:
            # CP response notification — opcode echo + status
            opcode = data[0]
            op_name = self._ASE_OPCODES.get(opcode, f"op 0x{opcode:02x}")
            status = "Success" if len(data) >= 4 and data[3] == 0 else "?"
            self._tag(pkt, "ASE_CP_RESPONSE", priority="context",
                      annotation=f"ASE CP response: {op_name} ({status})")
            return True

        if self.ase_cp_handle and handle != self.ase_cp_handle:
            # Likely ASE state notification from ASE characteristic
            self.ase_state_handle = handle
            # data[0] = ASE_ID, data[1] = state
            ase_states = {
                0x00: "Idle", 0x01: "Codec Configured",
                0x02: "QoS Configured", 0x03: "Enabling",
                0x04: "Streaming", 0x05: "Disabling",
            }
            ase_id = data[0] if data else "?"
            state_val = data[1] if len(data) >= 2 else None
            state_name = ase_states.get(state_val,
                                        f"0x{state_val:02x}" if state_val
                                        is not None else "?")
            self._tag(pkt, "ASE_STATE", priority="context",
                      annotation=f"ASE ID {ase_id} state: {state_name}")
            return True

        return False

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        # btmon nests LE sub-event names inside the body under
        # "LE Meta Event (0x3e)" headers, and HCI command names may
        # be truncated in the summary.  Search both locations.
        full = s + "\n" + body_text

        # --- Broadcast receiver flow ---

        if "Periodic Advertising Sync Established" in full or \
                "Periodic Advertising Sync Transfer Received" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "PA_ESTABLISHED",
                      annotation=f"PA sync established (Status: {status})")
            if "Success" in body_text:
                self.saw_pa_sync = True

        elif "Periodic Advertising Create Sync" in full:
            self._tag(pkt, "PA_CREATE_SYNC",
                      annotation="Host requesting PA sync")

        elif "Periodic Advertising Sync Transfer Parameters" in full:
            self._tag(pkt, "PAST_PARAMS", priority="context",
                      annotation="PAST parameters configured")

        elif "Periodic Advertising Report" in full:
            if "Basic Audio Announcement" in body_text:
                self._tag(pkt, "PA_REPORT_BASE",
                          annotation="PA Report with BASE data")
            else:
                self._tag(pkt, "PA_REPORT", priority="context",
                          annotation="PA Report")

        elif "BIG Info Advertising Report" in full:
            self._tag(pkt, "BIG_INFO",
                      annotation="BIG Info received -- BIG exists "
                                 "on this PA train")
            self.saw_big_info = True

        elif "BIG Create Sync" in full:
            self._tag(pkt, "BIG_CREATE_SYNC",
                      annotation="Host requesting BIG sync")
            self.saw_big_create_sync = True

        elif "BIG Sync Established" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "BIG_SYNC_ESTABLISHED",
                      annotation=f"BIG sync result: {status}")
            self.saw_big_sync_established = True
            if "Success" not in body_text:
                self._tag(pkt, "ERROR",
                          annotation="BIG sync FAILED")

        elif "BIG Sync Lost" in full:
            self._tag(pkt, "BIG_SYNC_LOST",
                      annotation="BIG sync lost")

        elif "BIG Terminate" in full:
            self._tag(pkt, "BIG_TERMINATE",
                      annotation="BIG terminated")

        # --- Unicast CIS flow ---

        elif "ASE Control Point" in full:
            # Determine the ASE operation from body
            op = "write"
            for kw in ("Config Codec", "Config QoS", "Enable",
                       "Disable", "Release", "Receiver Start",
                       "Receiver Stop"):
                if kw in body_text:
                    op = kw
                    break
            self._tag(pkt, "ASE_CONTROL",
                      annotation=f"ASE Control Point: {op}")
            self.saw_ase_control = True

        elif re.search(r"ASE ID:", body_text):
            # ASE state notification
            state_m = re.search(r"State:\s*(.+)", body_text)
            state = state_m.group(1).strip() if state_m else "?"
            self._tag(pkt, "ASE_STATE", priority="context",
                      annotation=f"ASE state: {state}")

        # --- Raw ATT fallback for ASE operations ---
        # btmon does not decode LE Audio GATT-level operations; it
        # only shows raw ATT: Write Command / Handle Value Notification.
        # Decode ASE Control Point opcodes from the first data byte.
        elif self._try_decode_ase_cp_write(pkt, body_text):
            pass  # tagged inside helper

        elif self._try_decode_ase_notification(pkt, body_text):
            pass  # tagged inside helper

        elif "Set CIG Parameters" in full:
            self._tag(pkt, "SET_CIG",
                      annotation="CIG parameters configured")
            self.saw_set_cig = True

        elif "Create CIS" in full and "Create CIS" not in body_text \
                or re.search(r"LE Create CIS\b", full):
            # Match the HCI command; avoid matching CIS Established body
            self._tag(pkt, "CREATE_CIS",
                      annotation="CIS creation requested")
            self.saw_create_cis = True

        elif "Connected Isochronous Stream Established" in full or \
                "CIS Established" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "CIS_ESTABLISHED",
                      annotation=f"CIS established: {status}")
            self.saw_cis_established = True
            if "Success" not in body_text:
                self._tag(pkt, "ERROR",
                          annotation="CIS establishment FAILED")

        elif "Accept Connected Isochronous Stream" in full:
            self._tag(pkt, "CIS_ACCEPT",
                      annotation="CIS accept sent")

        elif "Connected Isochronous Stream Request" in full:
            self._tag(pkt, "CIS_REQUEST",
                      annotation="CIS connection request from remote")
            self.saw_create_cis = True

        elif "Setup ISO" in full or "Setup Isochrono" in full:
            # Capture the coding format if present
            fmt_m = re.search(r"Coding Format:\s*(.+?)(?:\s*$)",
                              body_text, re.MULTILINE)
            fmt_note = ""
            if fmt_m:
                fmt_note = f" (Coding Format: {fmt_m.group(1).strip()})"
                self.saw_coding_format = True
            self._tag(pkt, "SETUP_ISO_PATH",
                      annotation=f"ISO data path configured{fmt_note}")
            self.saw_setup_iso = True

        elif re.match(r'[<>]\s*LE-CIS:', pkt._raw_header) or \
                "ISO Data" in s:
            self.cis_data_count += 1
            self.saw_iso_data = True
            # Only tag first pair and sparse samples for timing reference
            if self.cis_data_count <= 2 or self.cis_data_count % 500 == 0:
                self._tag(pkt, "ISO_DATA", priority="context",
                          annotation=f"ISO data #{self.cis_data_count}")
            # else: leave as skip (bulk data)

        # --- BASS ---

        elif "Add Source" in body_text:
            self._tag(pkt, "BASS_ADD_SOURCE",
                      annotation="BASS Add Source")

        # --- Codec info ---

        elif "LC3" in body_text and ("Codec:" in body_text or
                                      "Sampling Frequency" in body_text):
            self._tag(pkt, "CODEC_CONFIG", priority="context",
                      annotation="LC3 codec configuration")

        # --- Connection events relevant to LE Audio ---

        elif "LE Enhanced Connection Complete" in full or \
                "LE Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "LE_CONNECTION",
                      annotation=f"LE connection: {status}")

        elif "Disconnect" in s and pkt.direction in ("<", ">"):
            self._tag_disconnect(pkt)

    def finalize(self, packets):
        diags = []

        # Broadcast receiver absence checks
        if self.saw_pa_sync and not self.saw_big_info:
            diags.append(
                "ABSENCE: PA sync established but BIG Info Advertising "
                "Report never received -- BIG does not exist on this "
                "PA train, or broadcaster has not started it.")

        if self.saw_big_info and not self.saw_big_create_sync:
            diags.append(
                "ABSENCE: BIG Info received but host never sent "
                "BIG Create Sync -- host-side logic failed to act.")

        if self.saw_big_create_sync and not self.saw_big_sync_established:
            diags.append(
                "ABSENCE: BIG Create Sync sent but BIG Sync never "
                "established -- controller could not sync to BIG.")

        # Unicast CIS absence checks
        if self.saw_create_cis and not self.saw_cis_established:
            diags.append(
                "ABSENCE: Create CIS sent but CIS Established never "
                "received.")

        if self.saw_cis_established and not self.saw_setup_iso:
            diags.append(
                "ABSENCE: CIS established but Setup ISO Data Path "
                "never sent.")

        if self.saw_setup_iso and not self.saw_iso_data:
            diags.append(
                "ABSENCE: ISO data path set up but no ISO data "
                "packets observed.")

        # Summary annotation for ISO data (explicitly normal -- prevents
        # the LLM from flagging normal streaming volume as a problem).
        if self.cis_data_count > 0:
            diags.append(
                f"NOTE: {self.cis_data_count} ISO/CIS data packets "
                f"were streamed (normal LE Audio traffic, bulk data "
                f"omitted from prefiltered log).")

        return diags


# ---------------------------------------------------------------------------
# A2DP annotator
# ---------------------------------------------------------------------------

class A2DPAnnotator(Annotator):
    """Annotator for A2DP / AVDTP traces."""

    name = "a2dp"

    def __init__(self):
        self.saw_discover = False
        self.saw_set_config = False
        self.saw_open = False
        self.saw_start = False
        self.saw_media_data = False
        self.media_data_count = 0

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "AVDTP:" in full:
            # Parse AVDTP signaling
            for line in [s] + pkt.body:
                if "Discover" in line and "Response" not in line:
                    self._tag(pkt, "AVDTP_DISCOVER",
                              annotation="AVDTP Discover")
                    self.saw_discover = True
                    return
                elif "Discover" in line and "Response" in line:
                    self._tag(pkt, "AVDTP_DISCOVER_RSP",
                              annotation="AVDTP Discover Response")
                    return
                elif "Get All Capabilities" in line or \
                        "Get Capabilities" in line:
                    self._tag(pkt, "AVDTP_GET_CAP", priority="context",
                              annotation="AVDTP Get Capabilities")
                    return
                elif "Set Configuration" in line:
                    accept = "Accept" in line
                    self._tag(pkt, "AVDTP_SET_CONFIG",
                              annotation="AVDTP Set Configuration"
                              + (" Accept" if accept else ""))
                    self.saw_set_config = True
                    return
                elif "Open" in line and "AVDTP" in line:
                    accept = "Accept" in line
                    self._tag(pkt, "AVDTP_OPEN",
                              annotation="AVDTP Open"
                              + (" Accept" if accept else ""))
                    self.saw_open = True
                    return
                elif "Start" in line and "AVDTP" in line:
                    accept = "Accept" in line
                    self._tag(pkt, "AVDTP_START",
                              annotation="AVDTP Start"
                              + (" Accept" if accept else ""))
                    self.saw_start = True
                    return
                elif "Suspend" in line and "AVDTP" in line:
                    self._tag(pkt, "AVDTP_SUSPEND",
                              annotation="AVDTP Suspend")
                    return
                elif "Close" in line and "AVDTP" in line:
                    self._tag(pkt, "AVDTP_CLOSE",
                              annotation="AVDTP Close")
                    return
                elif "Abort" in line and "AVDTP" in line:
                    self._tag(pkt, "AVDTP_ABORT",
                              annotation="AVDTP Abort -- ERROR")
                    return
                elif "Response Reject" in line:
                    self._tag(pkt, "AVDTP_REJECT",
                              annotation="AVDTP REJECTED")
                    return

        if "Media Codec:" in body_text:
            codec_m = re.search(r"Media Codec:\s*(.+)", body_text)
            codec = codec_m.group(1).strip() if codec_m else "?"
            self._tag(pkt, "CODEC_CONFIG", priority="context",
                      annotation=f"Codec: {codec}")

        elif "PSM: 25" in body_text:
            self._tag(pkt, "L2CAP_AVDTP", priority="context",
                      annotation="L2CAP for AVDTP (PSM 25)")

        # ACL media transport data -- high volume, summarize
        elif pkt.direction in ("<", ">") and \
                "ACL:" in pkt._raw_header and \
                not pkt.tags:
            # Check if this looks like A2DP media data (large ACL on
            # the media transport channel) -- heuristic: large dlen
            dlen_m = re.search(r'dlen\s+(\d+)', pkt._raw_header)
            if dlen_m and int(dlen_m.group(1)) > 200:
                self.media_data_count += 1
                self.saw_media_data = True
                if self.media_data_count <= 2 or \
                        self.media_data_count % 500 == 0:
                    self._tag(pkt, "MEDIA_DATA", priority="context",
                              annotation=f"A2DP media data "
                              f"#{self.media_data_count}")

        # Connection events
        if "Connection Complete" in full and not pkt.tags:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "CONNECTION",
                      annotation=f"Connection: {status}")

        elif "Disconnect" in s and pkt.direction in ("<", ">") \
                and not pkt.tags:
            self._tag_disconnect(pkt)

        # Number of Completed Packets -- only flag anomalous latency
        elif "Number of Completed Packets" in full and not pkt.tags:
            if "Latency:" in body_text:
                # Extract the max latency value (e.g. "56 msec" from
                # "Latency: 56 msec (1-56 msec ~38 msec)")
                lat_m = re.search(r"Latency:\s*(\d+)\s*msec", body_text)
                if lat_m:
                    max_lat = int(lat_m.group(1))
                    if max_lat >= 20:
                        lat_full = re.search(
                            r"Latency:\s*(.+)", body_text)
                        lat_str = lat_full.group(1).strip() \
                            if lat_full else f"{max_lat} msec"
                        self._tag(pkt, "HIGH_LATENCY",
                                  annotation=f"High latency: {lat_str}")

    def finalize(self, packets):
        diags = []
        if self.saw_discover and not self.saw_set_config:
            diags.append(
                "ABSENCE: AVDTP Discover completed but Set "
                "Configuration never sent.")
        if self.saw_set_config and not self.saw_open:
            diags.append(
                "ABSENCE: AVDTP Set Configuration accepted but "
                "Open never sent.")
        if self.saw_open and not self.saw_start:
            diags.append(
                "ABSENCE: AVDTP Open completed but Start "
                "never sent.")
        if self.media_data_count > 0:
            diags.append(
                f"INFO: {self.media_data_count} A2DP media data "
                f"packets observed (bulk data omitted from "
                f"prefiltered log).")
        return diags


# ---------------------------------------------------------------------------
# HFP annotator
# ---------------------------------------------------------------------------

class HFPAnnotator(Annotator):
    """Annotator for HFP traces (RFCOMM + SCO)."""

    name = "hfp"

    def __init__(self):
        self.saw_rfcomm = False
        self.saw_sco_setup = False
        self.saw_sco_complete = False

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "RFCOMM:" in full:
            self.saw_rfcomm = True
            if "SABM" in body_text or "UA" in body_text:
                self._tag(pkt, "RFCOMM_SETUP",
                          annotation="RFCOMM channel setup")
            elif "UIH" in body_text:
                self._tag(pkt, "RFCOMM_DATA", priority="context",
                          annotation="RFCOMM data (AT commands)")
            elif "DISC" in body_text:
                self._tag(pkt, "RFCOMM_DISC",
                          annotation="RFCOMM disconnect")
            else:
                self._tag(pkt, "RFCOMM", priority="context",
                          annotation="RFCOMM")

        elif "PSM: 3" in body_text and "PSM: 3 " not in body_text:
            # PSM 3 = RFCOMM
            self._tag(pkt, "L2CAP_RFCOMM", priority="context",
                      annotation="L2CAP for RFCOMM (PSM 3)")

        elif "Setup Synchronous" in full or \
                "Enhanced Setup Synchronous" in full:
            self._tag(pkt, "SCO_SETUP",
                      annotation="SCO/eSCO connection setup")
            self.saw_sco_setup = True

        elif "Synchronous Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "SCO_COMPLETE",
                      annotation=f"SCO connection: {status}")
            self.saw_sco_complete = True
            if "Success" not in body_text:
                self._tag(pkt, "ERROR",
                          annotation="SCO setup FAILED")

        elif "Synchronous Connection Changed" in full:
            self._tag(pkt, "SCO_CHANGED", priority="context",
                      annotation="SCO parameters changed")

        elif "Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "CONNECTION",
                      annotation=f"Connection: {status}")

        elif "Disconnect" in s and pkt.direction in ("<", ">"):
            self._tag_disconnect(pkt)

    def finalize(self, packets):
        diags = []
        if self.saw_sco_setup and not self.saw_sco_complete:
            diags.append(
                "ABSENCE: SCO/eSCO setup sent but Synchronous "
                "Connection Complete never received.")
        return diags


# ---------------------------------------------------------------------------
# SMP annotator
# ---------------------------------------------------------------------------

class SMPAnnotator(Annotator):
    """Annotator for SMP pairing traces."""

    name = "smp"

    def __init__(self):
        self.saw_pairing_req = False
        self.saw_pairing_rsp = False
        self.saw_confirm = False
        self.saw_pubkey = False
        self.saw_dhkey = False
        self.saw_encrypt = False

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "Pairing Request" in full:
            self._tag(pkt, "PAIRING_REQ",
                      annotation="SMP Pairing Request")
            self.saw_pairing_req = True

        elif "Pairing Response" in full:
            self._tag(pkt, "PAIRING_RSP",
                      annotation="SMP Pairing Response")
            self.saw_pairing_rsp = True

        elif "Pairing Confirm" in full:
            self._tag(pkt, "PAIRING_CONFIRM", priority="context",
                      annotation="SMP Pairing Confirm")
            self.saw_confirm = True

        elif "Pairing Random" in full:
            self._tag(pkt, "PAIRING_RANDOM", priority="context",
                      annotation="SMP Pairing Random")

        elif "Pairing Public Key" in full:
            self._tag(pkt, "PUBKEY",
                      annotation="SMP Public Key (Secure Connections)")
            self.saw_pubkey = True

        elif "DHKey Check" in full:
            self._tag(pkt, "DHKEY_CHECK",
                      annotation="SMP DHKey Check")
            self.saw_dhkey = True

        elif "Pairing Failed" in full:
            reason_m = re.search(r"Reason:\s*(.+)", body_text)
            reason = reason_m.group(1).strip() if reason_m else "?"
            self._tag(pkt, "PAIRING_FAILED",
                      annotation=f"SMP Pairing FAILED: {reason}")

        elif "Encryption Change" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "ENCRYPTION_CHANGE",
                      annotation=f"Encryption change: {status}")
            self.saw_encrypt = True
            if "Success" not in body_text:
                self._tag(pkt, "ERROR",
                          annotation="Encryption change FAILED")

        elif "Identity Resolving Key" in body_text:
            self._tag(pkt, "IRK", priority="context",
                      annotation="IRK exchanged")

        elif "Long Term Key" in body_text:
            self._tag(pkt, "LTK", priority="context",
                      annotation="LTK exchanged")

        elif "Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "CONNECTION",
                      annotation=f"Connection: {status}")

    def finalize(self, packets):
        diags = []
        if self.saw_pairing_req and not self.saw_pairing_rsp:
            diags.append(
                "ABSENCE: Pairing Request sent but Pairing Response "
                "never received -- peer may not support pairing "
                "or connection was lost.")
        if self.saw_pairing_rsp and not self.saw_encrypt:
            diags.append(
                "ABSENCE: Pairing completed but Encryption Change "
                "never received.")
        return diags


# ---------------------------------------------------------------------------
# Connections annotator
# ---------------------------------------------------------------------------

class ConnectionsAnnotator(Annotator):
    """Annotator for connection lifecycle traces."""

    name = "connections"

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            handle_m = re.search(r"Handle:\s*(\d+)", body_text)
            handle = handle_m.group(1) if handle_m else "?"
            role_m = re.search(r"Role:\s*(.+)", body_text)
            role = role_m.group(1).strip() if role_m else ""
            self._tag(pkt, "CONNECT",
                      annotation=f"Connection handle={handle} "
                      f"{role} {status}")
            if "Success" not in body_text:
                self._tag(pkt, "ERROR")

        elif "Disconnect" in s and pkt.direction in ("<", ">"):
            handle_m = re.search(r"Handle:\s*(\d+)", body_text)
            handle = handle_m.group(1) if handle_m else "?"
            self._tag_disconnect(pkt, handle=handle)

        elif "Connection Update" in full:
            self._tag(pkt, "CONN_UPDATE", priority="context",
                      annotation="Connection parameters updated")

        elif "Data Length Change" in full:
            self._tag(pkt, "DLE_CHANGE", priority="context",
                      annotation="Data length changed")

        elif "Read Remote Used Features" in full:
            self._tag(pkt, "REMOTE_FEATURES", priority="context",
                      annotation="Remote features read")

        elif "Connection Timeout" in full or "Connection Failed" in full:
            self._tag(pkt, "CONN_FAIL",
                      annotation="Connection failure/timeout")


# ---------------------------------------------------------------------------
# L2CAP annotator
# ---------------------------------------------------------------------------

class L2CAPAnnotator(Annotator):
    """Annotator for L2CAP channel traces."""

    name = "l2cap"

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)

        if "L2CAP:" in s or "L2CAP:" in body_text:
            if "Connection Request" in body_text or \
                    "Connection Request" in s:
                psm_m = re.search(r"PSM:\s*(\d+)", body_text)
                psm = psm_m.group(1) if psm_m else "?"
                self._tag(pkt, "L2CAP_CONN_REQ",
                          annotation=f"L2CAP Connect Request PSM={psm}")
            elif "Connection Response" in body_text or \
                    "Connection Response" in s:
                result_m = re.search(r"Result:\s*(.+)", body_text)
                result = result_m.group(1).strip() if result_m else "?"
                self._tag(pkt, "L2CAP_CONN_RSP",
                          annotation=f"L2CAP Connect Response: {result}")
                if "Success" not in result:
                    self._tag(pkt, "ERROR")
            elif "Configuration Request" in body_text:
                self._tag(pkt, "L2CAP_CONFIG", priority="context",
                          annotation="L2CAP Config Request")
            elif "Configuration Response" in body_text:
                self._tag(pkt, "L2CAP_CONFIG_RSP", priority="context",
                          annotation="L2CAP Config Response")
            elif "Disconnection Request" in body_text:
                self._tag(pkt, "L2CAP_DISC",
                          annotation="L2CAP Disconnect Request")
            elif "Command Reject" in body_text:
                self._tag(pkt, "L2CAP_REJECT",
                          annotation="L2CAP Command REJECTED")
            else:
                self._tag(pkt, "L2CAP", priority="context",
                          annotation="L2CAP signaling")

        elif "LE Connection Request" in body_text or \
                "LE Connection Request" in s:
            psm_m = re.search(r"PSM:\s*(\d+)", body_text)
            psm = psm_m.group(1) if psm_m else "?"
            self._tag(pkt, "LE_L2CAP_COC",
                      annotation=f"LE L2CAP CoC Request PSM={psm}")

        elif "LE Connection Response" in body_text or \
                "LE Connection Response" in s:
            self._tag(pkt, "LE_L2CAP_COC_RSP",
                      annotation="LE L2CAP CoC Response")

        elif "PSM:" in body_text and not pkt.tags:
            psm_m = re.search(r"PSM:\s*(\d+)", body_text)
            psm = psm_m.group(1) if psm_m else "?"
            self._tag(pkt, "PSM_USAGE", priority="context",
                      annotation=f"PSM {psm} referenced")


# ---------------------------------------------------------------------------
# Advertising annotator
# ---------------------------------------------------------------------------

class AdvertisingAnnotator(Annotator):
    """Annotator for advertising and scanning traces."""

    name = "advertising"

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "Advertising Report" in full and \
                "BIG Info" not in full:
            addr_m = re.search(r"Address:\s*(\S+)", body_text)
            addr = addr_m.group(1) if addr_m else ""
            self._tag(pkt, "ADV_REPORT", priority="context",
                      annotation=f"Advertising report {addr}")

        elif "Set Extended Adv" in full or "Set Advertising" in full:
            self._tag(pkt, "ADV_CONFIG",
                      annotation="Advertising configuration")

        elif "Adv Enable" in full or "Advertising Enable" in full:
            self._tag(pkt, "ADV_ENABLE",
                      annotation="Advertising enable/disable")

        elif "Periodic Advertising" in full:
            self._tag(pkt, "PERIODIC_ADV", priority="context",
                      annotation="Periodic advertising")

        elif "Set Scan" in full or "Extended Scan" in full:
            self._tag(pkt, "SCAN_CONFIG", priority="context",
                      annotation="Scan configuration")


# ---------------------------------------------------------------------------
# HCI Init annotator
# ---------------------------------------------------------------------------

class HCIInitAnnotator(Annotator):
    """Annotator for HCI initialization sequence."""

    name = "hci_init"

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "Read Local Version" in full:
            self._tag(pkt, "LOCAL_VERSION",
                      annotation="Read Local Version")

        elif "Read BD ADDR" in full:
            self._tag(pkt, "BD_ADDR",
                      annotation="Read BD Address")

        elif "Read Buffer Size" in full:
            self._tag(pkt, "BUFFER_SIZE",
                      annotation="Read Buffer Size")

        elif "Set Event Mask" in full:
            self._tag(pkt, "EVENT_MASK", priority="context",
                      annotation="Set Event Mask")

        elif "Read Local Supported" in full:
            self._tag(pkt, "LOCAL_FEATURES", priority="context",
                      annotation="Read Local Supported Features/Commands")

        elif "Reset" in s and "HCI" in s:
            self._tag(pkt, "HCI_RESET",
                      annotation="HCI Reset")

        elif "Command Complete" in s or "Command Status" in s:
            if "Status:" in body_text and \
                    "Success" not in body_text:
                status_m = re.search(r"Status:\s*(.+)", body_text)
                status = status_m.group(1).strip() if status_m else "?"
                self._tag(pkt, "CMD_ERROR",
                          annotation=f"Command failed: {status}")


# ---------------------------------------------------------------------------
# Disconnection annotator (specialization of connections)
# ---------------------------------------------------------------------------

class DisconnectionAnnotator(Annotator):
    """Annotator focused on disconnection analysis."""

    name = "disconnection"

    def annotate_packet(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "Disconnect" in s and pkt.direction in ("<", ">"):
            handle_m = re.search(r"Handle:\s*(\d+)", body_text)
            handle = handle_m.group(1) if handle_m else "?"
            self._tag_disconnect(pkt, handle=handle)

        elif "Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "CONNECT",
                      annotation=f"Connection: {status}")

        elif "Supervision Timeout" in body_text:
            self._tag(pkt, "SV_TIMEOUT", priority="context",
                      annotation="Supervision timeout parameter")

        elif "Connection Timeout" in full:
            self._tag(pkt, "CONN_TIMEOUT",
                      annotation="Connection timeout")


# ---------------------------------------------------------------------------
# Annotator registry
# ---------------------------------------------------------------------------

# Map focus area strings to annotator classes.
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


def get_annotator(focus):
    """Return an Annotator instance for the given focus area.

    For the parent "Audio" focus, returns a list of audio annotators.
    Returns None if no specific annotator exists.
    """
    if focus == "Audio":
        return [A2DPAnnotator(), HFPAnnotator(), LEAudioAnnotator()]

    cls = ANNOTATORS.get(focus)
    if cls:
        return cls()
    return None


# ---------------------------------------------------------------------------
# Prefiltered log output
# ---------------------------------------------------------------------------

def _format_packet(pkt, include_body=True):
    """Format a packet for prefiltered output, with annotation prefix."""
    parts = []
    if pkt.annotation:
        parts.append(f"### [{' | '.join(pkt.tags)}] {pkt.annotation}")
    parts.append(pkt._raw_header)
    if include_body:
        parts.extend(pkt.body)
    return "\n".join(parts)


def annotate_trace(text, focus):
    """Parse and annotate a decoded btmon trace.

    Steps:
        1. Parse decoded btmon text into Packet objects
        2. Run the focus-specific annotator(s) to tag packets

    Args:
        text: Full decoded btmon output.
        focus: Focus area string (e.g. "Audio / LE Audio").

    Returns:
        (packets, diagnostics, annotator_found)
        packets: List of annotated Packet objects.
        diagnostics: List of diagnostic message strings.
        annotator_found: True if a focus-specific annotator was used.
    """
    packets = parse_packets(text)
    if not packets:
        return [], [], False

    annotator = get_annotator(focus)
    if annotator is None:
        return packets, [], False

    if isinstance(annotator, list):
        all_diags = []
        for ann in annotator:
            diags = ann.annotate(packets)
            all_diags.extend(diags)
    else:
        all_diags = annotator.annotate(packets)

    return packets, all_diags, True


def prefilter(text, focus, max_chars=24000, packets=None, diags=None):
    """Produce an annotated, prefiltered log for LLM consumption.

    Steps:
        1. Parse decoded btmon text into packets (or use pre-annotated)
        2. Run the focus-specific annotator(s) to tag packets
        3. Build output including key packets (full), context packets
           (header + annotation only if budget is tight), and skip
           gap markers
        4. Prepend a summary header with diagnostics and timeline

    Args:
        text: Full decoded btmon output.
        focus: Focus area string (e.g. "Audio / LE Audio").
        max_chars: Character budget for the output.
        packets: Optional pre-annotated Packet list (skips re-parsing).
        diags: Optional pre-computed diagnostics list.

    Returns:
        (prefiltered_text, diagnostics_list)
        The prefiltered text is ready for LLM consumption.
        diagnostics_list contains absence errors and info messages.
    """
    if packets is not None:
        # Use pre-annotated data
        all_diags = diags if diags is not None else []
        if not packets:
            return text, all_diags
    else:
        packets, all_diags, found = annotate_trace(text, focus)
        if not packets:
            return text, []
        if not found:
            # No specific annotator -- return original text truncated
            return text[:max_chars], []

    # Separate packets by priority
    key_pkts = [p for p in packets if p.priority == "key"]
    ctx_pkts = [p for p in packets if p.priority == "context"]

    # Build the summary header
    header_lines = [f"=== Prefiltered btmon log: {focus} ==="]
    header_lines.append(f"Total packets: {len(packets)}, "
                        f"Key: {len(key_pkts)}, "
                        f"Context: {len(ctx_pkts)}, "
                        f"Skipped: {len(packets) - len(key_pkts) - len(ctx_pkts)}")

    if packets:
        header_lines.append(
            f"Time span: {packets[0].timestamp:.3f}s - "
            f"{packets[-1].timestamp:.3f}s "
            f"({packets[-1].timestamp - packets[0].timestamp:.1f}s)")

    if all_diags:
        header_lines.append("")
        header_lines.append("Diagnostics:")
        for d in all_diags:
            header_lines.append(f"  * {d}")

    # Build timeline of key events
    header_lines.append("")
    header_lines.append("Key event timeline:")
    for pkt in key_pkts[:30]:  # Cap timeline at 30 entries
        header_lines.append(
            f"  {pkt.timestamp:>12.3f}s  #{pkt.frame:<5d}  "
            f"{pkt.annotation}")

    if len(key_pkts) > 30:
        header_lines.append(
            f"  ... and {len(key_pkts) - 30} more key events")

    header_lines.append("")
    header_lines.append("=== Annotated packets ===")
    header_lines.append("")

    header = "\n".join(header_lines)

    # Budget: reserve space for the header
    body_budget = max_chars - len(header) - 100  # margin
    if body_budget < 1000:
        # Not enough room even for key packets -- just return header
        return header, all_diags

    # Phase 1: Include all key packets with full body
    output_parts = []
    prev_idx = -1
    chars_used = 0

    # Merge key and context packets in order, key first priority
    tagged = [(p.line_start, p) for p in packets
              if p.priority in ("key", "context")]
    tagged.sort(key=lambda x: x[0])

    for _, pkt in tagged:
        # Calculate how much this packet would cost
        formatted = _format_packet(pkt, include_body=(pkt.priority == "key"))
        cost = len(formatted) + 50  # gap marker overhead

        if chars_used + cost > body_budget:
            # Context packets can be dropped to save budget
            if pkt.priority == "context":
                continue
            # Key packet but out of budget -- switch to header-only
            formatted = _format_packet(pkt, include_body=False)
            cost = len(formatted) + 50

        if chars_used + cost > body_budget:
            # Truly out of budget
            output_parts.append(
                f"\n[... budget exhausted, "
                f"{len(key_pkts)} key packets total ...]\n")
            break

        # Insert gap marker if there's a skip
        if prev_idx >= 0 and pkt.line_start > prev_idx + 1:
            gap_packets = sum(1 for p in packets
                              if prev_idx < p.line_start < pkt.line_start
                              and p.priority == "skip")
            if gap_packets > 0:
                output_parts.append(
                    f"\n[... {gap_packets} packets skipped ...]\n")

        output_parts.append(formatted)
        chars_used += cost
        prev_idx = pkt.line_end

    body = "\n".join(output_parts)
    return header + body, all_diags


def format_markdown(packets, diags, focus):
    """Format annotation results as a GitHub-comment-ready markdown block.

    Produces a key frames table with timestamps, frame numbers, and
    semantic labels that can be referenced in the analysis step.

    Args:
        packets: List of Packet objects (already annotated).
        diags: List of diagnostic strings from the annotator.
        focus: Focus area string.

    Returns:
        Markdown string suitable for posting as a GitHub issue comment.
    """
    key_pkts = [p for p in packets if p.priority == "key"]
    ctx_pkts = [p for p in packets if p.priority == "context"]
    graceful = [p for p in packets
                if "GRACEFUL_DISCONNECT" in p.tags]

    lines = ["## Step 2: Annotation", ""]
    lines.append(f"**Focus:** {focus}")
    lines.append(f"**Packets:** {len(packets)} total, "
                 f"{len(key_pkts)} key, {len(ctx_pkts)} context, "
                 f"{len(packets) - len(key_pkts) - len(ctx_pkts)} skipped")
    if packets:
        span = packets[-1].timestamp - packets[0].timestamp
        lines.append(f"**Time span:** {packets[0].timestamp:.3f}s - "
                     f"{packets[-1].timestamp:.3f}s ({span:.1f}s)")
    lines.append("")

    # Key frames table
    if key_pkts:
        lines.append("### Key Frames")
        lines.append("")
        lines.append("| # | Timestamp | Tags | Description |")
        lines.append("|--:|----------:|------|-------------|")
        for pkt in key_pkts[:50]:
            tags = ", ".join(f"`{t}`" for t in pkt.tags)
            lines.append(
                f"| #{pkt.frame} | {pkt.timestamp:.3f}s | "
                f"{tags} | {pkt.annotation} |"
            )
        if len(key_pkts) > 50:
            lines.append(f"| | | | "
                         f"*... and {len(key_pkts) - 50} more* |")
        lines.append("")

    # Graceful disconnects (informational, not errors)
    if graceful:
        lines.append("### Graceful Disconnects")
        lines.append("")
        for pkt in graceful:
            lines.append(
                f"- #{pkt.frame} at {pkt.timestamp:.3f}s: "
                f"{pkt.annotation}")
        lines.append("")

    # Diagnostics
    if diags:
        lines.append("### Diagnostics")
        lines.append("")
        for d in diags:
            if d.startswith("ABSENCE:"):
                lines.append(f"- :warning: {d}")
            elif d.startswith("INFO:"):
                lines.append(f"- :information_source: {d}")
            else:
                lines.append(f"- {d}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    """Read decoded btmon from stdin, print prefiltered output."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Annotate and prefilter btmon traces")
    parser.add_argument(
        "--focus", required=True,
        help="Focus area (e.g. 'Audio / LE Audio')")
    parser.add_argument(
        "--max-chars", type=int, default=24000,
        help="Character budget for output (default: 24000)")
    args = parser.parse_args()

    text = sys.stdin.read()
    if not text.strip():
        print("No input on stdin.", file=sys.stderr)
        sys.exit(1)

    output, diags = prefilter(text, args.focus, args.max_chars)
    print(output)

    if diags:
        print("\n--- Diagnostics ---", file=sys.stderr)
        for d in diags:
            print(f"  {d}", file=sys.stderr)


if __name__ == "__main__":
    main()
