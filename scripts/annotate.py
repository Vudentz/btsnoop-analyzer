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

Pipeline steps produced by this module:
  Step 2 (Filter):      format_filter_markdown()
  Step 3 (Annotation):  format_annotation_markdown()
  Step 4 (Diagnostics): format_diagnostics_markdown()

Usage as a module:
    from annotate import annotate_trace, prefilter
    from annotate import format_annotation_markdown
    from annotate import format_diagnostics_markdown
    from annotate import format_filter_markdown

Usage standalone (prefilter + diagnostics to stderr):
    python3 scripts/annotate.py --focus "Audio / LE Audio" < decoded.txt
    python3 scripts/annotate.py --focus "Audio / A2DP" --max-chars 16000 < decoded.txt
"""

import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field

# Import shared types from packet.py; re-export for backward compat
from packet import (  # noqa: F401
    HEADER_RE, META_RE, Packet, Diagnostic, parse_packets,
)


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
    def _tag(pkt, tags, priority="key", annotation=""):
        """Helper to add tag(s) and upgrade priority.

        ``tags`` may be a single string or a list of strings.
        """
        if isinstance(tags, str):
            pkt.tags.append(tags)
        else:
            pkt.tags.extend(tags)
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
            self._tag(pkt, "HCI", priority="context",
                      annotation=ann)
        else:
            if handle != "?":
                ann = f"Disconnect handle={handle}: {reason}"
            else:
                ann = f"Disconnect: {reason}"
            self._tag(pkt, "HCI", annotation=ann)


# ---------------------------------------------------------------------------
# Rule-driven annotator base class
# ---------------------------------------------------------------------------

class RuleMatchAnnotator(Annotator):
    """Annotator that evaluates declarative match_rules from JSON.

    Subclasses set ``name`` to match the rule file name.  At init,
    the matching RuleSet is loaded and compiled match_rules are used
    for packet annotation.  Subclasses can still override
    ``annotate_packet()`` to add procedural hooks before/after the
    declarative rules.
    """

    # HCI init commands whose body text lists protocol/command/event
    # names without representing actual protocol activity.  Matching
    # against their body produces false positives (e.g. "Set Event Mask"
    # body listing "Simple Pairing Complete", or "Read Local Supported
    # Commands" body listing "Setup Synchronous Connection").
    # Shared by all RuleMatchAnnotator subclasses.
    _INIT_COMMAND_RE = re.compile(
        r"Set Event Mask|"
        r"Read Local Supported Commands|"
        r"Read Local Supported Codec|"
        r"Read Local Supported Features|"
        r"Read Local Extended Features|"
        r"Read BD ADDR|"
        r"Read Buffer Size"
    )

    # Set to False in subclasses that intentionally match init commands
    # (e.g. HCIInitAnnotator).
    _skip_init_commands = True

    def __init__(self):
        from rules import get_rule_set
        self._ruleset = get_rule_set(self.name)

    def annotate_packet(self, pkt):
        """Evaluate match_rules against the packet.

        Hooks (subclass overrides) run first via _run_hooks().
        If a hook handles the packet, match_rules are skipped.
        Then declarative match_rules are evaluated in order.

        HCI init commands (Set Event Mask, Read Local Supported
        Commands, etc.) are skipped entirely — their body text lists
        protocol/event names that cause false-positive matches in both
        hooks and declarative rules.  Subclasses that intentionally
        match init commands (e.g. HCIInitAnnotator) set
        ``_skip_init_commands = False``.
        """
        if self._skip_init_commands:
            full = pkt.summary + "\n" + "\n".join(pkt.body)
            if self._INIT_COMMAND_RE.search(full):
                return
        if self._run_hooks(pkt):
            return
        self._apply_match_rules(pkt)

    def _run_hooks(self, pkt):
        """Override in subclasses to run procedural hooks.

        Return True if the packet was fully handled and match_rules
        should be skipped.
        """
        return False

    def _apply_match_rules(self, pkt):
        """Evaluate declarative match_rules from the RuleSet."""
        if not self._ruleset:
            return
        for rule in self._ruleset.match_rules:
            # Direction filter
            if rule.direction and pkt.direction != rule.direction:
                continue
            # Match condition
            if not rule.match.test(pkt):
                continue
            # Matched -- extract variables and build annotation
            annotation = rule.annotation
            if rule.extracts and annotation:
                for ext in rule.extracts:
                    val = ext.extract(pkt)
                    annotation = annotation.replace(
                        f"{{{ext.name}}}", val)
            # Apply tags and priority
            self._tag(pkt, list(rule.tags), priority=rule.priority,
                      annotation=annotation)
            # Set flag if specified
            if rule.set_flag:
                setattr(self, rule.set_flag, True)
            # Exclusive rule stops further evaluation
            if rule.exclusive:
                return

    def finalize(self, packets):
        """Evaluate diagnose sections from the RuleSet.

        Runs flag-based absence checks and conditional notes.
        Subclasses can extend this by calling super().finalize()
        and appending their own diagnostics.
        """
        diags = []
        if not self._ruleset:
            return diags

        # Flag-based absence checks
        for ac in self._ruleset.diagnose_absence_checks:
            cond_val = getattr(self, ac.condition_flag, False)
            missing_val = getattr(self, ac.missing_flag, False)
            if cond_val and not missing_val:
                diags.append(Diagnostic(f"ABSENCE: {ac.message}"))

        # Conditional notes
        for note in self._ruleset.diagnose_notes:
            if note.evaluate(self):
                diags.append(Diagnostic(note.format_message(self)))

        return diags


# ---------------------------------------------------------------------------
# LE Audio annotator
# ---------------------------------------------------------------------------

class LEAudioAnnotator(RuleMatchAnnotator):
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

    # Valid ASE state machine transitions triggered by each opcode.
    # Maps opcode -> set of opcodes that may legally precede it.
    # Config Codec can appear from Idle (start) or after Release.
    _VALID_PREDECESSORS = {
        0x01: {None, 0x08},       # Idle -> Config Codec
        0x02: {0x01},             # Codec Configured -> Config QoS
        0x03: {0x02, 0x05},       # QoS Configured -> Enable (also after Disable)
        0x04: {0x03},             # Enabling -> Receiver Start Ready
        0x05: {0x03, 0x04, 0x07}, # Streaming/Enabling -> Disable
        0x06: {0x05},             # Disabling -> Receiver Stop Ready
        0x07: {0x03, 0x04},       # Streaming -> Update Metadata
        0x08: {0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x07},  # Release from most states
    }

    # ASE state values in state notification
    _ASE_STATES = {
        0x00: "Idle",
        0x01: "Codec Configured",
        0x02: "QoS Configured",
        0x03: "Enabling",
        0x04: "Streaming",
        0x05: "Disabling",
    }

    def __init__(self):
        super().__init__()
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
        self.ase_cp_handle = None   # confirmed ASE CP handle
        self._ase_state_handles = set()  # confirmed ASE state handles
        # Candidate ATT writes/notifications buffered before confirmation
        # Each entry: (pkt, handle, opcode, data_bytes)
        self._ase_candidates = []
        # Candidate notifications: (pkt, handle, data_bytes)
        self._notify_candidates = []
        self._ase_confirmed = False
        # Per-ASE stream tracking: ase_id -> {codec, config, state, direction}
        self._ase_streams = {}
        # Per-ASE peak state: highest state reached (by rank order)
        self._ase_peak_state = {}
        # Per-ASE first frame reference (Config Codec packet)
        self._ase_first_pkt = {}
        # First ISO data packet reference
        self._first_iso_pkt = None
        # PA Report deduplication: track last BASE body hash
        self._last_pa_base_hash = None
        self._pa_report_count = 0
        # BIG Info deduplication: track whether first BIG Info was seen
        self._saw_first_big_info = False
        # MGMT crash detection: last MGMT Close packet (awaiting Open)
        self._mgmt_close_pkt = None
        self._daemon_restarts = 0
        # ASE state rank for peak tracking: higher = more progressed
        self._ASE_STATE_RANK = {
            "Codec Configured": 1,
            "QoS Configured": 2,
            "Enabling": 3,
            "Streaming": 4,
            "Disabling": 3,  # same level as Enabling
        }

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
                else:
                    # Non-hex line ends the data block
                    in_data = False
        return handle, data_bytes

    def _buffer_att_write(self, pkt, body_text):
        """Buffer an ATT Write Command as an ASE CP candidate.

        Returns True if the packet was handled (either buffered and
        confirmed, or immediately tagged post-confirmation).
        """
        if "ATT: Write Command" not in body_text and \
                "ATT: Write Request" not in body_text:
            return False
        handle, data = self._extract_att_data(pkt.body)
        if not handle or not data:
            return False
        opcode = data[0]
        if opcode not in self._ASE_OPCODES:
            return False
        # Basic sanity: byte 1 = num_ase (1-4 typical)
        if len(data) >= 2 and not (1 <= data[1] <= 8):
            return False

        if self._ase_confirmed:
            # Already confirmed — tag immediately if same handle
            if handle == self.ase_cp_handle:
                self._tag_ase_write(pkt, handle, opcode, data)
                return True
            return False

        # Buffer and check for confirmation
        self._ase_candidates.append((pkt, handle, opcode, data))
        self._check_ase_confirmation()
        return self._ase_confirmed

    def _buffer_att_notification(self, pkt, body_text):
        """Buffer an ATT Handle Value Notification as ASE candidate.

        Returns True if the packet was handled.
        """
        if "ATT: Handle Value Notification" not in body_text:
            return False
        handle, data = self._extract_att_data(pkt.body)
        if not handle or not data:
            return False

        if self._ase_confirmed:
            # Already confirmed — tag immediately if on known handles
            # or any non-CP handle with valid ASE state data
            if handle == self.ase_cp_handle or \
                    handle in self._ase_state_handles:
                self._tag_ase_notification(pkt, handle, data)
                return True
            # Unknown handle — try to adopt if data looks like ASE state
            if self.ase_cp_handle and handle != self.ase_cp_handle \
                    and len(data) >= 2 and 1 <= data[0] <= 255 \
                    and data[1] in self._ASE_STATES:
                self._tag_ase_notification(pkt, handle, data)
                return True
            return False

        # Buffer for later
        self._notify_candidates.append((pkt, handle, data))
        return False  # not yet confirmed, let other checks try

    def _check_ase_confirmation(self):
        """Check if buffered candidates confirm ASE CP on a handle.

        Confirmation requires writes to the same handle with opcodes
        that follow valid ASE state machine transitions.  We need at
        least 2 writes with a valid predecessor relationship.
        """
        if self._ase_confirmed:
            return
        # Group candidates by handle
        by_handle = defaultdict(list)
        for _, handle, opcode, data in self._ase_candidates:
            by_handle[handle].append(opcode)

        for handle, opcodes in by_handle.items():
            if len(opcodes) < 2:
                continue
            # Check sequential validity: each opcode should be a valid
            # successor of the previous one
            valid_transitions = 0
            prev = None
            for op in opcodes:
                if prev is not None:
                    predecessors = self._VALID_PREDECESSORS.get(op, set())
                    if prev in predecessors:
                        valid_transitions += 1
                prev = op
            # Need at least 1 valid transition between consecutive
            # opcodes (not counting the initial Idle -> first opcode),
            # and the sequence must start with Config Codec (0x01).
            if valid_transitions >= 1 and opcodes[0] == 0x01:
                self.ase_cp_handle = handle
                self._ase_confirmed = True
                self._flush_ase_candidates()
                return

    def _flush_ase_candidates(self):
        """Tag all buffered candidates now that ASE CP is confirmed."""
        # Tag writes
        for pkt, handle, opcode, data in self._ase_candidates:
            if handle == self.ase_cp_handle:
                self._tag_ase_write(pkt, handle, opcode, data)

        # Tag notifications
        for pkt, handle, data in self._notify_candidates:
            self._tag_ase_notification(pkt, handle, data)

    # Sampling Frequency index values (BAP Assigned Numbers)
    _SAMPLING_FREQ = {
        0x01: "8kHz", 0x02: "11.025kHz", 0x03: "16kHz",
        0x04: "22.05kHz", 0x05: "24kHz", 0x06: "32kHz",
        0x07: "44.1kHz", 0x08: "48kHz", 0x09: "88.2kHz",
        0x0a: "96kHz", 0x0b: "176.4kHz", 0x0c: "192kHz",
        0x0d: "384kHz",
    }
    # Frame Duration index values
    _FRAME_DURATION = {0x00: "7.5ms", 0x01: "10ms"}

    @staticmethod
    def _parse_cc_ltv(data, cc_offset):
        """Parse Codec Configuration LTV bytes from Config Codec data.

        Args:
            data: Full ASE CP write data bytes.
            cc_offset: Byte offset where CC LTV structures begin.

        Returns:
            dict with decoded CC fields (sampling_freq, frame_duration,
            octets_per_frame, channel_alloc) or empty dict.
        """
        cc_len_idx = cc_offset - 1  # cc_length byte precedes CC data
        if len(data) <= cc_offset:
            return {}
        cc_len = data[cc_len_idx]
        cc = data[cc_offset:cc_offset + cc_len]
        result = {}
        i = 0
        while i < len(cc):
            if i + 1 >= len(cc):
                break
            length = cc[i]
            if length == 0 or i + length >= len(cc):
                break
            typ = cc[i + 1]
            val = cc[i + 2:i + 1 + length]
            if typ == 0x01 and len(val) >= 1:
                result["sampling_freq"] = val[0]
            elif typ == 0x02 and len(val) >= 1:
                result["frame_duration"] = val[0]
            elif typ == 0x03 and len(val) >= 4:
                result["channel_alloc"] = int.from_bytes(val[:4], "little")
            elif typ == 0x04 and len(val) >= 2:
                result["octets_per_frame"] = int.from_bytes(
                    val[:2], "little")
            elif typ == 0x05 and len(val) >= 1:
                result["blocks_per_sdu"] = val[0]
            i += 1 + length
        return result

    def _tag_ase_write(self, pkt, handle, opcode, data):
        """Tag an ASE CP write packet (post-confirmation)."""
        op_name = self._ASE_OPCODES.get(opcode, f"0x{opcode:02x}")
        num_ase = data[1] if len(data) >= 2 else "?"
        ase_id = data[2] if len(data) >= 3 else "?"
        details = f"ASE CP {op_name}, ASE ID={ase_id}"
        # Enrich with opcode-specific decoded info
        if opcode == 0x01 and len(data) >= 11:
            # Config Codec: decode target latency + codec + CC LTV
            target_latency = data[3]
            tl_names = {1: "Low Latency", 2: "Balanced",
                        3: "High Reliability"}
            tl_name = tl_names.get(target_latency,
                                    f"0x{target_latency:02x}")
            coding_format = data[5]
            codec_names = {0x06: "LC3", 0x03: "Transparent",
                           0xFF: "Vendor Specific"}
            codec_name = codec_names.get(coding_format,
                                          f"0x{coding_format:02x}")
            details += f", Codec={codec_name}, Latency={tl_name}"
            # Parse CC LTV bytes (start at data[11] after cc_length)
            cc = self._parse_cc_ltv(data, 11)
            cfg_parts = []
            if cc:
                cc_parts = []
                freq_idx = cc.get("sampling_freq")
                if freq_idx is not None:
                    cc_parts.append(
                        self._SAMPLING_FREQ.get(freq_idx,
                                                f"0x{freq_idx:02x}"))
                dur_idx = cc.get("frame_duration")
                if dur_idx is not None:
                    cc_parts.append(
                        self._FRAME_DURATION.get(dur_idx,
                                                  f"0x{dur_idx:02x}"))
                octets = cc.get("octets_per_frame")
                if octets is not None:
                    cc_parts.append(f"{octets}oct")
                if cc_parts:
                    details += f" ({', '.join(cc_parts)})"
                    cfg_parts = list(cc_parts)
            # Track per-ASE stream info
            if ase_id != "?":
                stream = self._ase_streams.setdefault(ase_id, {})
                stream["codec"] = codec_name
                if cfg_parts:
                    stream["config"] = ", ".join(cfg_parts)
                # Config Codec implies Codec Configured state
                stream.setdefault("state", "Codec Configured")
                if ase_id not in self._ase_peak_state:
                    self._ase_peak_state[ase_id] = "Codec Configured"
                # Record first Config Codec packet per ASE
                if ase_id not in self._ase_first_pkt:
                    self._ase_first_pkt[ase_id] = pkt
        elif opcode == 0x02 and len(data) >= 5:
            # Config QoS: decode CIG/CIS IDs
            cig_id = data[3]
            cis_id = data[4]
            details += f", CIG=0x{cig_id:02x}, CIS=0x{cis_id:02x}"
        # Receiver Start/Stop Ready implies the remote is a receiver,
        # so this ASE is a Source (we send audio to the remote).
        if opcode in (0x04, 0x06) and ase_id != "?":
            stream = self._ase_streams.setdefault(ase_id, {})
            stream["direction"] = "Source"
        self._tag(pkt, ["ASCS", "ASE_CP"], annotation=details)
        self.saw_ase_control = True

    def _tag_ase_state(self, pkt, data):
        """Tag and track an ASE state notification."""
        ase_id = data[0] if data else "?"
        state_val = data[1] if len(data) >= 2 else None
        state_name = self._ASE_STATES.get(
            state_val,
            f"0x{state_val:02x}" if state_val is not None else "?")
        self._tag(pkt, ["ASCS", "ASE_STATE"],
                  annotation=f"ASE ID={ase_id} state: {state_name}")
        if ase_id != "?":
            stream = self._ase_streams.setdefault(ase_id, {})
            stream["state"] = state_name
            new_rank = self._ASE_STATE_RANK.get(state_name, 0)
            old_peak = self._ase_peak_state.get(ase_id, "")
            old_rank = self._ASE_STATE_RANK.get(old_peak, 0)
            if new_rank > old_rank:
                self._ase_peak_state[ase_id] = state_name

    def _tag_ase_notification(self, pkt, handle, data):
        """Tag an ATT notification as ASE CP response or state change."""
        if handle == self.ase_cp_handle:
            # CP response: [opcode, num_ase, ase_id, response_code, reason]
            opcode = data[0]
            op_name = self._ASE_OPCODES.get(opcode, f"op 0x{opcode:02x}")
            ase_id = data[2] if len(data) >= 3 else "?"
            resp_code = data[3] if len(data) >= 4 else None
            resp_names = {0x00: "Success", 0x01: "Unsupported Opcode",
                          0x02: "Invalid Length", 0x03: "Invalid ASE ID",
                          0x04: "Invalid ASE State",
                          0x05: "Invalid ASE Direction",
                          0x06: "Unsupported Audio Capabilities",
                          0x07: "Unsupported Configuration",
                          0x08: "Rejected",
                          0x09: "Invalid Configuration"}
            if isinstance(resp_code, int):
                resp_name = resp_names.get(resp_code,
                                           f"0x{resp_code:02x}")
            else:
                resp_name = "?"
            self._tag(pkt, ["ASCS", "ASE_CP"],
                      annotation=f"ASE CP response: {op_name}, "
                      f"ASE ID={ase_id}, {resp_name}")
        elif handle in self._ase_state_handles:
            # Known ASE state handle — tag directly
            self._tag_ase_state(pkt, data)
        elif len(data) >= 2 and 1 <= data[0] <= 255 \
                and data[1] in self._ASE_STATES:
            # New handle with valid ASE state data — adopt it
            self._ase_state_handles.add(handle)
            self._tag_ase_state(pkt, data)


    def _run_hooks(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        # btmon nests LE sub-event names inside the body under
        # "LE Meta Event (0x3e)" headers, and HCI command names may
        # be truncated in the summary.  Search both locations.
        full = s + "\n" + body_text

        # --- MGMT daemon crash detection ---
        # "@ MGMT Close: bluetoothd" followed by "@ MGMT Open: bluetoothd"
        # indicates a daemon restart (crash or intentional restart).
        # Only track bluetoothd (not btmgmt, bluetoothctl, etc.).
        if pkt.direction == "@" and "MGMT" in s and "bluetoothd" in s:
            if "MGMT Close" in s:
                self._mgmt_close_pkt = pkt
            elif "MGMT Open" in s and self._mgmt_close_pkt is not None:
                self._daemon_restarts += 1
                self._tag(self._mgmt_close_pkt, "MGMT",
                          annotation="bluetoothd closed (daemon restart)")
                self._tag(pkt, "MGMT",
                          annotation="bluetoothd reopened (daemon restart)")
                self._mgmt_close_pkt = None
            return True

        # --- Broadcast receiver flow ---

        if "Periodic Advertising Sync Established" in full or \
                "Periodic Advertising Sync Transfer Received" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "PA",
                      annotation=f"PA sync established ({status})")
            if "Success" in body_text:
                self.saw_pa_sync = True

        elif "Periodic Advertising Create Sync" in full:
            self._tag(pkt, "PA",
                      annotation="Host requesting PA sync")

        elif "Periodic Advertising Sync Transfer Parameters" in full:
            self._tag(pkt, "PA",
                      annotation="PAST parameters configured")

        elif "Periodic Advertising Report" in full:
            if "Basic Audio Announcement" in body_text:
                # Hash only the BASE portion (from "Basic Audio
                # Announcement" onward) — header fields like RSSI
                # vary between reports and would defeat dedup.
                base_start = body_text.find("Basic Audio Announcement")
                base_data = body_text[base_start:]
                body_hash = hash(base_data)
                self._pa_report_count += 1
                if body_hash != self._last_pa_base_hash:
                    # New or changed BASE — always key
                    self._last_pa_base_hash = body_hash
                    self._tag(pkt, "PA",
                              annotation="PA Report with BASE data")
                else:
                    # Duplicate BASE — demote to context
                    self._tag(pkt, "PA", priority="context",
                              annotation="PA Report (repeat)")
            else:
                self._tag(pkt, "PA", priority="context",
                          annotation="PA Report")

        elif "BIG Info Advertising Report" in full \
                or "Isochronous Group Info Advertising Report" in full:
            self.saw_big_info = True
            if not self._saw_first_big_info:
                # First BIG Info — key frame
                self._saw_first_big_info = True
                self._tag(pkt, "BIG",
                          annotation="BIG Info received -- BIG exists "
                                     "on this PA train")
            else:
                # Subsequent BIG Info — periodic repeat, demote
                self._tag(pkt, "BIG", priority="context",
                          annotation="BIG Info (repeat)")

        elif "BIG Create Sync" in full \
                or "Isochronous Group Create Sync" in full:
            self._tag(pkt, "BIG",
                      annotation="Host requesting BIG sync")
            self.saw_big_create_sync = True

        elif "BIG Sync Established" in full \
                or "Isochronous Group Sync Established" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "BIG",
                      annotation=f"BIG sync result: {status}")
            self.saw_big_sync_established = True
            if "Success" not in body_text:
                self._tag(pkt, "ERROR",
                          annotation="BIG sync FAILED")

        elif "BIG Sync Lost" in full \
                or "Isochronous Group Sync Lost" in full:
            self._tag(pkt, "BIG",
                      annotation="BIG sync lost")

        elif "BIG Terminate" in full \
                or "Isochronous Group Terminate" in full:
            self._tag(pkt, "BIG",
                      annotation="BIG terminated")

        # --- Unicast CIS flow ---

        elif "ASE Control Point" in full:
            # Determine the ASE operation from body
            op = "write"
            codec_name = None
            for kw in ("Config Codec", "Config QoS", "Enable",
                       "Disable", "Release", "Receiver Start",
                       "Receiver Stop"):
                if kw in body_text:
                    op = kw
                    break
            # Extract ASE ID if present
            ase_m = re.search(r"ASE ID:\s*(\d+)", body_text)
            ase_id = int(ase_m.group(1)) if ase_m else None
            self._tag(pkt, ["ASCS", "ASE_CP"],
                      annotation=f"ASE Control Point: {op}")
            self.saw_ase_control = True
            # Receiver Start/Stop Ready implies the remote is a
            # receiver, so this ASE is a Source.
            if ase_id is not None and op in ("Receiver Start",
                                             "Receiver Stop"):
                stream = self._ase_streams.setdefault(ase_id, {})
                stream["direction"] = "Source"
            # Track per-ASE info from decoded btmon
            if ase_id is not None and op == "Config Codec":
                stream = self._ase_streams.setdefault(ase_id, {})
                codec_m = re.search(
                    r"Codec:\s*(.+?)(?:\s*\(|$)", body_text)
                if codec_m:
                    stream["codec"] = codec_m.group(1).strip()
                # Config Codec implies Codec Configured state
                stream.setdefault("state", "Codec Configured")
                if ase_id not in self._ase_peak_state:
                    self._ase_peak_state[ase_id] = "Codec Configured"
                # Record first Config Codec packet per ASE
                if ase_id not in self._ase_first_pkt:
                    self._ase_first_pkt[ase_id] = pkt

        elif re.search(r"ASE ID:", body_text):
            # ASE state notification
            state_m = re.search(r"State:\s*(.+)", body_text)
            state = state_m.group(1).strip() if state_m else "?"
            ase_m = re.search(r"ASE ID:\s*(\d+)", body_text)
            self._tag(pkt, ["ASCS", "ASE_STATE"],
                      annotation=f"ASE state: {state}")
            # Track per-ASE state from decoded btmon
            if ase_m:
                ase_id = int(ase_m.group(1))
                stream = self._ase_streams.setdefault(ase_id, {})
                stream["state"] = state
                new_rank = self._ASE_STATE_RANK.get(state, 0)
                old_peak = self._ase_peak_state.get(ase_id, "")
                old_rank = self._ASE_STATE_RANK.get(old_peak, 0)
                if new_rank > old_rank:
                    self._ase_peak_state[ase_id] = state

        # --- Raw ATT fallback for ASE operations ---
        # When GATT discovery is absent, btmon cannot decode LE Audio
        # GATT operations.  Buffer ATT Write Commands whose first data
        # byte matches an ASE CP opcode (0x01-0x08) and confirm only
        # when we see a state-machine-valid sequence on the same handle.
        # Once confirmed, retroactively tag buffered packets with
        # decoded info in the annotation string.
        elif self._buffer_att_write(pkt, body_text):
            pass  # tagged inside helper once confirmed

        elif self._buffer_att_notification(pkt, body_text):
            pass  # tagged inside helper once confirmed

        elif "Set CIG Parameters" in full:
            self._tag(pkt, ["CIG", "HCI"],
                      annotation="CIG parameters configured")
            self.saw_set_cig = True

        elif "Create CIS" in full and "Create CIS" not in body_text \
                or re.search(r"LE Create CIS\b", full):
            # Match the HCI command; avoid matching CIS Established body
            self._tag(pkt, ["CIS", "HCI"],
                      annotation="CIS creation requested")
            self.saw_create_cis = True

        elif "Connected Isochronous Stream Established" in full or \
                "CIS Established" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, ["CIS", "HCI"],
                      annotation=f"CIS established: {status}")
            self.saw_cis_established = True
            if "Success" not in body_text:
                self._tag(pkt, "ERROR",
                          annotation="CIS establishment FAILED")

        elif "Accept Connected Isochronous Stream" in full:
            self._tag(pkt, ["CIS", "HCI"],
                      annotation="CIS accept sent")

        elif "Connected Isochronous Stream Request" in full:
            self._tag(pkt, ["CIS", "HCI"],
                      annotation="CIS connection request from remote")
            self.saw_create_cis = True

        elif "Setup ISO" in full or "Setup Isochrono" in full:
            # Capture Data Path field (HCI, Codec, Vendor, etc.)
            dp_m = re.search(r"Data Path:\s*(.+?)(?:\s*$)",
                             body_text, re.MULTILINE)
            dp_note = ""
            if dp_m:
                dp_note = f" (Data Path: {dp_m.group(1).strip()})"
                self.saw_coding_format = True
            self._tag(pkt, ["CIS", "HCI"],
                      annotation=f"ISO data path configured{dp_note}")
            self.saw_setup_iso = True

        elif re.match(r'[<>]\s*LE-CIS:', pkt._raw_header) or \
                "ISO Data" in s:
            self.cis_data_count += 1
            self.saw_iso_data = True
            # Record first ISO data packet
            if self._first_iso_pkt is None:
                self._first_iso_pkt = pkt
            # Only tag first pair and sparse samples for timing reference
            if self.cis_data_count <= 2 or self.cis_data_count % 500 == 0:
                self._tag(pkt, ["CIS", "ISO_DATA"], priority="context",
                          annotation=f"ISO data #{self.cis_data_count}")
            # else: leave as skip (bulk data)

        # --- BASS ---

        elif "Add Source" in body_text:
            self._tag(pkt, "BASS",
                      annotation="BASS Add Source")

        elif "Modify Source" in body_text:
            self._tag(pkt, "BASS",
                      annotation="BASS Modify Source")

        elif "Remove Source" in body_text:
            self._tag(pkt, "BASS",
                      annotation="BASS Remove Source")

        # --- Codec info ---

        elif "LC3" in body_text and ("Codec:" in body_text or
                                      "Sampling Frequency" in body_text):
            self._tag(pkt, "PACS",
                      annotation="LC3 codec configuration")

        # --- Connection events relevant to LE Audio ---

        elif "LE Enhanced Connection Complete" in full or \
                "LE Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, ["HCI", "LE"],
                      annotation=f"LE connection: {status}")

        elif "Disconnect" in s and pkt.direction in ("<", ">") \
                and not pkt.tags:
            self._tag_disconnect(pkt)

        return False

    def finalize(self, packets):
        # Declarative absence checks and notes from JSON
        diags = super().finalize(packets)

        # Broadcast/unicast subcategory: when the trace is broadcast-
        # dominant (PA/BIG/BASS activity present, ASEs never progressed
        # past Idle), demote unicast-only key frames to context so they
        # don't waste output budget.
        _UNICAST_ONLY_TAGS = {"PACS", "ASCS", "ASE_CP", "ASE_STATE"}
        broadcast_active = (self.saw_pa_sync or self.saw_big_info
                            or self.saw_big_create_sync
                            or any("BASS" in t for pkt in packets
                                   for t in pkt.tags))
        unicast_progressed = any(
            self._ASE_STATE_RANK.get(st, 0) > 0
            for st in self._ase_peak_state.values()
        )
        if broadcast_active and not unicast_progressed:
            for pkt in packets:
                if pkt.priority == "key" and pkt.tags:
                    if set(pkt.tags).issubset(_UNICAST_ONLY_TAGS):
                        pkt.priority = "context"

        # Audio Streams table: STREAM lines for common template
        for ase_id, info in sorted(self._ase_streams.items()):
            codec = info.get("codec", "?")
            # Use peak state (last non-terminal) for STREAM lines
            state = self._ase_peak_state.get(ase_id,
                                             info.get("state", "?"))
            config = info.get("config", "N/A")
            # Direction not available from raw ATT decoding; mark as
            # unknown so the LLM can infer from context if possible.
            direction = info.get("direction", "?")
            ref_pkt = self._ase_first_pkt.get(ase_id)
            diags.append(Diagnostic(
                f"STREAM: id={ase_id} dir={direction} codec={codec} "
                f"state={state} config={config}",
                frame=ref_pkt.frame if ref_pkt else None,
                timestamp=ref_pkt.timestamp if ref_pkt else None,
                tags=["ASCS"]))

        # Summary annotation for ISO data (explicitly normal -- prevents
        # the LLM from flagging normal streaming volume as a problem).
        if self.cis_data_count > 0:
            ref_pkt = self._first_iso_pkt
            diags.append(Diagnostic(
                f"NOTE: {self.cis_data_count} ISO/CIS data packets "
                f"were streamed (normal LE Audio traffic, bulk data "
                f"omitted from prefiltered log).",
                frame=ref_pkt.frame if ref_pkt else None,
                timestamp=ref_pkt.timestamp if ref_pkt else None,
                tags=["ISO_DATA"]))

        return diags


# ---------------------------------------------------------------------------
# A2DP annotator
# ---------------------------------------------------------------------------

class A2DPAnnotator(RuleMatchAnnotator):
    """Annotator for A2DP / AVDTP traces.

    Tracks the AVDTP state machine per SEID, extracts codec
    configuration from Set Configuration, and records state
    transitions for diagnostics.

    AVDTP states:
        Idle → Configured → Open → Streaming
        Streaming → Open (via Suspend)
        Any → Idle (via Close or Abort)
    """

    name = "a2dp"

    # AVDTP state machine
    _AVDTP_STATES = {
        "idle":       "Idle",
        "configured": "Configured",
        "open":       "Open",
        "streaming":  "Streaming",
        "closing":    "Closing",
        "aborting":   "Aborting",
    }

    # Regex to extract AVDTP label from body lines
    _LABEL_RE = re.compile(r"label\s+(\d+)")

    def __init__(self):
        super().__init__()
        self.saw_discover = False
        self.saw_set_config = False
        self.saw_open = False
        self.saw_start = False
        self.saw_media_data = False
        self.media_data_count = 0
        # Per-SEID state tracking: seid -> current state string
        self._seid_state = {}
        # Per-SEID state transition log: seid -> [(timestamp, old, new, trigger)]
        self._seid_transitions = defaultdict(list)
        # Discovered SEPs: seid -> {type, media_type, in_use}
        self._discovered_seps = {}
        # Per-SEID capabilities: seid -> [codec_description, ...]
        self._seid_capabilities = defaultdict(list)
        # Selected stream config: seid -> {codec, frequency, channel_mode,
        #                                  bitpool_min, bitpool_max, ...}
        self._stream_config = {}
        # Number of streaming sessions (Start Accept count)
        self._stream_sessions = 0
        # Per-SEID peak state: highest state reached (by rank order)
        self._seid_peak_state = {}
        # AVDTP state rank for peak tracking: higher = more progressed
        self._STATE_RANK = {
            "configured": 1,
            "open": 2,
            "streaming": 3,
        }
        # AVDTP label -> SEID mapping for correlating commands to responses
        self._label_seid = {}
        # AVDTP label -> config mapping for Set Configuration commands
        self._label_config = {}
        # Per-SEID first Set Configuration packet reference
        self._seid_first_pkt = {}
        # First Start Accept packet reference
        self._first_start_pkt = None
        # First media data packet reference
        self._first_media_pkt = None
        # L2CAP channel tracker for AVDTP transport (PSM 25)
        self._l2cap_tracker = L2CAPChannelTracker(psm_filter={25})

    def _transition(self, seid, new_state, trigger, timestamp):
        """Record an AVDTP state transition for a SEID."""
        old = self._seid_state.get(seid, "idle")
        self._seid_state[seid] = new_state
        # Track the highest state reached (by rank) for STREAM lines
        new_rank = self._STATE_RANK.get(new_state, 0)
        old_peak = self._seid_peak_state.get(seid, "")
        old_rank = self._STATE_RANK.get(old_peak, 0)
        if new_rank > old_rank:
            self._seid_peak_state[seid] = new_state
        self._seid_transitions[seid].append(
            (timestamp, old, new_state, trigger))

    def _extract_label(self, body_lines):
        """Extract AVDTP transaction label from packet lines."""
        for line in body_lines:
            m = self._LABEL_RE.search(line)
            if m:
                return int(m.group(1))
        return None

    def _resolve_seid(self, pkt):
        """Get SEID from body or from label correlation."""
        seid = self._parse_seid(pkt.body)
        if seid is not None:
            return seid
        # Fall back to label correlation
        label = self._extract_label([pkt.summary] + pkt.body)
        if label is not None:
            return self._label_seid.get(label)
        return None

    @staticmethod
    def _parse_seid(body_lines):
        """Extract ACP SEID from AVDTP body lines."""
        for line in body_lines:
            m = re.search(r"ACP SEID:\s*(\d+)", line)
            if m:
                return int(m.group(1))
        return None

    @staticmethod
    def _parse_codec_config(body_lines):
        """Extract codec configuration from Set Configuration body.

        Returns dict with codec details or empty dict.
        """
        config = {}
        codec_name = None
        for line in body_lines:
            stripped = line.strip()
            # Codec name
            m = re.match(r"Media Codec:\s*(.+)", stripped)
            if m:
                codec_name = m.group(1).strip()
                config["codec"] = codec_name
                continue
            # SBC / AAC / vendor parameters
            m = re.match(r"Frequency:\s*(.+)", stripped)
            if m:
                config["frequency"] = m.group(1).strip()
                continue
            m = re.match(r"Channel Mode:\s*(.+)", stripped)
            if m:
                config["channel_mode"] = m.group(1).strip()
                continue
            m = re.match(r"Minimum Bitpool:\s*(\d+)", stripped)
            if m:
                config["bitpool_min"] = int(m.group(1))
                continue
            m = re.match(r"Maximum Bitpool:\s*(\d+)", stripped)
            if m:
                config["bitpool_max"] = int(m.group(1))
                continue
            m = re.match(r"Block Length:\s*(.+)", stripped)
            if m:
                config["block_length"] = m.group(1).strip()
                continue
            m = re.match(r"Subbands:\s*(.+)", stripped)
            if m:
                config["subbands"] = m.group(1).strip()
                continue
            m = re.match(r"Allocation Method:\s*(.+)", stripped)
            if m:
                config["allocation"] = m.group(1).strip()
                continue
            m = re.match(r"Object Type:\s*(.+)", stripped)
            if m:
                config["object_type"] = m.group(1).strip()
                continue
            m = re.match(r"Bitrate:\s*(.+)", stripped)
            if m:
                config["bitrate"] = m.group(1).strip()
                continue
            m = re.match(r"VBR:\s*(.+)", stripped)
            if m:
                config["vbr"] = m.group(1).strip()
                continue
            m = re.match(r"Channels:\s*(.+)", stripped)
            if m:
                config["channels"] = m.group(1).strip()
                continue
            # Vendor codec info
            m = re.match(r"Vendor ID:\s*(.+)", stripped)
            if m:
                config["vendor_id"] = m.group(1).strip()
                continue
            m = re.match(r"Vendor Specific Codec ID:\s*(.+)", stripped)
            if m:
                config["vendor_codec"] = m.group(1).strip()
                # Use vendor codec name as codec if Non-A2DP
                if codec_name and "Non-A2DP" in codec_name:
                    # e.g. "aptX (0x0001)" -> "aptX"
                    short = m.group(1).strip().split("(")[0].strip()
                    config["codec"] = short
                continue
        return config

    @staticmethod
    def _format_config_summary(config):
        """Build a short human-readable codec config string."""
        parts = []
        codec = config.get("codec", "?")
        parts.append(A2DPAnnotator._clean_codec_name(codec))
        freq = config.get("frequency")
        if freq:
            cleaned_freq = A2DPAnnotator._clean_frequency(freq)
            if cleaned_freq:
                parts.append(cleaned_freq)
        ch = config.get("channel_mode")
        if ch:
            ch_short = ch.split("(")[0].strip()
            parts.append(ch_short)
        bp_min = config.get("bitpool_min")
        bp_max = config.get("bitpool_max")
        if bp_min is not None and bp_max is not None:
            parts.append(f"Bitpool {bp_min}-{bp_max}")
        bitrate = config.get("bitrate")
        if bitrate:
            parts.append(bitrate)
        return ", ".join(parts)

    @staticmethod
    def _clean_codec_name(name):
        """Strip hex code suffix from codec name.

        'SBC (0x00)' -> 'SBC', 'MPEG-2,4 AAC (0x02)' -> 'AAC'
        """
        if not name:
            return "?"
        # Remove trailing (0xNN)
        cleaned = re.sub(r"\s*\(0x[0-9a-fA-F]+\)\s*$", "", name)
        # Simplify MPEG-2,4 AAC -> AAC
        if "AAC" in cleaned:
            return "AAC"
        return cleaned

    @staticmethod
    def _clean_frequency(freq_str):
        """Clean frequency string for display.

        '44100 (0x20)' -> '44100Hz'
        '0x30' -> '' (bitmask in capabilities, skip)
        """
        if not freq_str:
            return ""
        # Skip pure hex bitmasks from capabilities (e.g. '0x30', '0x180')
        stripped = freq_str.strip()
        if re.match(r"^0x[0-9a-fA-F]+$", stripped):
            return ""
        # Extract decoded frequency (e.g. '44100' from '44100 (0x20)')
        m = re.match(r"(\d+)", stripped)
        if m and int(m.group(1)) > 0:
            return f"{m.group(1)}Hz"
        return ""

    @staticmethod
    def _parse_discover_response(body_lines):
        """Extract SEP info from Discover Response body.

        Returns list of dicts: [{seid, media_type, sep_type, in_use}]
        """
        seps = []
        current = {}
        for line in body_lines:
            stripped = line.strip()
            m = re.match(r"ACP SEID:\s*(\d+)", stripped)
            if m:
                if current:
                    seps.append(current)
                current = {"seid": int(m.group(1))}
                continue
            m = re.match(r"Media Type:\s*(.+)", stripped)
            if m and current:
                raw = m.group(1).strip()
                current["media_type"] = re.sub(
                    r"\s*\(0x[0-9a-fA-F]+\)\s*$", "", raw)
                continue
            m = re.match(r"SEP Type:\s*(.+)", stripped)
            if m and current:
                raw = m.group(1).strip()
                # Strip hex suffix: 'SNK (0x01)' -> 'SNK'
                current["sep_type"] = re.sub(
                    r"\s*\(0x[0-9a-fA-F]+\)\s*$", "", raw)
                continue
            m = re.match(r"In use:\s*(.+)", stripped)
            if m and current:
                current["in_use"] = m.group(1).strip()
                continue
        if current:
            seps.append(current)
        return seps

    def _run_hooks(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        # Feed every packet to L2CAP tracker (it ignores non-L2CAP)
        l2cap_info = self._l2cap_tracker.process(pkt)

        if "AVDTP:" in full:
            self._annotate_avdtp(pkt, body_text, full)
            return True

        # L2CAP signaling for PSM 25 (AVDTP transport channel)
        if l2cap_info is not None and not pkt.tags:
            ann = (f"L2CAP {l2cap_info['signal']} for AVDTP: "
                   f"{l2cap_info['detail']}")
            self._tag(pkt, ["L2CAP", "AVDTP"], annotation=ann)

        elif "PSM: 25" in body_text and not pkt.tags:
            self._tag(pkt, ["L2CAP", "AVDTP"],
                      annotation="L2CAP for AVDTP (PSM 25)")

        # ACL media transport data -- high volume, summarize
        elif pkt.direction in ("<", ">") and \
                "ACL:" in pkt._raw_header and \
                not pkt.tags:
            dlen_m = re.search(r'dlen\s+(\d+)', pkt._raw_header)
            if dlen_m and int(dlen_m.group(1)) > 200:
                self.media_data_count += 1
                self.saw_media_data = True
                # Record first media data packet
                if self._first_media_pkt is None:
                    self._first_media_pkt = pkt
                if self.media_data_count <= 2 or \
                        self.media_data_count % 500 == 0:
                    self._tag(pkt, "A2DP", priority="context",
                              annotation=f"A2DP media data "
                              f"#{self.media_data_count}")

        # Connection events
        if "Connection Complete" in full and not pkt.tags:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, "HCI",
                      annotation=f"Connection: {status}")

        elif "Disconnect" in s and pkt.direction in ("<", ">") \
                and not pkt.tags:
            self._tag_disconnect(pkt)

        # Number of Completed Packets -- only flag anomalous latency
        elif "Number of Completed Packets" in full and not pkt.tags:
            if "Latency:" in body_text:
                lat_m = re.search(r"Latency:\s*(\d+)\s*msec", body_text)
                if lat_m:
                    max_lat = int(lat_m.group(1))
                    if max_lat >= 20:
                        lat_full = re.search(
                            r"Latency:\s*(.+)", body_text)
                        lat_str = lat_full.group(1).strip() \
                            if lat_full else f"{max_lat} msec"
                        self._tag(pkt, ["A2DP", "HCI"],
                                  annotation=f"High latency: {lat_str}")

        return False

    def _annotate_avdtp(self, pkt, body_text, full):
        """Annotate AVDTP signaling with state machine tracking."""
        seid = self._parse_seid(pkt.body)
        label = self._extract_label([pkt.summary] + pkt.body)
        ts = pkt.timestamp

        # On Commands, store label→SEID mapping
        is_command = "Command" in full and "Response" not in full
        is_response = "Response Accept" in full
        is_reject = "Response Reject" in full

        if is_command and label is not None and seid is not None:
            self._label_seid[label] = seid

        # Resolve SEID for responses via label correlation
        if (is_response or is_reject) and seid is None and \
                label is not None:
            seid = self._label_seid.get(label)

        # Determine the AVDTP signal type from body lines
        for line in [pkt.summary] + pkt.body:
            # --- Discover ---
            if "Discover" in line and "AVDTP" in line:
                if is_response:
                    seps = self._parse_discover_response(pkt.body)
                    for sep in seps:
                        sid = sep.get("seid")
                        if sid is not None:
                            self._discovered_seps[sid] = sep
                            if sid not in self._seid_state:
                                self._seid_state[sid] = "idle"
                    sep_descs = []
                    for sep in seps:
                        sid = sep.get("seid", "?")
                        stype = sep.get("sep_type", "?")
                        in_use = sep.get("in_use", "?")
                        sep_descs.append(
                            f"SEID {sid} ({stype}"
                            + (", In use" if in_use == "Yes" else "")
                            + ")")
                    ann = "AVDTP Discover Response: " + ", ".join(
                        sep_descs) if sep_descs else \
                        "AVDTP Discover Response"
                    self._tag(pkt, "AVDTP", annotation=ann)
                    return
                elif is_reject:
                    self._tag(pkt, "AVDTP",
                              annotation="AVDTP Discover REJECTED")
                    return
                elif is_command:
                    self._tag(pkt, "AVDTP",
                              annotation="AVDTP Discover")
                    self.saw_discover = True
                    return

            # --- Get Capabilities ---
            if ("Get All Capabilities" in line or
                    "Get Capabilities" in line) and "AVDTP" in line:
                if is_response:
                    config = self._parse_codec_config(pkt.body)
                    codec = self._clean_codec_name(
                        config.get("codec", "?"))
                    if seid is not None:
                        self._seid_capabilities[seid].append(config)
                    ann = (f"AVDTP Get Capabilities Response "
                           f"SEID {seid}: {codec}")
                    # Add key params for richer annotation
                    caps_parts = []
                    freq = config.get("frequency")
                    if freq:
                        cleaned_freq = self._clean_frequency(freq)
                        if cleaned_freq:
                            caps_parts.append(cleaned_freq)
                    bp_max = config.get("bitpool_max")
                    if bp_max:
                        caps_parts.append(f"MaxBitpool={bp_max}")
                    bitrate = config.get("bitrate")
                    if bitrate:
                        caps_parts.append(bitrate)
                    if caps_parts:
                        ann += f" ({', '.join(caps_parts)})"
                    self._tag(pkt, "AVDTP", annotation=ann)
                    return
                elif is_command:
                    ann = f"AVDTP Get Capabilities SEID {seid}" \
                        if seid else "AVDTP Get Capabilities"
                    self._tag(pkt, "AVDTP", annotation=ann)
                    return

            # --- Set Configuration ---
            if "Set Configuration" in line and "AVDTP" in line:
                if is_response:
                    if seid is not None:
                        self._transition(seid, "configured",
                                         "Set Configuration Accept", ts)
                    # Retrieve config from command
                    config = (self._label_config.get(label)
                              if label is not None else None)
                    if seid is not None and config:
                        self._stream_config[seid] = config
                    summary = self._format_config_summary(config) \
                        if config else ""
                    ann = f"AVDTP Set Configuration Accept SEID {seid}"
                    if summary:
                        ann += f": {summary}"
                    self._tag(pkt, "AVDTP", annotation=ann)
                    self.saw_set_config = True
                    # Record first Set Configuration packet per SEID
                    if seid is not None and seid not in self._seid_first_pkt:
                        self._seid_first_pkt[seid] = pkt
                    return
                elif is_reject:
                    err_m = re.search(r"Error code:\s*(.+)", body_text)
                    err = err_m.group(1).strip() if err_m else "?"
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Set Configuration "
                              f"REJECTED: {err}")
                    return
                elif is_command:
                    config = self._parse_codec_config(pkt.body)
                    if label is not None and config:
                        self._label_config[label] = config
                    summary = self._format_config_summary(config) \
                        if config else ""
                    int_seid_m = re.search(r"INT SEID:\s*(\d+)",
                                           body_text)
                    int_seid = int_seid_m.group(1) if int_seid_m \
                        else "?"
                    ann = (f"AVDTP Set Configuration "
                           f"ACP SEID {seid}, INT SEID {int_seid}")
                    if summary:
                        ann += f": {summary}"
                    self._tag(pkt, ["AVDTP", "A2DP"], annotation=ann)
                    self.saw_set_config = True
                    return

            # --- Reconfigure ---
            if "Reconfigure" in line and "AVDTP" in line:
                if is_response:
                    config = self._parse_codec_config(pkt.body)
                    if seid is not None and config:
                        self._stream_config[seid] = config
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Reconfigure Accept "
                              f"SEID {seid}")
                    return
                elif is_command:
                    config = self._parse_codec_config(pkt.body)
                    if seid is not None and config:
                        self._stream_config[seid] = config
                    summary = self._format_config_summary(config) \
                        if config else ""
                    ann = f"AVDTP Reconfigure SEID {seid}"
                    if summary:
                        ann += f": {summary}"
                    self._tag(pkt, ["AVDTP", "A2DP"], annotation=ann)
                    return

            # --- Open ---
            if "Open" in line and "AVDTP" in line:
                if is_response:
                    if seid is not None:
                        self._transition(seid, "open",
                                         "Open Accept", ts)
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Open Accept "
                              f"SEID {seid}")
                    self.saw_open = True
                    return
                elif is_reject:
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Open REJECTED "
                              f"SEID {seid}")
                    return
                elif is_command:
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Open SEID {seid}")
                    self.saw_open = True
                    return

            # --- Start ---
            if "Start" in line and "AVDTP" in line:
                if is_response:
                    if seid is not None:
                        self._transition(seid, "streaming",
                                         "Start Accept", ts)
                    self._stream_sessions += 1
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Start Accept "
                              f"SEID {seid}")
                    self.saw_start = True
                    # Record first Start Accept packet
                    if self._first_start_pkt is None:
                        self._first_start_pkt = pkt
                    return
                elif is_reject:
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Start REJECTED "
                              f"SEID {seid}")
                    return
                elif is_command:
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Start SEID {seid}")
                    self.saw_start = True
                    return

            # --- Suspend ---
            if "Suspend" in line and "AVDTP" in line:
                if is_response:
                    if seid is not None:
                        self._transition(seid, "open",
                                         "Suspend Accept", ts)
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Suspend Accept "
                              f"SEID {seid}")
                    return
                elif is_command:
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Suspend SEID {seid}")
                    return

            # --- Close ---
            if "Close" in line and "AVDTP" in line:
                if "Response Accept" in line:
                    if seid is not None:
                        self._transition(seid, "idle",
                                         "Close Accept", ts)
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Close Accept "
                              f"SEID {seid}")
                    return
                elif "Command" in line:
                    if seid is not None:
                        self._transition(seid, "closing",
                                         "Close Command", ts)
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Close SEID {seid}")
                    return

            # --- Abort ---
            if "Abort" in line and "AVDTP" in line:
                if "Response Accept" in line:
                    if seid is not None:
                        self._transition(seid, "idle",
                                         "Abort Accept", ts)
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Abort Accept "
                              f"SEID {seid}")
                    return
                elif "Command" in line:
                    if seid is not None:
                        self._transition(seid, "aborting",
                                         "Abort Command", ts)
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Abort SEID {seid}"
                              f" -- ERROR")
                    return

            # --- Delay Report ---
            if "Delay Report" in line and "AVDTP" in line:
                delay_m = re.search(r"Delay:\s*(.+)", body_text)
                delay_str = delay_m.group(1).strip() \
                    if delay_m else "?"
                if "Response" in line:
                    self._tag(pkt, "AVDTP",
                              annotation="AVDTP Delay Report Accept")
                    return
                else:
                    self._tag(pkt, "AVDTP",
                              annotation=f"AVDTP Delay Report: "
                              f"{delay_str}")
                    return

            # --- Generic reject ---
            if "Response Reject" in line:
                err_m = re.search(r"Error code:\s*(.+)", body_text)
                err = err_m.group(1).strip() if err_m else "?"
                self._tag(pkt, "AVDTP",
                          annotation=f"AVDTP REJECTED: {err}")
                return

    def finalize(self, packets):
        # Declarative absence checks from JSON
        diags = super().finalize(packets)

        # Stream configuration summary
        for seid, config in self._stream_config.items():
            summary = self._format_config_summary(config)
            ref_pkt = self._seid_first_pkt.get(seid)
            diags.append(Diagnostic(
                f"CONFIG: SEID {seid} stream configured: {summary}",
                frame=ref_pkt.frame if ref_pkt else None,
                timestamp=ref_pkt.timestamp if ref_pkt else None,
                tags=["AVDTP"]))

        # Audio Streams table: STREAM lines for common template
        for seid, config in self._stream_config.items():
            sep = self._discovered_seps.get(seid, {})
            direction = sep.get("sep_type", "?")
            codec = self._clean_codec_name(config.get("codec", "?"))
            state = self._seid_peak_state.get(seid, "configured")
            cfg_parts = []
            freq = config.get("frequency")
            if freq:
                cleaned = self._clean_frequency(freq)
                if cleaned:
                    cfg_parts.append(cleaned)
            ch = config.get("channel_mode")
            if ch:
                cfg_parts.append(ch.split("(")[0].strip())
            bp_min = config.get("bitpool_min")
            bp_max = config.get("bitpool_max")
            if bp_min is not None and bp_max is not None:
                cfg_parts.append(f"Bitpool {bp_min}-{bp_max}")
            bitrate = config.get("bitrate")
            if bitrate:
                cfg_parts.append(bitrate)
            cfg_str = ", ".join(cfg_parts) if cfg_parts else "N/A"
            ref_pkt = self._seid_first_pkt.get(seid)
            diags.append(Diagnostic(
                f"STREAM: id={seid} dir={direction} codec={codec} "
                f"state={state} config={cfg_str}",
                frame=ref_pkt.frame if ref_pkt else None,
                timestamp=ref_pkt.timestamp if ref_pkt else None,
                tags=["AVDTP"]))

        # AVDTP state transition table per SEID
        for seid, transitions in self._seid_transitions.items():
            if not transitions:
                continue
            table_lines = [
                f"STATE: SEID {seid} AVDTP state transitions:"]
            for ts, old, new, trigger in transitions:
                table_lines.append(
                    f"  {ts:>12.3f}s  {old:>12s} -> {new:<12s}  "
                    f"({trigger})")
            # Use first transition's timestamp as reference
            first_ts, _, _, _ = transitions[0]
            ref_pkt = self._seid_first_pkt.get(seid)
            diags.append(Diagnostic(
                "\n".join(table_lines),
                frame=ref_pkt.frame if ref_pkt else None,
                timestamp=ref_pkt.timestamp if ref_pkt else None,
                tags=["AVDTP"]))

        # Streaming session count
        if self._stream_sessions > 0:
            ref_pkt = self._first_start_pkt
            diags.append(Diagnostic(
                f"INFO: {self._stream_sessions} streaming session(s) "
                f"started (Start Accept events).",
                frame=ref_pkt.frame if ref_pkt else None,
                timestamp=ref_pkt.timestamp if ref_pkt else None,
                tags=["AVDTP"]))

        if self.media_data_count > 0:
            ref_pkt = self._first_media_pkt
            diags.append(Diagnostic(
                f"INFO: {self.media_data_count} A2DP media data "
                f"packets observed (bulk data omitted from "
                f"prefiltered log).",
                frame=ref_pkt.frame if ref_pkt else None,
                timestamp=ref_pkt.timestamp if ref_pkt else None,
                tags=["A2DP"]))

        # L2CAP channel lifecycle diagnostics for PSM 25
        diags.extend(self._l2cap_tracker.diagnostics())

        return diags


# ---------------------------------------------------------------------------
# HFP annotator
# ---------------------------------------------------------------------------

class HFPAnnotator(RuleMatchAnnotator):
    """Annotator for HFP traces (RFCOMM + SCO)."""

    name = "hfp"

    def __init__(self):
        super().__init__()
        self.saw_rfcomm = False
        self.saw_sco_setup = False
        self.saw_sco_complete = False

    def _run_hooks(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "RFCOMM:" in full:
            self.saw_rfcomm = True
            if "SABM" in body_text or "UA" in body_text:
                self._tag(pkt, "RFCOMM",
                          annotation="RFCOMM channel setup")
            elif "UIH" in body_text:
                self._tag(pkt, ["RFCOMM", "HFP"],
                          annotation="RFCOMM data (AT commands)")
            elif "DISC" in body_text:
                self._tag(pkt, "RFCOMM",
                          annotation="RFCOMM disconnect")
            else:
                self._tag(pkt, "RFCOMM",
                          annotation="RFCOMM")
            return True

        elif "Synchronous Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, ["SCO", "HCI"],
                      annotation=f"SCO connection: {status}")
            self.saw_sco_complete = True
            if "Success" not in body_text:
                self._tag(pkt, "ERROR",
                          annotation="SCO setup FAILED")
            return True

        elif "Disconnect" in s and pkt.direction in ("<", ">") \
                and not pkt.tags:
            self._tag_disconnect(pkt)
            return True

        return False


# ---------------------------------------------------------------------------
# SMP annotator
# ---------------------------------------------------------------------------

class SMPAnnotator(RuleMatchAnnotator):
    """Annotator for SMP pairing traces."""

    name = "smp"

    def __init__(self):
        super().__init__()
        self.saw_pairing_req = False
        self.saw_pairing_rsp = False
        self.saw_confirm = False
        self.saw_pubkey = False
        self.saw_dhkey = False
        self.saw_encrypt = False

    def _run_hooks(self, pkt):
        full = pkt.summary + "\n" + "\n".join(pkt.body)
        if "Encryption Change" in full:
            body_text = "\n".join(pkt.body)
            status = "Success" if "Success" in body_text else "FAIL"
            self._tag(pkt, ["SMP", "HCI"],
                      annotation=f"Encryption change: {status}")
            self.saw_encrypt = True
            if "Success" not in body_text:
                self._tag(pkt, "ERROR",
                          annotation="Encryption change FAILED")
            return True
        return False


# ---------------------------------------------------------------------------
# Connections annotator
# ---------------------------------------------------------------------------

class ConnectionsAnnotator(RuleMatchAnnotator):
    """Annotator for connection lifecycle traces."""

    name = "connections"

    def _run_hooks(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)
        full = s + "\n" + body_text

        if "Connection Complete" in full:
            status = "Success" if "Success" in body_text else "FAIL"
            handle_m = re.search(r"Handle:\s*(\d+)", body_text)
            handle = handle_m.group(1) if handle_m else "?"
            role_m = re.search(r"Role:\s*(.+)", body_text)
            role = role_m.group(1).strip() if role_m else ""
            self._tag(pkt, "HCI",
                      annotation=f"Connection handle={handle} "
                      f"{role} {status}")
            if "Success" not in body_text:
                self._tag(pkt, "ERROR")
            return True

        elif "Disconnect" in s and pkt.direction in ("<", ">"):
            handle_m = re.search(r"Handle:\s*(\d+)", body_text)
            handle = handle_m.group(1) if handle_m else "?"
            self._tag_disconnect(pkt, handle=handle)
            return True

        return False


# ---------------------------------------------------------------------------
# L2CAP channel lifecycle tracker (composable helper)
# ---------------------------------------------------------------------------

class L2CAPChannelTracker:
    """Track L2CAP channel lifecycle: Connection, Configuration, Disconnect.

    This is a composable helper class (not an Annotator) that can be used
    by any annotator that needs L2CAP channel state awareness.

    Tracks:
    - Connection Request/Response pairs to learn CID <-> PSM mappings
    - Configure Request/Response pairs by ident to detect missing responses
    - Channel state: connecting -> connected -> configuring -> open -> disconnected
    - Half-configured channels (Configure Request sent, no Response received)

    Usage:
        tracker = L2CAPChannelTracker(psm_filter={25})  # or None for all
        for pkt in packets:
            info = tracker.process(pkt)  # returns annotation info or None
        diags = tracker.diagnostics()  # call after all packets processed

    The ``psm_filter`` parameter limits tracking to channels matching the
    given PSM values.  Pass ``None`` to track all channels.
    """

    # Regex patterns for L2CAP signaling body fields
    _PSM_RE = re.compile(r"PSM:\s*(\d+)")
    _SRC_CID_RE = re.compile(r"Source CID:\s*(\d+)")
    _DST_CID_RE = re.compile(r"Destination CID:\s*(\d+)")
    _IDENT_RE = re.compile(r"ident\s+(\d+)")
    _RESULT_RE = re.compile(r"Result:\s*(.+)")
    _MTU_RE = re.compile(r"MTU:\s*(\d+)")

    def __init__(self, psm_filter=None):
        """Initialize tracker.

        Args:
            psm_filter: Set of PSM values to track, or None for all.
        """
        self.psm_filter = psm_filter

        # Active channels: (local_cid, remote_cid) -> {
        #   psm, state, our_config_done, their_config_done,
        #   connect_pkt, config_req_pkt, mtu_local, mtu_remote }
        self._channels = {}

        # CID -> channel key for fast lookup
        self._cid_to_key = {}

        # Pending Connection Requests: (direction, ident) -> {
        #   psm, src_cid, pkt }
        # direction is the direction of the Request
        self._pending_conn = {}

        # Pending Configure Requests: (direction, ident) -> {
        #   dest_cid, mtu, pkt, channel_key }
        self._pending_config = {}

        # Completed channels (disconnected): list of channel info dicts
        self._completed = []

        # Diagnostics accumulated during processing
        self._issues = []

    def _body_text(self, pkt):
        return "\n".join(pkt.body)

    def _is_l2cap_signaling(self, pkt):
        """Check if this packet contains L2CAP signaling."""
        if pkt.direction not in ("<", ">"):
            return False
        s = pkt.summary
        body = self._body_text(pkt)
        return "L2CAP:" in s or "L2CAP:" in body

    def _extract_field(self, regex, body_text):
        """Extract first match of regex from body text."""
        m = regex.search(body_text)
        return m.group(1).strip() if m else None

    def _channel_key_for_cid(self, cid):
        """Look up channel key by any known CID."""
        return self._cid_to_key.get(cid)

    def _register_channel(self, local_cid, remote_cid, psm, pkt):
        """Register a new channel after successful connection."""
        key = (local_cid, remote_cid)
        self._channels[key] = {
            "psm": psm,
            "state": "connected",
            "our_config_done": False,
            "their_config_done": False,
            "connect_pkt": pkt,
            "config_req_pkt": None,
            "mtu_local": None,
            "mtu_remote": None,
        }
        self._cid_to_key[local_cid] = key
        self._cid_to_key[remote_cid] = key
        return key

    def process(self, pkt):
        """Process a packet and update channel state.

        Returns a dict with annotation info if this is a tracked L2CAP
        signaling packet, or None if not relevant.

        Returned dict keys:
            signal: str  -- signal type (e.g. "Connection Request")
            psm: int or None
            local_cid: int or None
            remote_cid: int or None
            channel_key: tuple or None
            detail: str  -- human-readable detail string
        """
        if not self._is_l2cap_signaling(pkt):
            return None

        body = self._body_text(pkt)
        # Determine signal type from the L2CAP line
        full = pkt.summary + "\n" + body

        if "Connection Request" in full and \
                "Disconnection" not in full:
            return self._handle_conn_request(pkt, body)
        elif "Connection Response" in full and \
                "Disconnection" not in full:
            return self._handle_conn_response(pkt, body)
        elif "Configuration Request" in full or \
                "Configure Request" in full:
            return self._handle_config_request(pkt, body)
        elif "Configuration Response" in full or \
                "Configure Response" in full:
            return self._handle_config_response(pkt, body)
        elif "Disconnection Request" in full:
            return self._handle_disconn_request(pkt, body)
        elif "Disconnection Response" in full:
            return self._handle_disconn_response(pkt, body)

        return None

    def _handle_conn_request(self, pkt, body):
        """Handle L2CAP Connection Request."""
        psm_s = self._extract_field(self._PSM_RE, body)
        psm = int(psm_s) if psm_s else None
        src_cid_s = self._extract_field(self._SRC_CID_RE, body)
        src_cid = int(src_cid_s) if src_cid_s else None

        # Extract ident from the L2CAP header line
        ident_s = self._extract_field(self._IDENT_RE,
                                      pkt.summary + "\n" + body)
        ident = int(ident_s) if ident_s else None

        # PSM filter: skip if not matching
        if self.psm_filter is not None and psm not in self.psm_filter:
            return None

        if ident is not None:
            self._pending_conn[(pkt.direction, ident)] = {
                "psm": psm,
                "src_cid": src_cid,
                "direction": pkt.direction,
                "pkt": pkt,
            }

        return {
            "signal": "Connection Request",
            "psm": psm,
            "local_cid": src_cid if pkt.direction == "<" else None,
            "remote_cid": src_cid if pkt.direction == ">" else None,
            "channel_key": None,
            "detail": f"PSM {psm}, CID {src_cid}",
        }

    def _handle_conn_response(self, pkt, body):
        """Handle L2CAP Connection Response."""
        dst_cid_s = self._extract_field(self._DST_CID_RE, body)
        dst_cid = int(dst_cid_s) if dst_cid_s else None
        src_cid_s = self._extract_field(self._SRC_CID_RE, body)
        src_cid = int(src_cid_s) if src_cid_s else None
        result_s = self._extract_field(self._RESULT_RE, body)

        ident_s = self._extract_field(self._IDENT_RE,
                                      pkt.summary + "\n" + body)
        ident = int(ident_s) if ident_s else None

        # Find the matching Connection Request.
        # Response comes from the opposite direction of the Request.
        # If pkt.direction == ">", the Request was "<" (we initiated).
        # If pkt.direction == "<", the Request was ">" (remote initiated).
        req_dir = "<" if pkt.direction == ">" else ">"
        pending_key = (req_dir, ident) if ident is not None else None
        pending = self._pending_conn.get(pending_key) if pending_key \
            else None

        if pending is None:
            # No matching request -- could be for an untracked PSM
            return None

        psm = pending["psm"]
        is_pending = result_s and "pending" in result_s.lower()
        is_success = result_s and "successful" in result_s.lower()
        is_failed = (result_s and not is_pending and not is_success)

        if is_pending:
            # Intermediate "pending" response; don't consume the request
            return {
                "signal": "Connection Response",
                "psm": psm,
                "local_cid": None,
                "remote_cid": None,
                "channel_key": None,
                "detail": f"PSM {psm}: pending",
            }

        # Final response -- consume the pending request
        del self._pending_conn[pending_key]

        if is_failed:
            self._issues.append(Diagnostic(
                f"ERROR: L2CAP Connection for PSM {psm} failed: "
                f"{result_s}",
                frame=pkt.frame,
                timestamp=pkt.timestamp,
                tags=["L2CAP"]))
            return {
                "signal": "Connection Response",
                "psm": psm,
                "local_cid": None,
                "remote_cid": None,
                "channel_key": None,
                "detail": f"PSM {psm}: FAILED ({result_s})",
            }

        # Successful connection -- determine local/remote CIDs.
        # Direction of the original Request determines who is local:
        # '<' Request = we initiated, our CID = Source CID in Request
        if req_dir == "<":
            # We initiated: Source CID (in Response) = our CID,
            # Destination CID = remote's CID
            local_cid = src_cid
            remote_cid = dst_cid
        else:
            # Remote initiated: Source CID (in Response) = remote's,
            # Destination CID = ours
            local_cid = dst_cid
            remote_cid = src_cid

        key = self._register_channel(local_cid, remote_cid, psm, pkt)

        return {
            "signal": "Connection Response",
            "psm": psm,
            "local_cid": local_cid,
            "remote_cid": remote_cid,
            "channel_key": key,
            "detail": f"PSM {psm}: Success "
                      f"(local={local_cid}, remote={remote_cid})",
        }

    def _handle_config_request(self, pkt, body):
        """Handle L2CAP Configure Request."""
        dst_cid_s = self._extract_field(self._DST_CID_RE, body)
        dst_cid = int(dst_cid_s) if dst_cid_s else None
        mtu_s = self._extract_field(self._MTU_RE, body)
        mtu = int(mtu_s) if mtu_s else None

        ident_s = self._extract_field(self._IDENT_RE,
                                      pkt.summary + "\n" + body)
        ident = int(ident_s) if ident_s else None

        # Find channel by destination CID
        ch_key = self._channel_key_for_cid(dst_cid) if dst_cid else None
        if ch_key is None:
            return None  # Not a tracked channel

        ch = self._channels.get(ch_key)
        if ch is None:
            return None

        ch["state"] = "configuring"

        # Record pending config request
        if ident is not None:
            self._pending_config[(pkt.direction, ident)] = {
                "dest_cid": dst_cid,
                "mtu": mtu,
                "pkt": pkt,
                "channel_key": ch_key,
                "psm": ch["psm"],
            }
            if ch.get("config_req_pkt") is None:
                ch["config_req_pkt"] = pkt

        return {
            "signal": "Configure Request",
            "psm": ch["psm"],
            "local_cid": ch_key[0],
            "remote_cid": ch_key[1],
            "channel_key": ch_key,
            "detail": f"PSM {ch['psm']}, dest CID {dst_cid}"
                      + (f", MTU {mtu}" if mtu else ""),
        }

    def _handle_config_response(self, pkt, body):
        """Handle L2CAP Configure Response."""
        src_cid_s = self._extract_field(self._SRC_CID_RE, body)
        src_cid = int(src_cid_s) if src_cid_s else None
        result_s = self._extract_field(self._RESULT_RE, body)

        ident_s = self._extract_field(self._IDENT_RE,
                                      pkt.summary + "\n" + body)
        ident = int(ident_s) if ident_s else None

        # Match to pending Configure Request (opposite direction).
        req_dir = "<" if pkt.direction == ">" else ">"
        pending_key = (req_dir, ident) if ident is not None else None
        pending = self._pending_config.get(pending_key) if pending_key \
            else None

        if pending is None:
            return None  # Not a tracked config request

        ch_key = pending["channel_key"]
        ch = self._channels.get(ch_key)
        if ch is None:
            return None

        # Consume the pending config request
        del self._pending_config[pending_key]

        is_success = result_s and "Success" in result_s

        if is_success:
            # Determine which side's config is now done.
            # The Request was sent by req_dir; the Response confirms it.
            # '<' Request = we sent config, so our_config_done = True
            # '>' Request = they sent config, so their_config_done = True
            if req_dir == "<":
                ch["our_config_done"] = True
                if pending.get("mtu"):
                    ch["mtu_local"] = pending["mtu"]
            else:
                ch["their_config_done"] = True
                if pending.get("mtu"):
                    ch["mtu_remote"] = pending["mtu"]

            # Both sides configured => channel is open
            if ch["our_config_done"] and ch["their_config_done"]:
                ch["state"] = "open"
        else:
            # Config failed/rejected
            detail = f"PSM {ch['psm']}: Config {result_s}"
            # Not necessarily fatal -- peer may retry
            pass

        return {
            "signal": "Configure Response",
            "psm": ch["psm"],
            "local_cid": ch_key[0],
            "remote_cid": ch_key[1],
            "channel_key": ch_key,
            "detail": f"PSM {ch['psm']}: {result_s or '?'}"
                      + (" -> OPEN" if ch["state"] == "open" else ""),
        }

    def _handle_disconn_request(self, pkt, body):
        """Handle L2CAP Disconnection Request."""
        dst_cid_s = self._extract_field(self._DST_CID_RE, body)
        dst_cid = int(dst_cid_s) if dst_cid_s else None
        src_cid_s = self._extract_field(self._SRC_CID_RE, body)
        src_cid = int(src_cid_s) if src_cid_s else None

        # Find channel by either CID
        ch_key = None
        for cid in (dst_cid, src_cid):
            if cid is not None:
                ch_key = self._channel_key_for_cid(cid)
                if ch_key:
                    break

        if ch_key is None:
            return None

        ch = self._channels.get(ch_key)
        if ch is None:
            return None

        ch["state"] = "disconnecting"

        return {
            "signal": "Disconnection Request",
            "psm": ch["psm"],
            "local_cid": ch_key[0],
            "remote_cid": ch_key[1],
            "channel_key": ch_key,
            "detail": f"PSM {ch['psm']} "
                      f"(CIDs {ch_key[0]}/{ch_key[1]})",
        }

    def _handle_disconn_response(self, pkt, body):
        """Handle L2CAP Disconnection Response."""
        dst_cid_s = self._extract_field(self._DST_CID_RE, body)
        dst_cid = int(dst_cid_s) if dst_cid_s else None
        src_cid_s = self._extract_field(self._SRC_CID_RE, body)
        src_cid = int(src_cid_s) if src_cid_s else None

        # Find channel by either CID
        ch_key = None
        for cid in (dst_cid, src_cid):
            if cid is not None:
                ch_key = self._channel_key_for_cid(cid)
                if ch_key:
                    break

        if ch_key is None:
            return None

        ch = self._channels.get(ch_key)
        if ch is None:
            return None

        # Move to completed list
        ch["state"] = "disconnected"
        self._completed.append(dict(ch, key=ch_key))
        # Clean up maps
        del self._channels[ch_key]
        for cid in ch_key:
            self._cid_to_key.pop(cid, None)

        return {
            "signal": "Disconnection Response",
            "psm": ch["psm"],
            "local_cid": ch_key[0],
            "remote_cid": ch_key[1],
            "channel_key": ch_key,
            "detail": f"PSM {ch['psm']} disconnected",
        }

    def get_channel_info(self, cid):
        """Get channel info dict for a CID, or None."""
        key = self._cid_to_key.get(cid)
        if key:
            return self._channels.get(key)
        return None

    def diagnostics(self):
        """Produce diagnostic messages for detected issues.

        Call after all packets have been processed.

        Checks:
        - Pending Connection Requests with no final Response
        - Pending Configure Requests with no Response (half-configured)
        - Channels that never reached "open" state
        """
        diags = list(self._issues)

        # Pending connection requests (never got a final response)
        for (direction, ident), info in self._pending_conn.items():
            psm = info["psm"]
            src_cid = info["src_cid"]
            ref = info["pkt"]
            diags.append(Diagnostic(
                f"ERROR: L2CAP Connection Request for PSM {psm} "
                f"(CID {src_cid}, ident {ident}) never received a "
                f"final Response",
                frame=ref.frame,
                timestamp=ref.timestamp,
                tags=["L2CAP"]))

        # Pending configure requests (never got a response)
        for (direction, ident), info in self._pending_config.items():
            ch_key = info["channel_key"]
            ch = self._channels.get(ch_key)
            psm = info.get("psm") or (ch["psm"] if ch else "?")
            ref = info["pkt"]
            who = "Our" if direction == "<" else "Remote"
            diags.append(Diagnostic(
                f"ERROR: {who} L2CAP Configure Request "
                f"(PSM {psm}, ident {ident}, dest CID "
                f"{info['dest_cid']}) never received a Response "
                f"-- channel half-configured",
                frame=ref.frame,
                timestamp=ref.timestamp,
                tags=["L2CAP"]))

        # Channels still open but never fully configured
        for ch_key, ch in self._channels.items():
            if ch["state"] not in ("open", "disconnected",
                                   "disconnecting"):
                if not ch["our_config_done"] or \
                        not ch["their_config_done"]:
                    our = "done" if ch["our_config_done"] else "MISSING"
                    their = ("done" if ch["their_config_done"]
                             else "MISSING")
                    ref = ch.get("config_req_pkt") or ch["connect_pkt"]
                    diags.append(Diagnostic(
                        f"WARNING: L2CAP channel PSM {ch['psm']} "
                        f"(CIDs {ch_key[0]}/{ch_key[1]}) never "
                        f"fully configured: our config={our}, "
                        f"their config={their}",
                        frame=ref.frame if ref else None,
                        timestamp=ref.timestamp if ref else None,
                        tags=["L2CAP"]))

        # Completed channels that were disconnected before being open
        for ch in self._completed:
            if not ch["our_config_done"] or \
                    not ch["their_config_done"]:
                our = "done" if ch["our_config_done"] else "MISSING"
                their = "done" if ch["their_config_done"] else "MISSING"
                ref = ch.get("config_req_pkt") or ch["connect_pkt"]
                diags.append(Diagnostic(
                    f"ERROR: L2CAP channel PSM {ch['psm']} "
                    f"(CIDs {ch['key'][0]}/{ch['key'][1]}) "
                    f"disconnected before fully configured: "
                    f"our config={our}, their config={their}",
                    frame=ref.frame if ref else None,
                    timestamp=ref.timestamp if ref else None,
                    tags=["L2CAP"]))

        return diags


# ---------------------------------------------------------------------------
# L2CAP annotator
# ---------------------------------------------------------------------------

class L2CAPAnnotator(RuleMatchAnnotator):
    """Annotator for L2CAP channel traces.

    Uses L2CAPChannelTracker to maintain channel state and detect
    lifecycle issues (missing Configure Responses, half-configured
    channels, etc.).
    """

    name = "l2cap"

    def __init__(self):
        super().__init__()
        self._tracker = L2CAPChannelTracker()  # track all PSMs

    def _run_hooks(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)

        if "L2CAP:" in s or "L2CAP:" in body_text:
            # Feed to tracker for stateful analysis
            info = self._tracker.process(pkt)

            if info is not None:
                ann = f"L2CAP {info['signal']}: {info['detail']}"
                self._tag(pkt, "L2CAP", annotation=ann)
                # Flag non-success connection responses as errors
                if info["signal"] == "Connection Response" and \
                        "FAILED" in info["detail"]:
                    self._tag(pkt, "ERROR")
                return True

            # Fallback for L2CAP signals the tracker doesn't handle
            # (e.g. Command Reject, Information Request/Response)
            if "Command Reject" in body_text:
                self._tag(pkt, "L2CAP",
                          annotation="L2CAP Command REJECTED")
            else:
                self._tag(pkt, "L2CAP",
                          annotation="L2CAP signaling")
            return True

        elif "LE Connection Request" in body_text or \
                "LE Connection Request" in s:
            psm_m = re.search(r"PSM:\s*(\d+)", body_text)
            psm = psm_m.group(1) if psm_m else "?"
            self._tag(pkt, ["L2CAP", "LE"],
                      annotation=f"LE L2CAP CoC Request PSM={psm}")
            return True

        elif "LE Connection Response" in body_text or \
                "LE Connection Response" in s:
            self._tag(pkt, ["L2CAP", "LE"],
                      annotation="LE L2CAP CoC Response")
            return True

        elif "PSM:" in body_text and not pkt.tags:
            psm_m = re.search(r"PSM:\s*(\d+)", body_text)
            psm = psm_m.group(1) if psm_m else "?"
            self._tag(pkt, "L2CAP",
                      annotation=f"PSM {psm} referenced")
            return True

        return False

    def finalize(self, packets):
        """Run base checks plus L2CAP tracker diagnostics."""
        diags = super().finalize(packets)
        diags.extend(self._tracker.diagnostics())
        return diags


# ---------------------------------------------------------------------------
# Advertising annotator
# ---------------------------------------------------------------------------

class AdvertisingAnnotator(RuleMatchAnnotator):
    """Annotator for advertising and scanning traces."""

    name = "advertising"


# ---------------------------------------------------------------------------
# HCI Init annotator
# ---------------------------------------------------------------------------

class HCIInitAnnotator(RuleMatchAnnotator):
    """Annotator for HCI initialization sequence."""

    name = "hci_init"
    _skip_init_commands = False

    def annotate_packet(self, pkt):
        """Match declarative rules first; hook handles remainder."""
        self._apply_match_rules(pkt)
        if not pkt.tags:
            self._run_hooks(pkt)

    def _run_hooks(self, pkt):
        s = pkt.summary
        if "Command Complete" in s or "Command Status" in s:
            body_text = "\n".join(pkt.body)
            if "Status:" in body_text and \
                    "Success" not in body_text:
                status_m = re.search(r"Status:\s*(.+)", body_text)
                status = status_m.group(1).strip() if status_m else "?"
                self._tag(pkt, "HCI",
                          annotation=f"Command failed: {status}")
                return True
        return False


# ---------------------------------------------------------------------------
# Channel Sounding annotator
# ---------------------------------------------------------------------------

# RAS (Ranging Service) GATT UUIDs
_RAS_SERVICE_UUID = "0x185B"
_RAS_UUIDS = {
    "0x2C14": "RAS Features",
    "0x2C15": "RAS Real-time Ranging Data",
    "0x2C16": "RAS On-demand Ranging Data",
    "0x2C17": "RAS Control Point",
    "0x2C18": "RAS Ranging Data Ready",
    "0x2C19": "RAS Ranging Data Overwritten",
}

# CS state machine states (per config_id)
_CS_IDLE = "idle"
_CS_CONFIGURED = "configured"
_CS_PARAMS_SET = "params_set"
_CS_RUNNING = "running"

# CS abort reason decode tables (4-bit nibbles)
_CS_PROC_ABORT = {
    0x00: "No abort",
    0x01: "Aborted by host/remote",
    0x02: "Channel map too small (<15)",
    0x03: "Channel map update passed",
    0x0F: "Unspecified",
}
_CS_SUB_ABORT = {
    0x00: "No abort",
    0x01: "Aborted by host/remote",
    0x02: "No CS_SYNC (Mode 0) received",
    0x03: "Scheduling conflict",
    0x0F: "Unspecified",
}


class ChannelSoundingAnnotator(RuleMatchAnnotator):
    """Annotator for Channel Sounding (CS) and Ranging Service (RAS).

    Includes a GATT proximity heuristic: ATT operations on the same
    ACL connection as CS HCI events, within a time window around CS
    activity, are inferred to be RAS/RAP-related even without visible
    UUIDs.  This is necessary because real traces use handle-based
    GATT access where UUIDs are resolved during discovery but not
    repeated in subsequent Read/Write/Notification operations.
    """

    name = "cs"

    # Time margin (seconds) around CS activity to capture GATT ops
    _GATT_MARGIN_BEFORE = 5.0   # GATT setup happens before CS events
    _GATT_MARGIN_AFTER = 2.0    # Notifications arrive shortly after

    def __init__(self):
        super().__init__()
        # CS state machine per config_id
        self._cs_state = {}          # config_id -> state string
        self._cs_transitions = {}    # config_id -> [(ts, old, new, event)]

        # Counters for diagnostics
        self.procedure_count = 0
        self.subevent_count = 0
        self.abort_count = 0
        self.ras_transfer_count = 0

        # Additional flags (beyond those set by match_rules)
        self.saw_config_complete = False
        self.saw_procedure_enable = False
        self.saw_procedure_enable_complete = False
        self.saw_subevent_result = False
        self.saw_ras_discovery = False

        # GATT proximity heuristic state
        self._cs_handles = set()     # HCI connection handles from CS events
        self._cs_timestamps = []     # timestamps of all CS HCI events
        self._gatt_att_count = 0     # ATT packets tagged by heuristic

    # -- GATT proximity heuristic --

    # Regex to extract ACL handle from packet summary.
    # Supports both old btmon format ("ACL Data RX/TX: Handle N")
    # and new format from BlueZ 5.86+ ("LE-ACL: Handle N",
    # "BR-ACL: Handle N", "ACL: Handle N").
    _ACL_HANDLE_RE = re.compile(
        r"(?:ACL Data (?:RX|TX)|(?:LE|BR)-ACL|ACL): Handle (\d+)")
    # CCCD write values that enable notifications (0x0001) or
    # indications (0x0002)
    _CCCD_ENABLE_RE = re.compile(r"Data\[\d+\]: 0[12]00$")

    def annotate(self, packets):
        """Two-pass annotation: CS HCI events first, then GATT heuristic.

        Pass 1: Standard rule + hook annotation tags CS HCI events and
                 records connection handles and timestamps.
        Pass 2: Scans untagged ATT packets on the same ACL connection
                 within a time window around CS activity and infers them
                 as RAS/RAP-related GATT operations.
        """
        # Pass 1: standard annotation
        for pkt in packets:
            self.annotate_packet(pkt)

        # Also extract connection handles from packets tagged by
        # declarative match_rules (which bypass hooks)
        for pkt in packets:
            if pkt.tags and "CS" in pkt.tags:
                body_text = "\n".join(pkt.body)
                m = self._CONN_HANDLE_RE.search(body_text)
                if m:
                    self._cs_handles.add(int(m.group(1)))
                if pkt.timestamp > 0:
                    self._cs_timestamps.append(pkt.timestamp)

        # Pass 2: GATT proximity heuristic
        if self._cs_handles and self._cs_timestamps:
            self._apply_gatt_heuristic(packets)

        return self.finalize(packets)

    def _apply_gatt_heuristic(self, packets):
        """Tag ATT operations near CS events as inferred RAS/GATT.

        Since real traces use handle-based GATT access (no visible
        UUIDs after discovery), we infer that ATT operations on the
        same ACL connection, within a time window around CS activity,
        are RAS-related.
        """
        cs_min = min(self._cs_timestamps) - self._GATT_MARGIN_BEFORE
        cs_max = max(self._cs_timestamps) + self._GATT_MARGIN_AFTER

        for pkt in packets:
            # Skip already-tagged packets
            if pkt.tags:
                continue
            # Only look at ACL data packets with ATT content
            acl_m = self._ACL_HANDLE_RE.search(pkt.summary)
            if not acl_m:
                continue
            acl_handle = int(acl_m.group(1))
            if acl_handle not in self._cs_handles:
                continue
            # Must be in the CS time window
            if not (cs_min <= pkt.timestamp <= cs_max):
                continue
            # Must contain ATT protocol data
            body_text = "\n".join(pkt.body)
            if "ATT:" not in body_text:
                continue

            # Classify the ATT operation
            result = self._classify_att_operation(body_text)
            if result:
                annotation, priority = result
                self._gatt_att_count += 1
                self._tag(pkt, ["CS", "RAS", "GATT"],
                          priority=priority,
                          annotation=annotation)

    def _classify_att_operation(self, body_text):
        """Classify an ATT operation for annotation and priority.

        Returns (annotation, priority) tuple, or None to skip.
        Signaling operations (writes, discovery, reads, errors) are
        ``key`` so they appear in the Key Frames table and get full
        body text in the prefilter.  Bulk data (notifications and
        indications) are ``context`` to avoid flooding.
        """
        handle_m = re.search(r"Handle:\s*(0x[0-9a-fA-F]+)", body_text)
        handle = handle_m.group(1) if handle_m else "?"

        if "Handle Value Notification" in body_text:
            self.ras_transfer_count += 1
            return (f"RAS Ranging Data (notification on {handle})",
                    "context")

        if "Handle Value Indication" in body_text:
            self.ras_transfer_count += 1
            return (f"RAS Ranging Data (indication on {handle})",
                    "context")

        if "Write Request" in body_text:
            if self._CCCD_ENABLE_RE.search(body_text):
                return (f"RAS CCCD enable notifications ({handle})",
                        "key")
            return (f"RAS GATT Write ({handle})", "key")

        if "Write Response" in body_text:
            return None   # response to write, not interesting on its own

        if "Read Request" in body_text:
            return (f"RAS GATT Read ({handle})", "key")

        if "Read Response" in body_text:
            return (f"RAS GATT Read Response", "context")

        if "Read By Type" in body_text:
            return (f"RAS GATT characteristic discovery", "key")

        if "Read By Group Type" in body_text:
            return (f"RAS GATT service discovery", "key")

        if "Find Information" in body_text:
            return (f"RAS GATT descriptor discovery", "key")

        if "Error Response" in body_text:
            return (f"RAS GATT Error Response ({handle})", "key")

        return None

    # -- Hooks: stateful CS event processing --

    # Regex for extracting connection handle (btmon uses mixed casing)
    _CONN_HANDLE_RE = re.compile(
        r"Connection [Hh]andle:\s*(\d+)", re.MULTILINE)

    def _extract_conn_handle(self, body_text, pkt):
        """Extract connection handle and record CS activity."""
        m = self._CONN_HANDLE_RE.search(body_text)
        if m:
            self._cs_handles.add(int(m.group(1)))
        self._cs_timestamps.append(pkt.timestamp)

    def _run_hooks(self, pkt):
        s = pkt.summary
        body_text = "\n".join(pkt.body)

        # CS Config Complete (async event after Create Config)
        if "LE CS Config Complete" in body_text and pkt.direction == ">":
            return self._handle_config_complete(pkt, body_text)

        # CS Procedure Enable/Disable command
        if "LE CS Procedure Enable" in s and pkt.direction == "<":
            return self._handle_procedure_enable_cmd(pkt, body_text)

        # CS Procedure Enable Complete (async event)
        if "LE CS Procedure Enable Complete" in body_text \
                and pkt.direction == ">":
            return self._handle_procedure_enable_complete(pkt, body_text)

        # CS Subevent Result / Subevent Result Continue
        if "LE CS Subevent Result" in body_text and pkt.direction == ">":
            return self._handle_subevent_result(pkt, body_text)

        # RAS GATT characteristics
        if any(uuid in body_text for uuid in _RAS_UUIDS) \
                or _RAS_SERVICE_UUID in body_text:
            return self._handle_ras(pkt, body_text)

        return False

    def _get_state(self, config_id):
        return self._cs_state.get(config_id, _CS_IDLE)

    def _transition(self, config_id, new_state, event, ts):
        old = self._get_state(config_id)
        self._cs_state[config_id] = new_state
        if config_id not in self._cs_transitions:
            self._cs_transitions[config_id] = []
        self._cs_transitions[config_id].append(
            (ts, old, new_state, event))

    def _handle_config_complete(self, pkt, body_text):
        self._extract_conn_handle(body_text, pkt)
        config_m = re.search(r"Config ID:\s*(\d+)", body_text)
        config_id = int(config_m.group(1)) if config_m else 0
        status_ok = "Success" in body_text

        if status_ok:
            self.saw_config_complete = True
            # Reflectors receive Config Complete without sending
            # Create Config, so also mark saw_create_config to avoid
            # false absence diagnostics.
            self.saw_create_config = True
            # Extract negotiated timing
            mode_m = re.search(r"Main Mode Type:\s*(0x[0-9a-fA-F]+)",
                               body_text)
            role_m = re.search(r"Role:\s*(.+?)(?:\s*\(|$)", body_text,
                               re.MULTILINE)
            mode = mode_m.group(1) if mode_m else "?"
            role = role_m.group(1).strip() if role_m else "?"
            self._tag(pkt, ["CS", "HCI"],
                      annotation=f"CS Config Complete: id={config_id} "
                                 f"mode={mode} role={role}")
            self._transition(config_id, _CS_CONFIGURED,
                             "Config Complete", pkt.timestamp)
        else:
            status_m = re.search(r"Status:\s*(.+)", body_text)
            status = status_m.group(1).strip() if status_m else "?"
            self._tag(pkt, ["CS", "HCI"],
                      annotation=f"CS Config Complete FAILED: "
                                 f"id={config_id} {status}")
        return True

    def _handle_procedure_enable_cmd(self, pkt, body_text):
        config_m = re.search(r"Config ID:\s*(\d+)", body_text)
        enable_m = re.search(r"Enable:\s*(0x[0-9a-fA-F]+)", body_text)
        config_id = int(config_m.group(1)) if config_m else 0
        enable = enable_m.group(1) if enable_m else "?"
        enabled = enable != "0x00"
        self.saw_procedure_enable = True

        if enabled:
            self._tag(pkt, ["CS", "HCI"],
                      annotation=f"CS Procedure Enable: id={config_id}")
        else:
            self._tag(pkt, ["CS", "HCI"],
                      annotation=f"CS Procedure Disable: id={config_id}")
        return True

    def _handle_procedure_enable_complete(self, pkt, body_text):
        self._extract_conn_handle(body_text, pkt)
        config_m = re.search(r"Config ID:\s*(\d+)", body_text)
        # btmon may output State as decimal (1) or hex (0x01)
        state_m = re.search(r"State:\s*(?:0x)?([0-9a-fA-F]+)", body_text)
        config_id = int(config_m.group(1)) if config_m else 0
        state_val = int(state_m.group(1), 16) if state_m else -1
        status_ok = "Success" in body_text

        if not status_ok:
            status_m = re.search(r"Status:\s*(.+)", body_text)
            status = status_m.group(1).strip() if status_m else "?"
            self._tag(pkt, ["CS", "HCI"],
                      annotation=f"CS Procedure Enable FAILED: "
                                 f"id={config_id} {status}")
            return True

        self.saw_procedure_enable_complete = True
        enabled = state_val == 1

        if enabled:
            self.procedure_count += 1
            # Extract scheduling details
            count_m = re.search(r"Procedure Count:\s*(\d+)", body_text)
            sub_m = re.search(r"Subevents Per Event:\s*(\d+)", body_text)
            pwr_m = re.search(r"Selected TX Power:\s*([\-\d]+)",
                              body_text)
            count = count_m.group(1) if count_m else "?"
            subs = sub_m.group(1) if sub_m else "?"
            pwr = pwr_m.group(1) if pwr_m else "?"
            self._tag(pkt, ["CS", "HCI"],
                      annotation=f"CS Procedure Started: id={config_id} "
                                 f"count={count} subs/evt={subs} "
                                 f"tx_pwr={pwr}")
            self._transition(config_id, _CS_RUNNING,
                             "Procedure Enable Complete (state=1)",
                             pkt.timestamp)
        else:
            self._tag(pkt, ["CS", "HCI"],
                      annotation=f"CS Procedure Stopped: id={config_id}")
            self._transition(config_id, _CS_CONFIGURED,
                             "Procedure Enable Complete (state=0)",
                             pkt.timestamp)
        return True

    def _handle_subevent_result(self, pkt, body_text):
        self._extract_conn_handle(body_text, pkt)
        self.saw_subevent_result = True
        self.subevent_count += 1

        is_continue = "Subevent Result Continue" in body_text

        # Extract key fields
        steps_m = re.search(r"Num Steps Reported:\s*(\d+)", body_text)
        proc_done_m = re.search(
            r"Procedure Done Status:\s*(.+?)(?:\s*\(|$)",
            body_text, re.MULTILINE)
        abort_m = re.search(r"Abort Reason:\s*(0x[0-9a-fA-F]+)",
                            body_text)

        steps = steps_m.group(1) if steps_m else "?"
        proc_done = proc_done_m.group(1).strip() if proc_done_m else "?"

        # Check for aborts
        abort_detail = ""
        if abort_m:
            abort_val = int(abort_m.group(1), 16)
            proc_abort = abort_val & 0x0F
            sub_abort = (abort_val >> 4) & 0x0F
            if proc_abort != 0 or sub_abort != 0:
                self.abort_count += 1
                parts = []
                if proc_abort != 0:
                    parts.append(f"proc={_CS_PROC_ABORT.get(proc_abort, '?')}")
                if sub_abort != 0:
                    parts.append(f"sub={_CS_SUB_ABORT.get(sub_abort, '?')}")
                abort_detail = " ABORT: " + ", ".join(parts)

        kind = "Continue" if is_continue else "Result"

        # Only tag key frames for first result, aborts, and procedure-done
        if abort_detail or "All results complete" in proc_done \
                or self.subevent_count <= 3:
            self._tag(pkt, ["CS", "HCI"],
                      annotation=f"CS Subevent {kind}: "
                                 f"{steps} steps{abort_detail}")
        else:
            # Mark as context to avoid flooding key frames table
            self._tag(pkt, ["CS"], priority="context",
                      annotation=f"CS Subevent {kind}: {steps} steps")
        return True

    def _handle_ras(self, pkt, body_text):
        # RAS Service discovery
        if _RAS_SERVICE_UUID in body_text:
            self.saw_ras_discovery = True
            self._tag(pkt, ["CS", "RAS", "GATT"],
                      annotation="RAS Service discovered (UUID 0x185B)")
            return True

        # RAS characteristic operations
        for uuid, name in _RAS_UUIDS.items():
            if uuid not in body_text:
                continue

            if uuid == "0x2C14":  # Features
                self._tag(pkt, ["CS", "RAS", "GATT"],
                          annotation=f"RAS Features read")
                return True

            if uuid == "0x2C18":  # Data Ready
                self._tag(pkt, ["CS", "RAS", "GATT"],
                          annotation="RAS Ranging Data Ready")
                return True

            if uuid == "0x2C19":  # Data Overwritten
                self._tag(pkt, ["CS", "RAS", "GATT"],
                          annotation="RAS Ranging Data Overwritten")
                return True

            if uuid == "0x2C17":  # Control Point
                op_m = re.search(r"Opcode:\s*(.+?)(?:\s*\(|$)",
                                 body_text, re.MULTILINE)
                opcode = op_m.group(1).strip() if op_m else "?"
                self._tag(pkt, ["CS", "RAS", "GATT"],
                          annotation=f"RAS Control Point: {opcode}")
                return True

            if uuid in ("0x2C15", "0x2C16"):  # Ranging data
                seg_m = re.search(
                    r"First Segment:\s*(True|False)", body_text)
                last_m = re.search(
                    r"Last Segment:\s*(True|False)", body_text)
                first = seg_m and seg_m.group(1) == "True"
                last = last_m and last_m.group(1) == "True"
                kind = "Real-time" if uuid == "0x2C15" else "On-demand"
                if first:
                    self.ras_transfer_count += 1
                flags = []
                if first:
                    flags.append("first")
                if last:
                    flags.append("last")
                seg_info = f" [{'+'.join(flags)}]" if flags else ""
                self._tag(pkt, ["CS", "RAS", "GATT"],
                          annotation=f"RAS {kind} Ranging Data{seg_info}")
                return True

            # Generic RAS characteristic
            self._tag(pkt, ["CS", "RAS", "GATT"],
                      annotation=f"{name}")
            return True

        return False

    # -- Finalize: state machine diagnostics --

    def finalize(self, packets):
        diags = super().finalize(packets)

        # Emit state machine transition summaries per config_id
        for config_id in sorted(self._cs_transitions):
            transitions = self._cs_transitions[config_id]
            if not transitions:
                continue
            lines = [f"STATE: Config ID {config_id} "
                     f"CS state transitions:"]
            for ts, old, new, event in transitions:
                lines.append(
                    f"        {ts:.3f}s {old:>14s} -> "
                    f"{new:<14s} ({event})")
            first_ts = transitions[0][0]
            first_frame = None
            for p in packets:
                if abs(p.timestamp - first_ts) < 0.001:
                    first_frame = p.frame
                    break
            diags.append(Diagnostic(
                "\n".join(lines),
                frame=first_frame,
                timestamp=first_ts,
                tags=["CS"]))

        # GATT proximity heuristic summary
        if self._gatt_att_count > 0:
            diags.append(Diagnostic(
                f"NOTE: {self._gatt_att_count} GATT operation(s) "
                f"inferred as RAS-related by proximity heuristic "
                f"(same ACL connection, within time window of CS "
                f"activity)."))

        return diags


# ---------------------------------------------------------------------------
# Disconnection annotator (specialization of connections)
# ---------------------------------------------------------------------------

class DisconnectionAnnotator(RuleMatchAnnotator):
    """Annotator focused on disconnection analysis."""

    name = "disconnection"

    def _run_hooks(self, pkt):
        s = pkt.summary
        if "Disconnect" in s and pkt.direction in ("<", ">"):
            body_text = "\n".join(pkt.body)
            handle_m = re.search(r"Handle:\s*(\d+)", body_text)
            handle = handle_m.group(1) if handle_m else "?"
            self._tag_disconnect(pkt, handle=handle)
            return True
        return False


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
    "Channel Sounding": ChannelSoundingAnnotator,
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
# Prefiltered log output (moved to prefilter.py; re-exported for compat)
# ---------------------------------------------------------------------------

from prefilter import (  # noqa: E402
    prefilter,
    format_filter_markdown,
    _format_packet,
    _format_packet_raw,
)


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


def format_annotation_markdown(packets, focus):
    """Format annotation results as Step 3: Key Frames table.

    Produces a key frames table with timestamps, frame numbers, and
    semantic labels that can be referenced in the analysis step.

    Args:
        packets: List of Packet objects (already annotated).
        focus: Focus area string.

    Returns:
        Markdown string suitable for posting as a GitHub issue comment.
    """
    key_pkts = [p for p in packets if p.priority == "key"]
    ctx_pkts = [p for p in packets if p.priority == "context"]

    lines = ["## Step 3: Annotation", ""]
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

    return "\n".join(lines)


# Diagnostics formatting (moved to diagnose.py; re-exported for compat)
from diagnose import format_diagnostics_markdown  # noqa: E402


def format_markdown(packets, diags, focus):
    """Format annotation + diagnostics as markdown (backward compat).

    Combines format_annotation_markdown() and
    format_diagnostics_markdown() into a single output.

    Args:
        packets: List of Packet objects (already annotated).
        diags: List of diagnostic strings from the annotator.
        focus: Focus area string.

    Returns:
        Markdown string suitable for posting as a GitHub issue comment.
    """
    parts = [format_annotation_markdown(packets, focus)]
    diag_md = format_diagnostics_markdown(packets, diags)
    if diag_md.strip():
        parts.append(diag_md)
    return "\n".join(parts)


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
