"""Tests for L2CAP channel lifecycle tracking.

Tests the L2CAPChannelTracker class which tracks:
- Connection Request/Response pairs (CID <-> PSM mapping)
- Configure Request/Response pairs (detect missing responses)
- Channel state lifecycle (connecting -> configured -> open)
- Half-configured channels (missing Configure Response)
- PSM filtering for focused tracking
"""

from packet import Packet
from annotate import L2CAPChannelTracker, annotate_trace


def _make_packet(direction, summary, body_lines, frame=0, ts=0.0):
    """Helper to construct a Packet with a raw header."""
    pkt = Packet(
        line_start=0, line_end=len(body_lines),
        direction=direction, summary=summary,
        frame=frame, timestamp=ts, body=body_lines,
    )
    pkt._raw_header = f"{direction} {summary}  #{frame} [hci0] {ts}"
    return pkt


# ---------------------------------------------------------------------------
# Realistic L2CAP signaling packet builders
# ---------------------------------------------------------------------------

def _conn_request(direction, psm, src_cid, ident, frame=0, ts=0.0):
    """Build an L2CAP Connection Request packet."""
    return _make_packet(
        direction,
        f"ACL Data {'TX' if direction == '<' else 'RX'}: "
        f"Handle 256 flags 0x00 dlen 12",
        [f"      L2CAP: Connection Request (0x02) ident {ident} len 4",
         f"        PSM: {psm} (0x{psm:04x})",
         f"        Source CID: {src_cid}"],
        frame=frame, ts=ts,
    )


def _conn_response(direction, dst_cid, src_cid, ident, result,
                    frame=0, ts=0.0):
    """Build an L2CAP Connection Response packet."""
    result_map = {
        "successful": "Connection successful (0x0000)",
        "pending": "Connection pending (0x0001)",
        "refused_psm": "Connection refused - PSM not supported (0x0002)",
        "refused_security": "Connection refused - security block (0x0003)",
    }
    result_str = result_map.get(result, result)
    return _make_packet(
        direction,
        f"ACL Data {'TX' if direction == '<' else 'RX'}: "
        f"Handle 256 flags 0x00 dlen 16",
        [f"      L2CAP: Connection Response (0x03) ident {ident} len 8",
         f"        Destination CID: {dst_cid}",
         f"        Source CID: {src_cid}",
         f"        Result: {result_str}",
         "        Status: No further information available (0x0000)"],
        frame=frame, ts=ts,
    )


def _config_request(direction, dest_cid, ident, mtu=None,
                     frame=0, ts=0.0):
    """Build an L2CAP Configure Request packet."""
    body = [
        f"      L2CAP: Configure Request (0x04) ident {ident} len 19",
        f"        Destination CID: {dest_cid}",
        "        Flags: 0x0000",
    ]
    if mtu is not None:
        body.append("        Option: Maximum Transmission Unit "
                     "(0x01) [mandatory]")
        body.append(f"          MTU: {mtu}")
    return _make_packet(
        direction,
        f"ACL Data {'TX' if direction == '<' else 'RX'}: "
        f"Handle 256 flags 0x00 dlen 27",
        body, frame=frame, ts=ts,
    )


def _config_response(direction, src_cid, ident, result="Success",
                      frame=0, ts=0.0):
    """Build an L2CAP Configure Response packet."""
    return _make_packet(
        direction,
        f"ACL Data {'TX' if direction == '<' else 'RX'}: "
        f"Handle 256 flags 0x00 dlen 18",
        [f"      L2CAP: Configure Response (0x05) ident {ident} len 10",
         f"        Source CID: {src_cid}",
         "        Flags: 0x0000",
         f"        Result: {result} (0x0000)"],
        frame=frame, ts=ts,
    )


def _disconn_request(direction, dst_cid, src_cid, ident,
                      frame=0, ts=0.0):
    """Build an L2CAP Disconnection Request packet."""
    return _make_packet(
        direction,
        f"ACL Data {'TX' if direction == '<' else 'RX'}: "
        f"Handle 256 flags 0x00 dlen 12",
        [f"      L2CAP: Disconnection Request (0x06) ident {ident} len 4",
         f"        Destination CID: {dst_cid}",
         f"        Source CID: {src_cid}"],
        frame=frame, ts=ts,
    )


def _disconn_response(direction, dst_cid, src_cid, ident,
                       frame=0, ts=0.0):
    """Build an L2CAP Disconnection Response packet."""
    return _make_packet(
        direction,
        f"ACL Data {'TX' if direction == '<' else 'RX'}: "
        f"Handle 256 flags 0x00 dlen 12",
        [f"      L2CAP: Disconnection Response (0x07) ident {ident} len 4",
         f"        Destination CID: {dst_cid}",
         f"        Source CID: {src_cid}"],
        frame=frame, ts=ts,
    )


# ---------------------------------------------------------------------------
# Test: Basic channel lifecycle (happy path)
# ---------------------------------------------------------------------------

class TestTrackerHappyPath:
    """Test a normal L2CAP channel open/configure/disconnect cycle."""

    def _create_happy_path_packets(self):
        """Create a complete, successful L2CAP channel lifecycle.

        Sequence:
        1. < Connection Request PSM 25, Src CID 65
        2. > Connection Response: pending
        3. > Connection Response: successful (Dst CID 321, Src CID 65)
        4. < Configure Request dest CID 321, MTU 1021
        5. > Configure Request dest CID 65, MTU 895
        6. < Configure Response ident 6 (their request), Success
        7. > Configure Response ident 1 (our request), Success
        8. < Disconnection Request
        9. > Disconnection Response
        """
        return [
            _conn_request("<", 25, 65, ident=1, frame=269, ts=33.106),
            _conn_response(">", 321, 65, ident=1, result="pending",
                           frame=271, ts=33.116),
            _conn_response(">", 321, 65, ident=1, result="successful",
                           frame=272, ts=33.117),
            _config_request("<", 321, ident=1, mtu=1021,
                            frame=273, ts=33.118),
            _config_request(">", 65, ident=6, mtu=895,
                            frame=274, ts=33.119),
            _config_response("<", 321, ident=6, frame=275, ts=33.120),
            _config_response(">", 65, ident=1, frame=276, ts=33.121),
            _disconn_request("<", 321, 65, ident=2, frame=313, ts=64.019),
            _disconn_response(">", 321, 65, ident=2, frame=317,
                              ts=64.038),
        ]

    def test_no_diagnostics_on_happy_path(self):
        """A fully successful lifecycle should produce no error diags."""
        tracker = L2CAPChannelTracker()
        for pkt in self._create_happy_path_packets():
            tracker.process(pkt)
        diags = tracker.diagnostics()
        errors = [d for d in diags if "ERROR" in str(d)]
        assert errors == [], f"Expected no errors, got: {errors}"

    def test_channel_reaches_open_state(self):
        """After both config responses, channel should be open."""
        tracker = L2CAPChannelTracker()
        pkts = self._create_happy_path_packets()
        for pkt in pkts[:7]:  # up through both Configure Responses
            tracker.process(pkt)
        # Channel (65, 321) should be open
        ch = tracker.get_channel_info(65)
        assert ch is not None
        assert ch["state"] == "open"
        assert ch["our_config_done"]
        assert ch["their_config_done"]

    def test_conn_request_returns_info(self):
        """Connection Request should return signal info."""
        tracker = L2CAPChannelTracker()
        pkt = _conn_request("<", 25, 65, ident=1, frame=269, ts=33.106)
        info = tracker.process(pkt)
        assert info is not None
        assert info["signal"] == "Connection Request"
        assert info["psm"] == 25

    def test_conn_response_pending_does_not_register(self):
        """Pending response should not register a channel."""
        tracker = L2CAPChannelTracker()
        tracker.process(
            _conn_request("<", 25, 65, ident=1, frame=269, ts=33.106))
        tracker.process(
            _conn_response(">", 321, 65, ident=1, result="pending",
                           frame=271, ts=33.116))
        # No channel should be registered yet
        assert tracker.get_channel_info(65) is None

    def test_conn_response_successful_registers_channel(self):
        """Successful response should register the channel."""
        tracker = L2CAPChannelTracker()
        tracker.process(
            _conn_request("<", 25, 65, ident=1, frame=269, ts=33.106))
        tracker.process(
            _conn_response(">", 321, 65, ident=1, result="successful",
                           frame=272, ts=33.117))
        ch = tracker.get_channel_info(65)
        assert ch is not None
        assert ch["psm"] == 25
        assert ch["state"] == "connected"

    def test_channel_cid_lookup_both_sides(self):
        """Both local and remote CIDs should look up the same channel."""
        tracker = L2CAPChannelTracker()
        tracker.process(
            _conn_request("<", 25, 65, ident=1, frame=269, ts=33.106))
        tracker.process(
            _conn_response(">", 321, 65, ident=1, result="successful",
                           frame=272, ts=33.117))
        ch_local = tracker.get_channel_info(65)
        ch_remote = tracker.get_channel_info(321)
        assert ch_local is ch_remote

    def test_disconnect_removes_channel(self):
        """After disconnect response, channel should be cleaned up."""
        tracker = L2CAPChannelTracker()
        for pkt in self._create_happy_path_packets():
            tracker.process(pkt)
        assert tracker.get_channel_info(65) is None
        assert tracker.get_channel_info(321) is None


# ---------------------------------------------------------------------------
# Test: Missing Configure Response (the issue #8 bug)
# ---------------------------------------------------------------------------

class TestMissingConfigResponse:
    """Test detection of missing L2CAP Configure Response."""

    def _create_half_configured_packets(self):
        """Reproduce issue #8: our Configure Request gets no Response.

        Sequence:
        1. < Connection Request PSM 25, Src CID 65
        2. > Connection Response: successful (Dst CID 321)
        3. < Configure Request ident 1 dest CID 321 (our config)
        4. > Configure Request ident 6 dest CID 65 (their config)
        5. < Configure Response ident 6 (we respond to their request)
        -- NO Configure Response for ident 1 from remote --
        6. < Disconnection Request
        7. > Disconnection Response
        """
        return [
            _conn_request("<", 25, 65, ident=1, frame=269, ts=33.106),
            _conn_response(">", 321, 65, ident=1, result="successful",
                           frame=272, ts=33.117),
            _config_request("<", 321, ident=1, mtu=1021,
                            frame=273, ts=33.118),
            _config_request(">", 65, ident=6, mtu=895,
                            frame=274, ts=33.119),
            _config_response("<", 321, ident=6, frame=275, ts=33.120),
            # NO config response for ident 1
            _disconn_request("<", 321, 65, ident=2, frame=313, ts=64.019),
            _disconn_response(">", 321, 65, ident=2, frame=317,
                              ts=64.038),
        ]

    def test_detects_missing_config_response(self):
        """Should diagnose that our Configure Request got no Response."""
        tracker = L2CAPChannelTracker()
        for pkt in self._create_half_configured_packets():
            tracker.process(pkt)
        diags = tracker.diagnostics()
        diag_strs = [str(d) for d in diags]
        # Should mention the missing configure response
        config_errors = [d for d in diag_strs
                         if "Configure Request" in d and "never" in d]
        assert len(config_errors) >= 1, \
            f"Expected config error, got: {diag_strs}"

    def test_channel_not_open(self):
        """Channel with missing config response should not be open."""
        tracker = L2CAPChannelTracker()
        pkts = self._create_half_configured_packets()
        for pkt in pkts[:5]:  # up to our response to their request
            tracker.process(pkt)
        ch = tracker.get_channel_info(65)
        assert ch is not None
        assert ch["state"] != "open"
        assert ch["their_config_done"] is True
        assert ch["our_config_done"] is False

    def test_disconnected_before_configured(self):
        """Should report channel disconnected before fully configured."""
        tracker = L2CAPChannelTracker()
        for pkt in self._create_half_configured_packets():
            tracker.process(pkt)
        diags = tracker.diagnostics()
        diag_strs = [str(d) for d in diags]
        disconn_errors = [d for d in diag_strs
                          if "disconnected before fully configured" in d]
        assert len(disconn_errors) >= 1, \
            f"Expected disconnect-before-configured, got: {diag_strs}"

    def test_error_references_correct_frame(self):
        """Diagnostic should reference the Configure Request frame."""
        tracker = L2CAPChannelTracker()
        for pkt in self._create_half_configured_packets():
            tracker.process(pkt)
        diags = tracker.diagnostics()
        config_diags = [d for d in diags
                        if "Configure Request" in str(d)]
        assert len(config_diags) >= 1
        assert config_diags[0].frame == 273  # the Configure Request


# ---------------------------------------------------------------------------
# Test: Missing Configure Response at end of trace (no disconnect)
# ---------------------------------------------------------------------------

class TestMissingConfigAtTraceEnd:
    """Channel still active at trace end with missing config response."""

    def test_detects_half_configured_at_trace_end(self):
        """Should detect half-configured channel when trace ends."""
        tracker = L2CAPChannelTracker()
        pkts = [
            _conn_request("<", 25, 65, ident=1, frame=269, ts=33.106),
            _conn_response(">", 321, 65, ident=1, result="successful",
                           frame=272, ts=33.117),
            _config_request("<", 321, ident=1, mtu=1021,
                            frame=273, ts=33.118),
            # Trace ends here -- no config response, no disconnect
        ]
        for pkt in pkts:
            tracker.process(pkt)
        diags = tracker.diagnostics()
        diag_strs = [str(d) for d in diags]
        # Should find both: pending config request + half-configured channel
        assert any("Configure Request" in d and "never" in d
                    for d in diag_strs), \
            f"Expected pending config diag, got: {diag_strs}"
        assert any("never fully configured" in d for d in diag_strs), \
            f"Expected half-configured warning, got: {diag_strs}"


# ---------------------------------------------------------------------------
# Test: PSM filter
# ---------------------------------------------------------------------------

class TestPSMFilter:
    """Test that PSM filtering works correctly."""

    def test_psm_filter_tracks_matching(self):
        """Tracker with psm_filter={25} should track PSM 25."""
        tracker = L2CAPChannelTracker(psm_filter={25})
        info = tracker.process(
            _conn_request("<", 25, 65, ident=1, frame=1, ts=1.0))
        assert info is not None
        assert info["psm"] == 25

    def test_psm_filter_ignores_non_matching(self):
        """Tracker with psm_filter={25} should ignore PSM 1."""
        tracker = L2CAPChannelTracker(psm_filter={25})
        info = tracker.process(
            _conn_request("<", 1, 192, ident=1, frame=1, ts=1.0))
        assert info is None

    def test_no_filter_tracks_all(self):
        """Tracker with no filter should track all PSMs."""
        tracker = L2CAPChannelTracker()
        info1 = tracker.process(
            _conn_request("<", 1, 192, ident=1, frame=1, ts=1.0))
        info25 = tracker.process(
            _conn_request("<", 25, 65, ident=2, frame=2, ts=2.0))
        assert info1 is not None
        assert info25 is not None


# ---------------------------------------------------------------------------
# Test: Remote-initiated connection
# ---------------------------------------------------------------------------

class TestRemoteInitiated:
    """Test tracking when remote initiates the L2CAP connection."""

    def test_remote_initiated_connection(self):
        """Remote '>' Connection Request should be tracked correctly."""
        tracker = L2CAPChannelTracker()
        # Remote sends Connection Request
        tracker.process(
            _conn_request(">", 23, 386, ident=7, frame=278, ts=33.728))
        # We respond with pending then successful
        tracker.process(
            _conn_response("<", 66, 386, ident=7, result="pending",
                           frame=279, ts=33.729))
        info = tracker.process(
            _conn_response("<", 66, 386, ident=7, result="successful",
                           frame=280, ts=33.730))
        assert info is not None
        assert info["signal"] == "Connection Response"
        assert "Success" in info["detail"]
        # Channel registered: local=66, remote=386
        ch = tracker.get_channel_info(66)
        assert ch is not None
        assert ch["psm"] == 23


# ---------------------------------------------------------------------------
# Test: Connection refused
# ---------------------------------------------------------------------------

class TestConnectionRefused:
    """Test tracking when connection is refused."""

    def test_connection_refused_generates_error_diag(self):
        """Refused connection should produce an error diagnostic."""
        tracker = L2CAPChannelTracker()
        tracker.process(
            _conn_request("<", 25, 65, ident=1, frame=1, ts=1.0))
        tracker.process(
            _conn_response(">", 0, 65, ident=1,
                           result="refused_psm", frame=2, ts=2.0))
        diags = tracker.diagnostics()
        diag_strs = [str(d) for d in diags]
        assert any("failed" in d.lower() or "refused" in d.lower()
                    for d in diag_strs), \
            f"Expected connection refused diag, got: {diag_strs}"


# ---------------------------------------------------------------------------
# Test: Multiple channels simultaneously
# ---------------------------------------------------------------------------

class TestMultipleChannels:
    """Test tracking multiple channels at the same time."""

    def test_two_channels_independent(self):
        """Two independent channels should not interfere."""
        tracker = L2CAPChannelTracker()
        # Channel 1: PSM 25 (AVDTP)
        tracker.process(
            _conn_request("<", 25, 65, ident=1, frame=1, ts=1.0))
        tracker.process(
            _conn_response(">", 321, 65, ident=1, result="successful",
                           frame=2, ts=2.0))
        # Channel 2: PSM 23 (AVCTP)
        tracker.process(
            _conn_request(">", 23, 386, ident=7, frame=3, ts=3.0))
        tracker.process(
            _conn_response("<", 66, 386, ident=7, result="successful",
                           frame=4, ts=4.0))
        # Both channels should exist
        ch1 = tracker.get_channel_info(65)
        ch2 = tracker.get_channel_info(66)
        assert ch1 is not None
        assert ch2 is not None
        assert ch1["psm"] == 25
        assert ch2["psm"] == 23

    def test_one_half_configured_one_ok(self):
        """One half-configured + one fully open = only one error."""
        tracker = L2CAPChannelTracker()
        # Channel 1: PSM 25 -- will be half-configured
        tracker.process(
            _conn_request("<", 25, 65, ident=1, frame=1, ts=1.0))
        tracker.process(
            _conn_response(">", 321, 65, ident=1, result="successful",
                           frame=2, ts=2.0))
        tracker.process(
            _config_request("<", 321, ident=1, mtu=1021,
                            frame=3, ts=3.0))
        # Their config + our response
        tracker.process(
            _config_request(">", 65, ident=6, mtu=895,
                            frame=4, ts=4.0))
        tracker.process(
            _config_response("<", 321, ident=6, frame=5, ts=5.0))
        # NO response for ident 1

        # Channel 2: PSM 23 -- fully configured
        tracker.process(
            _conn_request(">", 23, 386, ident=7, frame=6, ts=6.0))
        tracker.process(
            _conn_response("<", 66, 386, ident=7, result="successful",
                           frame=7, ts=7.0))
        tracker.process(
            _config_request("<", 386, ident=2, frame=8, ts=8.0))
        tracker.process(
            _config_request(">", 66, ident=9, frame=9, ts=9.0))
        tracker.process(
            _config_response(">", 66, ident=2, frame=10, ts=10.0))
        tracker.process(
            _config_response("<", 386, ident=9, frame=11, ts=11.0))

        diags = tracker.diagnostics()
        # Channel 2 should be open, no errors
        ch2 = tracker.get_channel_info(66)
        assert ch2 is not None
        assert ch2["state"] == "open"
        # Channel 1 should have errors
        config_errors = [d for d in diags
                         if "Configure Request" in str(d)
                         and "never" in str(d)]
        assert len(config_errors) == 1


# ---------------------------------------------------------------------------
# Test: Non-L2CAP packets are ignored
# ---------------------------------------------------------------------------

class TestNonL2CAPIgnored:
    """Test that non-L2CAP packets are silently ignored."""

    def test_avdtp_packet_ignored(self):
        """AVDTP signaling should not be processed by tracker."""
        tracker = L2CAPChannelTracker()
        pkt = _make_packet(
            ">", "ACL Data RX: Handle 256 flags 0x02 dlen 6",
            ["      Channel: 64 len 2 [PSM 25 mode Basic] {chan 0}",
             "      AVDTP: Open (0x06) Response Accept"],
            frame=268, ts=33.106,
        )
        info = tracker.process(pkt)
        assert info is None

    def test_hci_event_ignored(self):
        """HCI events should not be processed by tracker."""
        tracker = L2CAPChannelTracker()
        pkt = _make_packet(
            ">", "HCI Event: Number of Completed Packets (0x13) plen 5",
            ["        Num handles: 1",
             "        Handle: 256"],
            frame=270, ts=33.110,
        )
        info = tracker.process(pkt)
        assert info is None


# ---------------------------------------------------------------------------
# Test: Integration with L2CAPAnnotator
# ---------------------------------------------------------------------------

class TestL2CAPAnnotatorIntegration:
    """Test the L2CAPAnnotator uses the tracker for annotations."""

    def _make_trace_text(self):
        """Build a minimal btmon-like text with L2CAP signaling."""
        lines = [
            "Bluetooth monitor ver 5.64",
            "= Note: Linux version 6.1.0 (x86_64)                        0.000000",
            "< ACL Data TX: Handle 256 flags 0x00 dlen 12"
            "        #1 [hci0] 1.000000",
            "      L2CAP: Connection Request (0x02) ident 1 len 4",
            "        PSM: 1 (0x0001)",
            "        Source CID: 64",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 16"
            "        #2 [hci0] 2.000000",
            "      L2CAP: Connection Response (0x03) ident 1 len 8",
            "        Destination CID: 192",
            "        Source CID: 64",
            "        Result: Connection successful (0x0000)",
            "        Status: No further information available (0x0000)",
            "< ACL Data TX: Handle 256 flags 0x00 dlen 23"
            "        #3 [hci0] 3.000000",
            "      L2CAP: Configure Request (0x04) ident 1 len 15",
            "        Destination CID: 192",
            "        Flags: 0x0000",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 16"
            "        #4 [hci0] 4.000000",
            "      L2CAP: Configure Request (0x04) ident 2 len 8",
            "        Destination CID: 64",
            "        Flags: 0x0000",
            "        Option: Maximum Transmission Unit (0x01) [mandatory]",
            "          MTU: 48",
            "< ACL Data TX: Handle 256 flags 0x00 dlen 18"
            "        #5 [hci0] 5.000000",
            "      L2CAP: Configure Response (0x05) ident 2 len 10",
            "        Source CID: 192",
            "        Flags: 0x0000",
            "        Result: Success (0x0000)",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 14"
            "        #6 [hci0] 6.000000",
            "      L2CAP: Configure Response (0x05) ident 1 len 6",
            "        Source CID: 64",
            "        Flags: 0x0000",
            "        Result: Success (0x0000)",
        ]
        return "\n".join(lines)

    def test_annotator_tags_l2cap(self):
        """L2CAPAnnotator should tag L2CAP signaling packets."""
        text = self._make_trace_text()
        packets, diags, found = annotate_trace(
            text, "L2CAP channel issues")
        assert found
        tagged = [p for p in packets if "L2CAP" in p.tags]
        assert len(tagged) >= 4

    def test_annotator_no_errors_on_complete_handshake(self):
        """Complete handshake should produce no error diagnostics."""
        text = self._make_trace_text()
        packets, diags, found = annotate_trace(
            text, "L2CAP channel issues")
        errors = [d for d in diags if "ERROR" in str(d)]
        assert errors == []


# ---------------------------------------------------------------------------
# Test: Integration with A2DPAnnotator (PSM 25 tracking)
# ---------------------------------------------------------------------------

class TestA2DPTrackerIntegration:
    """Test that A2DPAnnotator uses L2CAP tracker for PSM 25."""

    def _make_a2dp_trace_with_missing_config(self):
        """Build trace text reproducing issue #8 pattern.

        PSM 25 channel with missing Configure Response.
        """
        lines = [
            "Bluetooth monitor ver 5.64",
            "= Note: Linux version 6.1.0 (x86_64)                        0.000000",
            # AVDTP signaling channel (PSM 25) - first channel, fully configured
            "< ACL Data TX: Handle 256 flags 0x00 dlen 12"
            "        #250 [hci0] 31.000000",
            "      L2CAP: Connection Request (0x02) ident 1 len 4",
            "        PSM: 25 (0x0019)",
            "        Source CID: 64",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 16"
            "        #251 [hci0] 31.100000",
            "      L2CAP: Connection Response (0x03) ident 1 len 8",
            "        Destination CID: 256",
            "        Source CID: 64",
            "        Result: Connection successful (0x0000)",
            "        Status: No further information available (0x0000)",
            "< ACL Data TX: Handle 256 flags 0x00 dlen 23"
            "        #252 [hci0] 31.200000",
            "      L2CAP: Configure Request (0x04) ident 1 len 15",
            "        Destination CID: 256",
            "        Flags: 0x0000",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 16"
            "        #253 [hci0] 31.300000",
            "      L2CAP: Configure Request (0x04) ident 2 len 8",
            "        Destination CID: 64",
            "        Flags: 0x0000",
            "< ACL Data TX: Handle 256 flags 0x00 dlen 18"
            "        #254 [hci0] 31.400000",
            "      L2CAP: Configure Response (0x05) ident 2 len 10",
            "        Source CID: 256",
            "        Flags: 0x0000",
            "        Result: Success (0x0000)",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 14"
            "        #255 [hci0] 31.500000",
            "      L2CAP: Configure Response (0x05) ident 1 len 6",
            "        Source CID: 64",
            "        Flags: 0x0000",
            "        Result: Success (0x0000)",
            # Some AVDTP signaling on the channel
            "> ACL Data RX: Handle 256 flags 0x02 dlen 14"
            "        #260 [hci0] 32.000000",
            "      Channel: 64 len 8 [PSM 25 mode Basic (0x00)] {chan 0}",
            "      AVDTP: Discover (0x01) Response Accept (0x02) type 0x00 label 0 nosp 0",
            "        ACP SEID: 11",
            "        Media Type: Audio (0x00)",
            "        SEP Type: SNK (0x01)",
            "        In use: No",
            # AVDTP transport channel (PSM 25) - MISSING CONFIG RESPONSE
            "< ACL Data TX: Handle 256 flags 0x00 dlen 12"
            "        #269 [hci0] 33.106000",
            "      L2CAP: Connection Request (0x02) ident 3 len 4",
            "        PSM: 25 (0x0019)",
            "        Source CID: 65",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 16"
            "        #272 [hci0] 33.117000",
            "      L2CAP: Connection Response (0x03) ident 3 len 8",
            "        Destination CID: 321",
            "        Source CID: 65",
            "        Result: Connection successful (0x0000)",
            "        Status: No further information available (0x0000)",
            "< ACL Data TX: Handle 256 flags 0x00 dlen 27"
            "        #273 [hci0] 33.118000",
            "      L2CAP: Configure Request (0x04) ident 4 len 19",
            "        Destination CID: 321",
            "        Flags: 0x0000",
            "        Option: Maximum Transmission Unit (0x01) [mandatory]",
            "          MTU: 1021",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 20"
            "        #274 [hci0] 33.119000",
            "      L2CAP: Configure Request (0x04) ident 6 len 12",
            "        Destination CID: 65",
            "        Flags: 0x0000",
            "        Option: Maximum Transmission Unit (0x01) [mandatory]",
            "          MTU: 895",
            "< ACL Data TX: Handle 256 flags 0x00 dlen 18"
            "        #275 [hci0] 33.120000",
            "      L2CAP: Configure Response (0x05) ident 6 len 10",
            "        Source CID: 321",
            "        Flags: 0x0000",
            "        Result: Success (0x0000)",
            # NO Configure Response ident 4 from remote!
            # AVDTP Abort after ~30s
            "> ACL Data RX: Handle 256 flags 0x02 dlen 9"
            "        #310 [hci0] 63.107000",
            "      Channel: 64 len 3 [PSM 25 mode Basic (0x00)] {chan 0}",
            "      AVDTP: Abort (0x0a) Command (0x00) type 0x00 label 1 nosp 0",
            "        ACP SEID: 11",
            # We disconnect the transport channel
            "< ACL Data TX: Handle 256 flags 0x00 dlen 12"
            "        #313 [hci0] 64.019000",
            "      L2CAP: Disconnection Request (0x06) ident 5 len 4",
            "        Destination CID: 321",
            "        Source CID: 65",
            "> ACL Data RX: Handle 256 flags 0x02 dlen 12"
            "        #317 [hci0] 64.038000",
            "      L2CAP: Disconnection Response (0x07) ident 5 len 4",
            "        Destination CID: 321",
            "        Source CID: 65",
        ]
        return "\n".join(lines)

    def test_a2dp_detects_missing_config_response(self):
        """A2DPAnnotator should report missing Config Response."""
        text = self._make_a2dp_trace_with_missing_config()
        packets, diags, found = annotate_trace(text, "Audio / A2DP")
        assert found
        diag_strs = [str(d) for d in diags]
        config_errors = [d for d in diag_strs
                         if "Configure Request" in d and "never" in d]
        assert len(config_errors) >= 1, \
            f"Expected missing config diag, got: {diag_strs}"

    def test_a2dp_detects_half_configured_disconnect(self):
        """A2DPAnnotator should report channel disconnected half-configured."""
        text = self._make_a2dp_trace_with_missing_config()
        packets, diags, found = annotate_trace(text, "Audio / A2DP")
        diag_strs = [str(d) for d in diags]
        half_config = [d for d in diag_strs
                       if "disconnected before fully configured" in d]
        assert len(half_config) >= 1, \
            f"Expected half-configured diag, got: {diag_strs}"

    def test_a2dp_tags_l2cap_psm25_packets(self):
        """A2DPAnnotator should tag PSM 25 L2CAP packets."""
        text = self._make_a2dp_trace_with_missing_config()
        packets, diags, found = annotate_trace(text, "Audio / A2DP")
        l2cap_pkts = [p for p in packets
                      if "L2CAP" in p.tags and "AVDTP" in p.tags]
        assert len(l2cap_pkts) >= 2


# ---------------------------------------------------------------------------
# Test: Ident reuse across signal types
# ---------------------------------------------------------------------------

class TestIdentReuse:
    """Test that idents shared between Connection/Configure don't clash."""

    def test_same_ident_conn_and_config(self):
        """Ident 1 for Connection and ident 1 for Configure should work."""
        tracker = L2CAPChannelTracker()
        # Connection with ident 1
        tracker.process(
            _conn_request("<", 25, 65, ident=1, frame=1, ts=1.0))
        tracker.process(
            _conn_response(">", 321, 65, ident=1, result="successful",
                           frame=2, ts=2.0))
        # Configure also with ident 1 (same number, different signal)
        tracker.process(
            _config_request("<", 321, ident=1, mtu=1021,
                            frame=3, ts=3.0))
        # Remote config with ident 2
        tracker.process(
            _config_request(">", 65, ident=2, mtu=895,
                            frame=4, ts=4.0))
        # Responses
        tracker.process(
            _config_response("<", 321, ident=2, frame=5, ts=5.0))
        tracker.process(
            _config_response(">", 65, ident=1, frame=6, ts=6.0))

        ch = tracker.get_channel_info(65)
        assert ch is not None
        assert ch["state"] == "open"
        diags = tracker.diagnostics()
        errors = [d for d in diags if "ERROR" in str(d)]
        assert errors == []
