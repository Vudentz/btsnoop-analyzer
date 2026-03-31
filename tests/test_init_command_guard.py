"""Tests that HCI init commands don't produce false-positive annotations.

HCI init commands like Set Event Mask and Read Local Supported Commands
have body text that lists protocol/event names (e.g. "Synchronous
Connection Complete", "Encryption Change", "Connection Complete").
These should NOT trigger HFP, SMP, Connections, or other annotator hooks.
"""

import sys

from packet import Packet
from annotate import (
    HFPAnnotator, SMPAnnotator, ConnectionsAnnotator,
    LEAudioAnnotator, AdvertisingAnnotator, DisconnectionAnnotator,
)


def _make_packet(direction, summary, body_lines, frame=0, ts=0.0):
    """Helper to construct a Packet with a raw header."""
    pkt = Packet(
        line_start=0, line_end=len(body_lines),
        direction=direction, summary=summary,
        frame=frame, timestamp=ts, body=body_lines,
    )
    pkt._raw_header = f"{direction} {summary}  #{frame} [hci0] {ts}"
    return pkt


# Realistic body text from "< Set Event Mask" — lists all enabled
# event names including ones that match HFP/SMP/Connections hooks.
SET_EVENT_MASK_BODY = [
    "        Mask: 0x3dbff807fffbffff",
    "          Inquiry Complete",
    "          Inquiry Result",
    "          Connection Complete",
    "          Connection Request",
    "          Disconnection Complete",
    "          Authentication Complete",
    "          Remote Name Request Complete",
    "          Encryption Change",
    "          Change Connection Link Key Complete",
    "          Read Remote Supported Features Complete",
    "          Read Remote Version Information Complete",
    "          QoS Setup Complete",
    "          Hardware Error",
    "          Role Change",
    "          Mode Change",
    "          PIN Code Request",
    "          Link Key Request",
    "          Link Key Notification",
    "          Data Buffer Overflow",
    "          Max Slots Change",
    "          Read Clock Offset Complete",
    "          Connection Packet Type Changed",
    "          Page Scan Repetition Mode Change",
    "          Flow Specification Complete",
    "          Inquiry Result with RSSI",
    "          Read Remote Extended Features Complete",
    "          Synchronous Connection Complete",
    "          Synchronous Connection Changed",
    "          Sniff Subrating",
    "          Extended Inquiry Result",
    "          Encryption Key Refresh Complete",
    "          IO Capability Request",
    "          IO Capability Response",
    "          User Confirmation Request",
    "          User Passkey Request",
    "          Remote OOB Data Request",
    "          Simple Pairing Complete",
    "          Link Supervision Timeout Changed",
    "          Enhanced Flush Complete",
    "          User Passkey Notification",
    "          LE Meta Event",
    "          Authenticated Payload Timeout Expired",
]


READ_LOCAL_SUPPORTED_COMMANDS_BODY = [
    "        Supported commands: 252",
    "          Inquiry",
    "          Create Connection",
    "          Disconnect",
    "          Read Remote Supported Features",
    "          Setup Synchronous Connection",
    "          Accept Synchronous Connection Request",
    "          LE Set Event Mask",
]


class TestSetEventMaskNotFalsePositive:
    """Set Event Mask must not produce false-positive annotations."""

    def _make_set_event_mask(self):
        return _make_packet(
            "<",
            "HCI Command: Set Event Mask (0x0c01) plen 8",
            SET_EVENT_MASK_BODY,
            frame=47, ts=1.234,
        )

    def test_hfp_no_annotation(self):
        """HFP annotator must not annotate Set Event Mask as SCO."""
        pkt = self._make_set_event_mask()
        ann = HFPAnnotator()
        ann.annotate_packet(pkt)
        assert not pkt.tags, f"HFP falsely tagged: {pkt.tags} {pkt.annotation}"

    def test_smp_no_annotation(self):
        """SMP annotator must not annotate Set Event Mask as Encryption."""
        pkt = self._make_set_event_mask()
        ann = SMPAnnotator()
        ann.annotate_packet(pkt)
        assert not pkt.tags, f"SMP falsely tagged: {pkt.tags} {pkt.annotation}"

    def test_connections_no_annotation(self):
        """Connections annotator must not annotate Set Event Mask."""
        pkt = self._make_set_event_mask()
        ann = ConnectionsAnnotator()
        ann.annotate_packet(pkt)
        assert not pkt.tags, \
            f"Connections falsely tagged: {pkt.tags} {pkt.annotation}"

    def test_le_audio_no_annotation(self):
        """LE Audio annotator must not annotate Set Event Mask."""
        pkt = self._make_set_event_mask()
        ann = LEAudioAnnotator()
        ann.annotate_packet(pkt)
        assert not pkt.tags, \
            f"LE Audio falsely tagged: {pkt.tags} {pkt.annotation}"

    def test_advertising_no_annotation(self):
        """Advertising annotator must not annotate Set Event Mask."""
        pkt = self._make_set_event_mask()
        ann = AdvertisingAnnotator()
        ann.annotate_packet(pkt)
        assert not pkt.tags, \
            f"Advertising falsely tagged: {pkt.tags} {pkt.annotation}"

    def test_disconnection_no_annotation(self):
        """Disconnection annotator must not annotate Set Event Mask."""
        pkt = self._make_set_event_mask()
        ann = DisconnectionAnnotator()
        ann.annotate_packet(pkt)
        assert not pkt.tags, \
            f"Disconnection falsely tagged: {pkt.tags} {pkt.annotation}"


class TestReadLocalSupportedCommandsNotFalsePositive:
    """Read Local Supported Commands must not produce false positives."""

    def _make_read_local(self):
        return _make_packet(
            ">",
            "HCI Event: Command Complete (0x0e) plen 68",
            READ_LOCAL_SUPPORTED_COMMANDS_BODY,
            frame=50, ts=1.500,
        )

    def test_hfp_no_annotation(self):
        pkt = self._make_read_local()
        # Inject "Read Local Supported Commands" into body so the
        # guard regex can find it (real btmon includes it in the
        # Command Complete body).
        pkt.body.insert(0, "    Read Local Supported Commands (0x1002)")
        ann = HFPAnnotator()
        ann.annotate_packet(pkt)
        assert not pkt.tags, f"HFP falsely tagged: {pkt.tags} {pkt.annotation}"

    def test_smp_no_annotation(self):
        pkt = self._make_read_local()
        pkt.body.insert(0, "    Read Local Supported Commands (0x1002)")
        ann = SMPAnnotator()
        ann.annotate_packet(pkt)
        assert not pkt.tags, f"SMP falsely tagged: {pkt.tags} {pkt.annotation}"


class TestRealEventsStillAnnotated:
    """Real protocol events should still be annotated (not blocked)."""

    def test_real_sco_complete_annotated(self):
        """A real Synchronous Connection Complete event should be tagged."""
        pkt = _make_packet(
            ">",
            "HCI Event: Synchronous Connection Complete (0x2c) plen 17",
            [
                "        Status: Success (0x00)",
                "        Handle: 257",
                "        Address: AA:BB:CC:DD:EE:FF (OUI AA-BB-CC)",
            ],
            frame=200, ts=10.0,
        )
        ann = HFPAnnotator()
        ann.annotate_packet(pkt)
        assert pkt.tags, "Real SCO Complete should be tagged"
        assert "SCO" in pkt.tags

    def test_real_encryption_change_annotated(self):
        """A real Encryption Change event should be tagged."""
        pkt = _make_packet(
            ">",
            "HCI Event: Encryption Change (0x08) plen 4",
            [
                "        Status: Success (0x00)",
                "        Handle: 256",
                "        Encryption: Enabled with E0 (0x01)",
            ],
            frame=210, ts=11.0,
        )
        ann = SMPAnnotator()
        ann.annotate_packet(pkt)
        assert pkt.tags, "Real Encryption Change should be tagged"
        assert "SMP" in pkt.tags

    def test_real_connection_complete_annotated(self):
        """A real Connection Complete event should be tagged."""
        pkt = _make_packet(
            ">",
            "HCI Event: Connection Complete (0x03) plen 11",
            [
                "        Status: Success (0x00)",
                "        Handle: 256",
                "        Address: AA:BB:CC:DD:EE:FF (OUI AA-BB-CC)",
                "        Link type: ACL (0x01)",
                "        Encryption: Disabled (0x00)",
                "        Role: Central",
            ],
            frame=220, ts=12.0,
        )
        ann = ConnectionsAnnotator()
        ann.annotate_packet(pkt)
        assert pkt.tags, "Real Connection Complete should be tagged"
        assert "HCI" in pkt.tags
