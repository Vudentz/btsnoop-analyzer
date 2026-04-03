"""Tests for Channel Sounding (CS) annotator and detection.

Tests the ChannelSoundingAnnotator class covering:
- CS HCI command/event detection via declarative match_rules
- CS state machine tracking via hooks (config, procedure enable)
- Subevent result counting and abort detection
- RAS (Ranging Service) GATT characteristic detection
- Absence-check diagnostics
- State transition diagnostic output
- Integration with annotate_trace()
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from packet import Packet, Diagnostic  # noqa: E402
from annotate import (  # noqa: E402
    ChannelSoundingAnnotator, annotate_trace,
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


# ---------------------------------------------------------------------------
# Realistic CS packet builders
# ---------------------------------------------------------------------------

def _cs_read_local_caps_cmd(frame=100, ts=1.0):
    return _make_packet(
        "<",
        "HCI Command: LE CS Read Local Supported Capabilities "
        "(0x08|0x0089) plen 0",
        [], frame=frame, ts=ts)


def _cs_read_local_caps_complete(frame=101, ts=1.01):
    return _make_packet(
        ">",
        "HCI Event: Command Complete (0x0e) plen 42",
        ["      LE CS Read Local Supported Capabilities (0x08|0x0089) "
         "ncmd 1",
         "        Status: Success (0x00)",
         "        Num Config Supported: 4",
         "        Num Antennas Supported: 2",
         "        Max Antenna Paths Supported: 4",
         "        Roles Supported: 0x03",
         "          Initiator",
         "          Reflector",
         "        Modes Supported: 0x03"],
        frame=frame, ts=ts)


def _cs_read_remote_caps_cmd(frame=110, ts=2.0):
    return _make_packet(
        "<",
        "HCI Command: LE CS Read Remote Supported Capabilities "
        "(0x08|0x008a) plen 2",
        ["      Handle: 2048"],
        frame=frame, ts=ts)


def _cs_read_remote_caps_complete(frame=115, ts=2.5,
                                   status="Success"):
    status_line = f"        Status: {status} (0x00)" \
        if status == "Success" \
        else f"        Status: {status} (0x0c)"
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 42",
        ["      LE CS Read Remote Supported Capabilities Complete "
         "(0x2c)",
         status_line,
         "        Handle: 2048",
         "        Num Config Supported: 4",
         "        Roles Supported: 0x03"],
        frame=frame, ts=ts)


def _cs_security_enable_cmd(frame=120, ts=3.0):
    return _make_packet(
        "<",
        "HCI Command: LE CS Security Enable (0x08|0x008c) plen 2",
        ["      Handle: 2048"],
        frame=frame, ts=ts)


def _cs_security_enable_complete(frame=125, ts=3.5,
                                  status="Success"):
    status_str = f"Status: {status} (0x00)" \
        if status == "Success" \
        else f"Status: {status} (0x06)"
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 3",
        ["      LE CS Security Enable Complete (0x2e)",
         f"        {status_str}",
         "        Handle: 2048"],
        frame=frame, ts=ts)


def _cs_set_default_settings(frame=130, ts=4.0):
    return _make_packet(
        "<",
        "HCI Command: LE CS Set Default Settings "
        "(0x08|0x008d) plen 5",
        ["      Handle: 2048",
         "      Role Enable: 0x03",
         "        Initiator",
         "        Reflector",
         "      CS Sync Antenna Selection: 0x01",
         "      Max TX Power: 20"],
        frame=frame, ts=ts)


def _cs_create_config(config_id=0, frame=150, ts=5.0):
    return _make_packet(
        "<",
        "HCI Command: LE CS Create Config (0x08|0x0090) plen 20",
        ["      Handle: 2048",
         f"      Config ID: {config_id}",
         "      Create Context: 0x00",
         "      Main Mode Type: 0x01",
         "      Sub Mode Type: 0xff",
         "      Min Main Mode Steps: 2",
         "      Max Main Mode Steps: 5",
         "      Mode 0 Steps: 3",
         "      Role: Initiator (0x00)",
         "      RTT Type: 0x01",
         "      CS Sync PHY: LE 2M (0x01)"],
        frame=frame, ts=ts)


def _cs_config_complete(config_id=0, frame=155, ts=5.5,
                         status="Success"):
    status_str = f"Status: {status} (0x00)" \
        if status == "Success" \
        else f"Status: {status} (0x0c)"
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 30",
        ["      LE CS Config Complete (0x2f)",
         f"        {status_str}",
         "        Handle: 2048",
         f"        Config ID: {config_id}",
         "        Action: 0x00",
         "        Main Mode Type: 0x01",
         "        Sub Mode Type: 0xff",
         "        Role: Initiator (0x00)",
         "        RTT Type: 0x01",
         "        CS Sync PHY: LE 2M (0x01)",
         "        T_IP1 Time: 30 us",
         "        T_IP2 Time: 30 us",
         "        T_FCS Time: 50 us",
         "        T_PM Time: 10 us"],
        frame=frame, ts=ts)


def _cs_set_proc_params(config_id=0, frame=170, ts=6.0):
    return _make_packet(
        "<",
        "HCI Command: LE CS Set Procedure Parameters "
        "(0x08|0x0093) plen 16",
        ["      Handle: 2048",
         f"      Config ID: {config_id}",
         "      Max Procedure Len: 200",
         "      Min Procedure Interval: 10",
         "      Max Procedure Interval: 20",
         "      Max Procedure Count: 0"],
        frame=frame, ts=ts)


def _cs_procedure_enable(config_id=0, enable=True, frame=180, ts=7.0):
    enable_val = "0x01" if enable else "0x00"
    return _make_packet(
        "<",
        "HCI Command: LE CS Procedure Enable (0x08|0x0094) plen 4",
        ["      Handle: 2048",
         f"      Config ID: {config_id}",
         f"      Enable: {enable_val}"],
        frame=frame, ts=ts)


def _cs_procedure_enable_complete(config_id=0, state=1, frame=185,
                                    ts=7.5, status="Success",
                                    decimal_state=False):
    status_str = f"Status: {status} (0x00)" \
        if status == "Success" \
        else f"Status: {status} (0x0c)"
    state_val = str(state) if decimal_state else f"0x{state:02x}"
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 20",
        ["      LE CS Procedure Enable Complete (0x30)",
         f"        {status_str}",
         "        Handle: 2048",
         f"        Config ID: {config_id}",
         f"        State: {state_val}",
         "        Tone Antenna Config Selection: 0x01",
         "        Selected TX Power: 12",
         "        Subevent Len: 5000 us",
         "        Subevents Per Event: 2",
         "        Subevent Interval: 3750",
         "        Procedure Count: 100",
         "        Max Procedure Len: 200"],
        frame=frame, ts=ts)


def _cs_subevent_result(steps=8, proc_done="Partial results",
                         abort=0x00, frame=200, ts=8.0):
    proc_done_str = f"Procedure Done Status: {proc_done} (0x01)" \
        if "Partial" in proc_done \
        else f"Procedure Done Status: {proc_done} (0x00)"
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 50",
        ["      LE CS Subevent Result (0x31)",
         "        Handle: 2048",
         "        Config ID: 0",
         "        Start ACL Conn Event Counter: 1200",
         "        Procedure Counter: 0",
         "        Frequency Compensation: 0x0000",
         "        Reference Power Level: -20",
         f"        {proc_done_str}",
         "        Subevent Done Status: All results complete (0x00)",
         f"        Abort Reason: 0x{abort:02x}",
         "        Num Antenna Paths: 1",
         f"        Num Steps Reported: {steps}"],
        frame=frame, ts=ts)


def _cs_subevent_result_continue(steps=4, frame=202, ts=8.1):
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 40",
        ["      LE CS Subevent Result Continue (0x32)",
         "        Handle: 2048",
         "        Config ID: 0",
         "        Procedure Done Status: Partial results (0x01)",
         "        Subevent Done Status: All results complete (0x00)",
         "        Abort Reason: 0x00",
         "        Num Antenna Paths: 1",
         f"        Num Steps Reported: {steps}"],
        frame=frame, ts=ts)


def _cs_remove_config(config_id=0, frame=300, ts=15.0):
    return _make_packet(
        "<",
        "HCI Command: LE CS Remove Config (0x08|0x0091) plen 3",
        ["      Handle: 2048",
         f"      Config ID: {config_id}"],
        frame=frame, ts=ts)


def _cs_set_channel_classification(frame=145, ts=4.5):
    return _make_packet(
        "<",
        "HCI Command: LE CS Set Channel Classification "
        "(0x08|0x0092) plen 10",
        ["      Channel Map: ffffffffff7f0000000000"],
        frame=frame, ts=ts)


def _cs_test_cmd(frame=400, ts=20.0):
    return _make_packet(
        "<",
        "HCI Command: LE CS Test (0x08|0x0095) plen 34",
        ["      Main Mode Type: 0x01",
         "      Sub Mode Type: 0xff",
         "      Role: Initiator (0x00)"],
        frame=frame, ts=ts)


def _ras_service_discovery(frame=500, ts=25.0):
    return _make_packet(
        "<",
        "ACL Data TX: Handle 2048 flags 0x00 dlen 11",
        ["      ATT: Find By Type Value Request (0x06) len 8",
         "        UUID: Primary Service (0x2800)",
         "        Value: 0x185B"],
        frame=frame, ts=ts)


def _ras_features_read(frame=510, ts=25.5):
    return _make_packet(
        ">",
        "ACL Data RX: Handle 2048 flags 0x02 dlen 11",
        ["      ATT: Read Response (0x0b) len 4",
         "        Handle: 0x0003",
         "          Features: 0x0000000f",
         "          UUID: 0x2C14"],
        frame=frame, ts=ts)


def _ras_data_ready(counter=42, frame=520, ts=26.0):
    return _make_packet(
        ">",
        "ACL Data RX: Handle 2048 flags 0x02 dlen 9",
        ["      ATT: Handle Value Notification (0x1b) len 2",
         "        Handle: 0x000e",
         f"          Counter: {counter}",
         "          UUID: 0x2C18"],
        frame=frame, ts=ts)


def _ras_get_ranging_data(counter=42, frame=530, ts=26.5):
    return _make_packet(
        "<",
        "ACL Data TX: Handle 2048 flags 0x00 dlen 10",
        ["      ATT: Write Command (0x52) len 3",
         "        Handle: 0x000b",
         "          Opcode: Get Ranging Data (0x00)",
         f"          Ranging Counter: 0x{counter:04x}",
         "          UUID: 0x2C17"],
        frame=frame, ts=ts)


def _ras_ondemand_data(first=True, last=False, frame=540, ts=27.0):
    return _make_packet(
        ">",
        "ACL Data RX: Handle 2048 flags 0x02 dlen 30",
        ["      ATT: Handle Value Notification (0x1b) len 25",
         "        Handle: 0x0005",
         f"          First Segment: {first}",
         f"          Last Segment: {last}",
         "          Segment Index: 0",
         "          UUID: 0x2C16"],
        frame=frame, ts=ts)


def _ras_ack(counter=42, frame=550, ts=28.0):
    return _make_packet(
        "<",
        "ACL Data TX: Handle 2048 flags 0x00 dlen 10",
        ["      ATT: Write Command (0x52) len 3",
         "        Handle: 0x000b",
         "          Opcode: ACK Ranging Data (0x01)",
         f"          Ranging Counter: 0x{counter:04x}",
         "          UUID: 0x2C17"],
        frame=frame, ts=ts)


# ---------------------------------------------------------------------------
# Helper to build a full CS setup sequence
# ---------------------------------------------------------------------------

def _full_cs_setup(config_id=0):
    """Build a complete CS setup sequence up to procedure running."""
    return [
        _cs_read_local_caps_cmd(frame=100, ts=1.0),
        _cs_read_local_caps_complete(frame=101, ts=1.01),
        _cs_read_remote_caps_cmd(frame=110, ts=2.0),
        _cs_read_remote_caps_complete(frame=115, ts=2.5),
        _cs_security_enable_cmd(frame=120, ts=3.0),
        _cs_security_enable_complete(frame=125, ts=3.5),
        _cs_set_default_settings(frame=130, ts=4.0),
        _cs_create_config(config_id=config_id, frame=150, ts=5.0),
        _cs_config_complete(config_id=config_id, frame=155, ts=5.5),
        _cs_set_proc_params(config_id=config_id, frame=170, ts=6.0),
        _cs_procedure_enable(config_id=config_id, frame=180, ts=7.0),
        _cs_procedure_enable_complete(config_id=config_id, state=1,
                                      frame=185, ts=7.5),
    ]


# ===================================================================
# Tests: Declarative match_rules (simple command/event detection)
# ===================================================================

class TestCSMatchRules:
    """Tests for declarative match_rule detection."""

    def test_read_local_caps_tagged(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_read_local_caps_cmd()
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert pkt.annotation == "CS Read Local Capabilities"
        assert ann.saw_read_local_caps is True

    def test_read_local_caps_complete_extracts_info(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_read_local_caps_complete()
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert "Local Capabilities" in pkt.annotation

    def test_read_remote_caps_cmd(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_read_remote_caps_cmd()
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_read_remote_caps is True

    def test_security_enable_cmd(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_security_enable_cmd()
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_security_enable is True

    def test_security_enable_success(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_security_enable_complete()
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert "Success" in pkt.annotation
        assert ann.saw_security_complete is True

    def test_security_enable_failure(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_security_enable_complete(
            status="Pin or Key Missing")
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert "FAILED" in pkt.annotation

    def test_default_settings(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_set_default_settings()
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_default_settings is True
        assert "Default Settings" in pkt.annotation

    def test_create_config_cmd(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_create_config(config_id=2)
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_create_config is True
        assert "id=2" in pkt.annotation
        assert "mode=0x01" in pkt.annotation

    def test_set_proc_params(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_set_proc_params(config_id=1)
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_set_proc_params is True
        assert "id=1" in pkt.annotation

    def test_remove_config(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_remove_config(config_id=0)
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert "Remove Config" in pkt.annotation
        assert "id=0" in pkt.annotation

    def test_channel_classification(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_set_channel_classification()
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_channel_classification is True

    def test_cs_test_cmd(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_test_cmd()
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_cs_test is True
        assert "Test" in pkt.annotation


# ===================================================================
# Tests: Hook-based state tracking
# ===================================================================

class TestCSHooks:
    """Tests for hook-based CS event processing."""

    def test_config_complete_success(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_config_complete(config_id=0)
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_config_complete is True
        assert "Config Complete" in pkt.annotation
        assert "id=0" in pkt.annotation
        assert ann._cs_state[0] == "configured"

    def test_config_complete_failure(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_config_complete(config_id=0,
                                   status="Invalid Parameters")
        ann.annotate_packet(pkt)
        assert "FAILED" in pkt.annotation
        assert 0 not in ann._cs_state  # no state transition

    def test_procedure_enable_cmd(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_procedure_enable(config_id=0, enable=True)
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_procedure_enable is True
        assert "Procedure Enable" in pkt.annotation

    def test_procedure_disable_cmd(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_procedure_enable(config_id=0, enable=False)
        ann.annotate_packet(pkt)
        assert "Procedure Disable" in pkt.annotation

    def test_procedure_enable_complete_started(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_procedure_enable_complete(config_id=0, state=1)
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert ann.saw_procedure_enable_complete is True
        assert ann.procedure_count == 1
        assert "Procedure Started" in pkt.annotation
        assert ann._cs_state[0] == "running"

    def test_procedure_enable_complete_stopped(self):
        ann = ChannelSoundingAnnotator()
        # First start
        pkt1 = _cs_procedure_enable_complete(
            config_id=0, state=1, frame=185, ts=7.5)
        ann.annotate_packet(pkt1)
        # Then stop
        pkt2 = _cs_procedure_enable_complete(
            config_id=0, state=0, frame=305, ts=15.0)
        ann.annotate_packet(pkt2)
        assert "Procedure Stopped" in pkt2.annotation
        assert ann._cs_state[0] == "configured"
        assert ann.procedure_count == 1  # only counted starts

    def test_procedure_enable_complete_failure(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_procedure_enable_complete(
            config_id=0, state=0,
            status="Command Disallowed")
        ann.annotate_packet(pkt)
        assert "FAILED" in pkt.annotation
        assert ann.procedure_count == 0


# ===================================================================
# Tests: Subevent results
# ===================================================================

class TestCSSubeventResults:
    """Tests for subevent result counting and abort detection."""

    def test_subevent_result_counted(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_subevent_result(steps=8)
        ann.annotate_packet(pkt)
        assert ann.subevent_count == 1
        assert ann.saw_subevent_result is True
        assert "8 steps" in pkt.annotation

    def test_subevent_result_continue(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_subevent_result_continue(steps=4)
        ann.annotate_packet(pkt)
        assert ann.subevent_count == 1
        assert "Continue" in pkt.annotation
        assert "4 steps" in pkt.annotation

    def test_subevent_abort_detected(self):
        ann = ChannelSoundingAnnotator()
        # abort_reason 0x02 in low nibble = channel map too small
        pkt = _cs_subevent_result(steps=0, abort=0x02)
        ann.annotate_packet(pkt)
        assert ann.abort_count == 1
        assert "ABORT" in pkt.annotation
        assert "Channel map too small" in pkt.annotation

    def test_subevent_abort_high_nibble(self):
        ann = ChannelSoundingAnnotator()
        # abort_reason 0x20 = high nibble 0x02 = no CS_SYNC
        pkt = _cs_subevent_result(steps=0, abort=0x20)
        ann.annotate_packet(pkt)
        assert ann.abort_count == 1
        assert "No CS_SYNC" in pkt.annotation

    def test_subevent_both_abort_nibbles(self):
        ann = ChannelSoundingAnnotator()
        # both nibbles non-zero
        pkt = _cs_subevent_result(steps=0, abort=0x21)
        ann.annotate_packet(pkt)
        assert ann.abort_count == 1
        assert "proc=" in pkt.annotation
        assert "sub=" in pkt.annotation

    def test_subevent_no_abort(self):
        ann = ChannelSoundingAnnotator()
        pkt = _cs_subevent_result(steps=8, abort=0x00)
        ann.annotate_packet(pkt)
        assert ann.abort_count == 0
        assert "ABORT" not in pkt.annotation

    def test_many_subevents_context_priority(self):
        """After the first few, subevents become context priority."""
        ann = ChannelSoundingAnnotator()
        for i in range(10):
            pkt = _cs_subevent_result(
                steps=8, frame=200 + i, ts=8.0 + i * 0.1)
            ann.annotate_packet(pkt)
        assert ann.subevent_count == 10
        # First 3 should be key, rest context
        # (unless they have abort or procedure-done)

    def test_procedure_done_is_key(self):
        """Procedure Done = All results complete should be key frame."""
        ann = ChannelSoundingAnnotator()
        # Burn through 3 normal results
        for i in range(3):
            pkt = _cs_subevent_result(
                steps=8, frame=200 + i, ts=8.0 + i * 0.1)
            ann.annotate_packet(pkt)
        # 4th with procedure done should still be key
        pkt_done = _cs_subevent_result(
            steps=8, proc_done="All results complete",
            frame=210, ts=9.0)
        ann.annotate_packet(pkt_done)
        assert pkt_done.priority == "key"


# ===================================================================
# Tests: RAS (Ranging Service) GATT tracking
# ===================================================================

class TestCSRAS:
    """Tests for RAS GATT characteristic detection."""

    def test_ras_service_discovery(self):
        ann = ChannelSoundingAnnotator()
        pkt = _ras_service_discovery()
        ann.annotate_packet(pkt)
        assert "RAS" in pkt.tags
        assert "GATT" in pkt.tags
        assert ann.saw_ras_discovery is True
        assert "RAS Service discovered" in pkt.annotation

    def test_ras_features_read(self):
        ann = ChannelSoundingAnnotator()
        pkt = _ras_features_read()
        ann.annotate_packet(pkt)
        assert "RAS" in pkt.tags
        assert "Features" in pkt.annotation

    def test_ras_data_ready(self):
        ann = ChannelSoundingAnnotator()
        pkt = _ras_data_ready(counter=42)
        ann.annotate_packet(pkt)
        assert "RAS" in pkt.tags
        assert "Data Ready" in pkt.annotation

    def test_ras_control_point_get(self):
        ann = ChannelSoundingAnnotator()
        pkt = _ras_get_ranging_data(counter=42)
        ann.annotate_packet(pkt)
        assert "RAS" in pkt.tags
        assert "Control Point" in pkt.annotation
        assert "Get Ranging Data" in pkt.annotation

    def test_ras_ondemand_data_first(self):
        ann = ChannelSoundingAnnotator()
        pkt = _ras_ondemand_data(first=True, last=False)
        ann.annotate_packet(pkt)
        assert "RAS" in pkt.tags
        assert ann.ras_transfer_count == 1
        assert "first" in pkt.annotation
        assert "On-demand" in pkt.annotation

    def test_ras_ondemand_data_last(self):
        ann = ChannelSoundingAnnotator()
        pkt = _ras_ondemand_data(first=False, last=True)
        ann.annotate_packet(pkt)
        assert "RAS" in pkt.tags
        assert ann.ras_transfer_count == 0  # not first segment
        assert "last" in pkt.annotation

    def test_ras_ack(self):
        ann = ChannelSoundingAnnotator()
        pkt = _ras_ack(counter=42)
        ann.annotate_packet(pkt)
        assert "RAS" in pkt.tags
        assert "Control Point" in pkt.annotation
        assert "ACK" in pkt.annotation


# ===================================================================
# Tests: Diagnostics (finalize)
# ===================================================================

class TestCSDiagnostics:
    """Tests for CS diagnostic generation."""

    def test_state_machine_diagnostic(self):
        """Full CS flow produces state transition diagnostic."""
        ann = ChannelSoundingAnnotator()
        packets = _full_cs_setup(config_id=0)
        all_diags = ann.annotate(packets)
        diags = [d for d in all_diags
                 if "STATE:" in str(d)]
        assert len(diags) >= 1
        msg = str(diags[0])
        assert "Config ID 0" in msg
        assert "configured" in msg
        assert "running" in msg

    def test_absence_security_no_config(self):
        """Security enabled but no config created."""
        ann = ChannelSoundingAnnotator()
        packets = [
            _cs_security_enable_cmd(frame=120, ts=3.0),
            _cs_security_enable_complete(frame=125, ts=3.5),
        ]
        diags = ann.annotate(packets)
        absence = [d for d in diags if "ABSENCE:" in str(d)]
        assert any("Config" in str(d) for d in absence)

    def test_absence_config_no_enable(self):
        """Config created but procedure never enabled."""
        ann = ChannelSoundingAnnotator()
        packets = [
            _cs_create_config(frame=150, ts=5.0),
            _cs_config_complete(frame=155, ts=5.5),
            _cs_set_proc_params(frame=170, ts=6.0),
        ]
        diags = ann.annotate(packets)
        absence = [d for d in diags if "ABSENCE:" in str(d)]
        assert any("Procedure Enable" in str(d) for d in absence)

    def test_subevent_count_note(self):
        """Subevent count is reported as a NOTE."""
        ann = ChannelSoundingAnnotator()
        packets = _full_cs_setup()
        packets.extend([
            _cs_subevent_result(frame=200, ts=8.0),
            _cs_subevent_result(frame=201, ts=8.1),
            _cs_subevent_result(
                proc_done="All results complete", frame=202, ts=8.2),
        ])
        diags = ann.annotate(packets)
        notes = [d for d in diags if "NOTE:" in str(d)]
        assert any("3 CS subevent" in str(d) for d in notes)

    def test_abort_count_note(self):
        """Abort count is reported as a NOTE."""
        ann = ChannelSoundingAnnotator()
        packets = _full_cs_setup()
        packets.append(
            _cs_subevent_result(steps=0, abort=0x02,
                                frame=200, ts=8.0))
        diags = ann.annotate(packets)
        notes = [d for d in diags if "NOTE:" in str(d)]
        assert any("abort" in str(d).lower() for d in notes)

    def test_ras_transfer_note(self):
        """RAS transfer count is reported as a NOTE."""
        ann = ChannelSoundingAnnotator()
        packets = [
            _ras_ondemand_data(first=True, last=True,
                               frame=540, ts=27.0),
        ]
        diags = ann.annotate(packets)
        notes = [d for d in diags if "NOTE:" in str(d)]
        assert any("RAS" in str(d) and "transfer" in str(d)
                    for d in notes)

    def test_cs_test_note(self):
        """CS Test mode produces a NOTE."""
        ann = ChannelSoundingAnnotator()
        packets = [_cs_test_cmd()]
        diags = ann.annotate(packets)
        notes = [d for d in diags if "NOTE:" in str(d)]
        assert any("Test mode" in str(d) for d in notes)


# ===================================================================
# Tests: Full integration via annotate_trace
# ===================================================================

class TestCSIntegration:
    """Integration tests via annotate_trace()."""

    def _build_trace_text(self, packets):
        """Build a simple trace text from packets."""
        lines = []
        for pkt in packets:
            lines.append(pkt._raw_header)
            for b in pkt.body:
                lines.append(b)
            lines.append("")
        return "\n".join(lines)

    def test_annotate_trace_cs_focus(self):
        """annotate_trace with CS focus returns annotated packets."""
        pkts = _full_cs_setup()
        text = self._build_trace_text(pkts)
        packets, diags, found = annotate_trace(text, "Channel Sounding")
        assert found is True
        assert len(packets) > 0
        # Some packets should be tagged
        tagged = [p for p in packets if p.tags]
        assert len(tagged) > 0

    def test_annotate_trace_cs_alias(self):
        """'cs' alias normalizes to Channel Sounding."""
        from analyze import normalize_focus
        assert normalize_focus("cs") == "Channel Sounding"
        assert normalize_focus("channel sounding") == "Channel Sounding"
        assert normalize_focus("ranging") == "Channel Sounding"
        assert normalize_focus("ras") == "Channel Sounding"


# ===================================================================
# Tests: Detection patterns
# ===================================================================

class TestCSDetection:
    """Tests for CS detection pattern matching."""

    def test_cs_detected_in_trace(self):
        """Trace with CS commands should be detected as CS area."""
        from detect import detect
        text = (
            "< HCI Command: LE CS Read Local Supported Capabilities "
            "(0x08|0x0089) plen 0  #100 [hci0]\n"
            "> HCI Event: Command Complete (0x0e) plen 42  #101 [hci0]\n"
            "      LE CS Read Local Supported Capabilities\n"
            "        Status: Success (0x00)\n"
            "\n"
            "< HCI Command: LE CS Security Enable (0x08|0x008c) "
            "plen 2  #120 [hci0]\n"
            "      Handle: 2048\n"
            "\n"
            "< HCI Command: LE CS Create Config (0x08|0x0090) "
            "plen 20  #150 [hci0]\n"
        )
        results = detect(text)
        # Should have CS area scored
        cs_results = [r for r in results if r.area.name == "cs"]
        assert len(cs_results) == 1
        assert cs_results[0].activity_count >= 3


# ===================================================================
# Tests: Bug fixes (issue #6)
# ===================================================================

class TestCSBugFixes:
    """Tests for bug fixes discovered from real-world trace analysis."""

    def test_state_decimal_format(self):
        """Procedure Enable Complete with decimal State (e.g. 'State: 1')
        should be parsed correctly, not only hex '0x01'."""
        ann = ChannelSoundingAnnotator()
        pkt = _cs_procedure_enable_complete(
            config_id=0, state=1, decimal_state=True)
        ann.annotate_packet(pkt)
        assert ann.saw_procedure_enable_complete is True
        assert ann.procedure_count == 1
        assert "Procedure Started" in pkt.annotation
        assert ann._cs_state[0] == "running"

    def test_state_decimal_stopped(self):
        """Decimal State: 0 should be parsed as stopped."""
        ann = ChannelSoundingAnnotator()
        # Start first
        pkt1 = _cs_procedure_enable_complete(
            config_id=0, state=1, decimal_state=True,
            frame=185, ts=7.5)
        ann.annotate_packet(pkt1)
        # Then stop with decimal
        pkt2 = _cs_procedure_enable_complete(
            config_id=0, state=0, decimal_state=True,
            frame=305, ts=15.0)
        ann.annotate_packet(pkt2)
        assert "Procedure Stopped" in pkt2.annotation
        assert ann._cs_state[0] == "configured"

    def test_reflector_no_false_absence(self):
        """Reflector receives Config Complete without sending Create Config.
        Should NOT trigger 'no Config was ever created' absence."""
        ann = ChannelSoundingAnnotator()
        # Reflector flow: security enable, then Config Complete arrives
        # (without the reflector sending Create Config)
        packets = [
            _cs_security_enable_cmd(frame=120, ts=3.0),
            _cs_security_enable_complete(frame=125, ts=3.5),
            _cs_config_complete(config_id=0, frame=155, ts=5.5),
        ]
        diags = ann.annotate(packets)
        absence = [d for d in diags if "ABSENCE:" in str(d)]
        # Should NOT have "no Config was ever created"
        assert not any("Config was ever created" in str(d)
                       for d in absence), \
            f"False absence for reflector: {absence}"

    def test_connection_handle_lowercase(self):
        """btmon outputs 'Connection handle:' (lowercase h)."""
        ann = ChannelSoundingAnnotator()
        pkt = _make_packet(
            ">",
            "HCI Event: LE Meta Event (0x3e) plen 34",
            ["      LE CS Config Complete (0x2f)",
             "        Status: Success (0x00)",
             "        Connection handle: 3",
             "        Config ID: 0",
             "        Main Mode Type: 0x01",
             "        Role: Reflector (0x01)"],
            frame=2033, ts=243.647)
        ann.annotate_packet(pkt)
        assert "CS" in pkt.tags
        assert 3 in ann._cs_handles

    def test_connection_handle_uppercase(self):
        """Also handle 'Connection Handle:' (uppercase H)."""
        ann = ChannelSoundingAnnotator()
        pkt = _make_packet(
            ">",
            "HCI Event: LE Meta Event (0x3e) plen 34",
            ["      LE CS Config Complete (0x2f)",
             "        Status: Success (0x00)",
             "        Connection Handle: 42",
             "        Config ID: 0",
             "        Main Mode Type: 0x01"],
            frame=100, ts=1.0)
        ann.annotate_packet(pkt)
        assert 42 in ann._cs_handles


# ===================================================================
# Packet builders for GATT proximity heuristic tests
# ===================================================================

def _cs_config_complete_connhandle(conn_handle=3, config_id=0,
                                    frame=155, ts=5.5):
    """Config Complete with realistic 'Connection handle:' field."""
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 34",
        ["      LE CS Config Complete (0x2f)",
         "        Status: Success (0x00)",
         f"        Connection handle: {conn_handle}",
         f"        Config ID: {config_id}",
         "        Action: 1",
         "        Main Mode Type: 0x01",
         "        Role: Reflector (0x01)"],
        frame=frame, ts=ts)


def _cs_procedure_enable_complete_connhandle(conn_handle=3, config_id=0,
                                              state=1, frame=185,
                                              ts=7.5):
    """Procedure Enable Complete with decimal State and Connection handle."""
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 20",
        ["      LE CS Procedure Enable Complete (0x30)",
         "        Status: Success (0x00)",
         f"        Connection handle: {conn_handle}",
         f"        Config ID: {config_id}",
         f"        State: {state}",
         "        Tone Antenna Config Selection: 0x01",
         "        Selected TX Power: 12",
         "        Subevent Len: 5000 us",
         "        Subevents Per Event: 2",
         "        Procedure Count: 100"],
        frame=frame, ts=ts)


def _cs_subevent_result_connhandle(conn_handle=3, steps=8,
                                    frame=200, ts=8.0):
    """Subevent Result with Connection handle."""
    return _make_packet(
        ">",
        "HCI Event: LE Meta Event (0x3e) plen 50",
        ["      LE CS Subevent Result (0x31)",
         f"        Connection handle: {conn_handle}",
         "        Config ID: 0",
         "        Procedure Counter: 0",
         "        Procedure Done Status: Partial results (0x01)",
         "        Subevent Done Status: All results complete (0x00)",
         "        Abort Reason: 0x00",
         "        Num Antenna Paths: 1",
         f"        Num Steps Reported: {steps}"],
        frame=frame, ts=ts)


def _att_read_request(handle="0x007f", acl_handle=3,
                       frame=500, ts=25.0):
    """ATT Read Request on ACL connection (no UUIDs visible)."""
    return _make_packet(
        "<",
        f"ACL Data TX: Handle {acl_handle} flags 0x00 dlen 5",
        ["      ATT: Read Request (0x0a) len 2",
         f"        Handle: {handle}"],
        frame=frame, ts=ts)


def _att_read_response(value="01000000", acl_handle=3,
                        frame=501, ts=25.1):
    """ATT Read Response on ACL connection."""
    return _make_packet(
        ">",
        f"ACL Data RX: Handle {acl_handle} flags 0x02 dlen 9",
        ["      ATT: Read Response (0x0b) len 4",
         f"        Value: {value}"],
        frame=frame, ts=ts)


def _att_write_request(handle="0x0088", data="0200",
                        acl_handle=3, frame=510, ts=25.5):
    """ATT Write Request (e.g. CCCD enable)."""
    return _make_packet(
        "<",
        f"ACL Data TX: Handle {acl_handle} flags 0x00 dlen 7",
        ["      ATT: Write Request (0x12) len 4",
         f"        Handle: {handle}",
         f"        Data[2]: {data}"],
        frame=frame, ts=ts)


def _att_notification(handle="0x0081", acl_handle=3,
                       frame=520, ts=26.0):
    """ATT Handle Value Notification (e.g. RAS ranging data)."""
    return _make_packet(
        ">",
        f"ACL Data RX: Handle {acl_handle} flags 0x02 dlen 30",
        ["      ATT: Handle Value Notification (0x1b) len 25",
         f"        Handle: {handle}",
         "        Data: 0102030405060708090a0b0c0d0e0f"],
        frame=frame, ts=ts)


def _att_indication(handle="0x0081", acl_handle=3,
                     frame=521, ts=26.1):
    """ATT Handle Value Indication."""
    return _make_packet(
        ">",
        f"ACL Data RX: Handle {acl_handle} flags 0x02 dlen 30",
        ["      ATT: Handle Value Indication (0x1d) len 25",
         f"        Handle: {handle}",
         "        Data: 0102030405060708090a0b0c0d0e0f"],
        frame=frame, ts=ts)


def _att_find_information(acl_handle=3, frame=530, ts=24.0):
    """ATT Find Information Request (descriptor discovery)."""
    return _make_packet(
        "<",
        f"ACL Data TX: Handle {acl_handle} flags 0x00 dlen 9",
        ["      ATT: Find Information Request (0x04) len 4",
         "        Handle Range: 0x0001-0x00ff"],
        frame=frame, ts=ts)


def _att_error_response(handle="0x0090", acl_handle=3,
                         frame=535, ts=24.5):
    """ATT Error Response."""
    return _make_packet(
        ">",
        f"ACL Data RX: Handle {acl_handle} flags 0x02 dlen 9",
        ["      ATT: Error Response (0x01) len 4",
         f"        Handle: {handle}",
         "        Error: Attribute Not Found (0x0a)"],
        frame=frame, ts=ts)


def _unrelated_acl_packet(acl_handle=99, frame=600, ts=30.0):
    """ACL packet on a different connection (should NOT be tagged)."""
    return _make_packet(
        ">",
        f"ACL Data RX: Handle {acl_handle} flags 0x02 dlen 10",
        ["      ATT: Read Request (0x0a) len 2",
         "        Handle: 0x0010"],
        frame=frame, ts=ts)


# ===================================================================
# Tests: GATT proximity heuristic
# ===================================================================

class TestCSGATTProximityHeuristic:
    """Tests for the GATT proximity heuristic that infers ATT
    operations as RAS-related when they share the same ACL connection
    and occur near CS HCI events."""

    def _build_cs_sequence(self, conn_handle=3, base_ts=243.0):
        """Build a minimal CS HCI event sequence with connection handle."""
        return [
            _cs_config_complete_connhandle(
                conn_handle=conn_handle, frame=2033,
                ts=base_ts + 0.6),
            _cs_procedure_enable_complete_connhandle(
                conn_handle=conn_handle, state=1,
                frame=2038, ts=base_ts + 0.85),
            _cs_subevent_result_connhandle(
                conn_handle=conn_handle, steps=8,
                frame=2046, ts=base_ts + 1.0),
        ]

    def test_att_read_near_cs_tagged(self):
        """ATT Read Request on same ACL handle within window gets tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _att_read_request(
            handle="0x007f", acl_handle=3,
            frame=2005, ts=243.263)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert "CS" in att_pkt.tags
        assert "RAS" in att_pkt.tags
        assert "GATT" in att_pkt.tags
        assert "RAS GATT Read" in att_pkt.annotation

    def test_att_write_cccd_tagged(self):
        """ATT Write Request with CCCD enable data gets tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        # 0100 = enable notifications
        att_pkt = _att_write_request(
            handle="0x0082", data="0100", acl_handle=3,
            frame=2024, ts=243.498)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert "RAS" in att_pkt.tags
        assert "CCCD" in att_pkt.annotation

    def test_att_write_cccd_indications(self):
        """CCCD write with 0200 (enable indications) also tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _att_write_request(
            handle="0x0088", data="0200", acl_handle=3,
            frame=2021, ts=243.434)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert "CCCD" in att_pkt.annotation

    def test_att_notification_tagged(self):
        """ATT Handle Value Notification on same connection gets tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _att_notification(
            handle="0x0081", acl_handle=3,
            frame=2057, ts=244.071)
        packets = cs_pkts + [att_pkt]
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert "RAS" in att_pkt.tags
        assert "Ranging Data" in att_pkt.annotation
        assert "notification" in att_pkt.annotation

    def test_att_indication_tagged(self):
        """ATT Handle Value Indication on same connection gets tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _att_indication(
            handle="0x0081", acl_handle=3,
            frame=2060, ts=244.1)
        packets = cs_pkts + [att_pkt]
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert "RAS" in att_pkt.tags
        assert "indication" in att_pkt.annotation

    def test_different_acl_handle_not_tagged(self):
        """ATT packet on different ACL connection should NOT be tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _unrelated_acl_packet(
            acl_handle=99, frame=2010, ts=243.3)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert not att_pkt.tags

    def test_outside_time_window_not_tagged(self):
        """ATT packet outside time window should NOT be tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        # Way before CS events (more than 5s margin)
        att_pkt = _att_read_request(
            acl_handle=3, frame=100, ts=230.0)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert not att_pkt.tags

    def test_outside_after_window_not_tagged(self):
        """ATT packet after time window should NOT be tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        # Way after CS events (more than 2s margin)
        att_pkt = _att_read_request(
            acl_handle=3, frame=9000, ts=250.0)
        packets = cs_pkts + [att_pkt]
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert not att_pkt.tags

    def test_ras_transfer_count_incremented(self):
        """Notifications inferred as RAS data bump ras_transfer_count."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        notif1 = _att_notification(
            acl_handle=3, frame=2057, ts=244.071)
        notif2 = _att_notification(
            acl_handle=3, frame=2061, ts=244.081)
        packets = cs_pkts + [notif1, notif2]
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert ann.ras_transfer_count >= 2

    def test_gatt_count_diagnostic(self):
        """GATT heuristic summary diagnostic is emitted."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkts = [
            _att_read_request(acl_handle=3, frame=2005, ts=243.263),
            _att_write_request(
                handle="0x0082", data="0100", acl_handle=3,
                frame=2024, ts=243.498),
            _att_notification(acl_handle=3, frame=2057, ts=244.071),
        ]
        packets = att_pkts + cs_pkts
        ann = ChannelSoundingAnnotator()
        diags = ann.annotate(packets)
        gatt_diags = [d for d in diags
                      if "proximity heuristic" in str(d)]
        assert len(gatt_diags) == 1
        assert "3 GATT operation" in str(gatt_diags[0])

    def test_already_tagged_not_double_tagged(self):
        """Packets already tagged by UUID-based RAS detection should
        NOT be re-tagged by the heuristic."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        # This packet has visible UUID 0x185B (RAS Service)
        ras_pkt = _ras_service_discovery(frame=2010, ts=243.3)
        # Hack: set ACL handle to 3 in summary for potential match
        ras_pkt._raw_header = ras_pkt._raw_header.replace(
            "Handle 2048", "Handle 3")
        packets = [ras_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        # Should be tagged only once by UUID detection, not by heuristic
        assert ras_pkt.tags.count("RAS") == 1

    def test_context_priority_for_heuristic(self):
        """GATT-heuristic-tagged packets should have context priority."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _att_read_request(
            acl_handle=3, frame=2005, ts=243.263)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert att_pkt.priority == "context"

    def test_find_information_tagged(self):
        """ATT Find Information Request classified as descriptor discovery."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _att_find_information(acl_handle=3, frame=2001, ts=240.0)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert "RAS" in att_pkt.tags
        assert "descriptor discovery" in att_pkt.annotation

    def test_error_response_tagged(self):
        """ATT Error Response on same connection gets tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _att_error_response(
            handle="0x0090", acl_handle=3,
            frame=2002, ts=240.5)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert "RAS" in att_pkt.tags
        assert "Error Response" in att_pkt.annotation

    def test_read_response_tagged(self):
        """ATT Read Response gets tagged as RAS GATT Read Response."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _att_read_response(
            acl_handle=3, frame=2018, ts=243.359)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert "RAS" in att_pkt.tags
        assert "Read Response" in att_pkt.annotation

    def test_write_response_not_tagged(self):
        """ATT Write Response is skipped (not interesting on its own)."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        att_pkt = _make_packet(
            ">",
            "ACL Data RX: Handle 3 flags 0x02 dlen 5",
            ["      ATT: Write Response (0x13) len 0"],
            frame=2025, ts=243.5)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert not att_pkt.tags

    def test_non_att_acl_not_tagged(self):
        """ACL packet without ATT content should NOT be tagged."""
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        non_att_pkt = _make_packet(
            ">",
            "ACL Data RX: Handle 3 flags 0x02 dlen 20",
            ["      L2CAP: Connection Request (0x02) ident 1 len 4",
             "        PSM: 25 (0x0019)",
             "        Source CID: 64"],
            frame=2015, ts=243.35)
        packets = [non_att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert not non_att_pkt.tags

    def test_multiple_connections_isolated(self):
        """ATT on one connection isn't tagged due to CS on a different one."""
        # CS events on connection handle 3
        cs_pkts = self._build_cs_sequence(conn_handle=3, base_ts=243.0)
        # ATT on connection handle 5 — should NOT be tagged
        att_pkt = _att_read_request(
            acl_handle=5, frame=2005, ts=243.263)
        packets = [att_pkt] + cs_pkts
        ann = ChannelSoundingAnnotator()
        ann.annotate(packets)
        assert not att_pkt.tags


# ===================================================================
# Tests: _classify_att_operation unit tests
# ===================================================================

class TestClassifyATTOperation:
    """Unit tests for the _classify_att_operation helper."""

    def test_notification(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Handle Value Notification (0x1b) len 25\n"
                "        Handle: 0x0081\n"
                "        Data: 0102030405")
        result = ann._classify_att_operation(body)
        assert result is not None
        assert "Ranging Data" in result
        assert "notification" in result
        assert "0x0081" in result

    def test_indication(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Handle Value Indication (0x1d) len 25\n"
                "        Handle: 0x0081")
        result = ann._classify_att_operation(body)
        assert "indication" in result

    def test_write_cccd_notifications(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Write Request (0x12) len 4\n"
                "        Handle: 0x0082\n"
                "        Data[2]: 0100")
        result = ann._classify_att_operation(body)
        assert "CCCD" in result

    def test_write_cccd_indications(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Write Request (0x12) len 4\n"
                "        Handle: 0x0088\n"
                "        Data[2]: 0200")
        result = ann._classify_att_operation(body)
        assert "CCCD" in result

    def test_write_non_cccd(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Write Request (0x12) len 10\n"
                "        Handle: 0x0090\n"
                "        Data[8]: 0102030405060708")
        result = ann._classify_att_operation(body)
        assert result is not None
        assert "GATT Write" in result

    def test_write_response_skipped(self):
        ann = ChannelSoundingAnnotator()
        body = "      ATT: Write Response (0x13) len 0"
        result = ann._classify_att_operation(body)
        assert result is None

    def test_read_request(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Read Request (0x0a) len 2\n"
                "        Handle: 0x007f")
        result = ann._classify_att_operation(body)
        assert "GATT Read" in result
        assert "0x007f" in result

    def test_read_response(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Read Response (0x0b) len 4\n"
                "        Value: 01000000")
        result = ann._classify_att_operation(body)
        assert "Read Response" in result

    def test_read_by_type(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Read By Type Request (0x08) len 6\n"
                "        Handle Range: 0x0001-0x00ff\n"
                "        UUID: 0x2803")
        result = ann._classify_att_operation(body)
        assert "characteristic discovery" in result

    def test_read_by_group_type(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Read By Group Type Request (0x10) len 6\n"
                "        Handle Range: 0x0001-0xffff\n"
                "        UUID: Primary Service (0x2800)")
        result = ann._classify_att_operation(body)
        assert "service discovery" in result

    def test_find_information(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Find Information Request (0x04) len 4\n"
                "        Handle Range: 0x0001-0x00ff")
        result = ann._classify_att_operation(body)
        assert "descriptor discovery" in result

    def test_error_response(self):
        ann = ChannelSoundingAnnotator()
        body = ("      ATT: Error Response (0x01) len 4\n"
                "        Handle: 0x0090\n"
                "        Error: Attribute Not Found (0x0a)")
        result = ann._classify_att_operation(body)
        assert "Error Response" in result
        assert "0x0090" in result

    def test_unknown_att_returns_none(self):
        """Unknown ATT operation type returns None."""
        ann = ChannelSoundingAnnotator()
        body = "      ATT: Exchange MTU Request (0x02) len 2"
        result = ann._classify_att_operation(body)
        assert result is None
