"""Tests for btmon --analyze output parser.

Tests the parse_btmon_analyze() function which extracts structured
statistics from btmon --analyze text output.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from btmon_stats import (
    parse_btmon_analyze, BtmonAnalysis, ControllerStats,
    ConnectionStats, ChannelStats,
)


# ---------------------------------------------------------------------------
# Sample btmon --analyze output (representative of real traces)
# ---------------------------------------------------------------------------

SAMPLE_OUTPUT = """\
Bluetooth monitor ver 5.86
Trace contains 87632 packets

Found BR/EDR controller with index 65535
  BD_ADDR 00:00:00:00:00:00
  0 commands
  0 events
  0 ACL packets
  0 SCO packets
  0 ISO packets
  0 vendor diagnostics
  2 system notes
  0 user logs
  2 control messages
  0 unknown opcodes

Found BR/EDR controller with index 0
  BD_ADDR 80:13:16:55:F7:F2 (Intel Corp.)
  14 commands
  29228 events
  58296 ACL packets
  0 SCO packets
  0 ISO packets
  0 vendor diagnostics
  0 system notes
  0 user logs
  87 control messages
  0 unknown opcodes
  Found LE-ACL connection with handle 2048
        Address: 80:13:16:55:F7:8E (Intel Corporate)
        RX packets: 29140/29140
        RX Latency: 0-11881 msec (~24 msec)
        RX size: 5-48 octets (~12 octets)
        RX speed: ~59 Kb/s (min ~69 Kb/s max ~90 Kb/s)
        TX packets: 29156/29150
        TX Latency: 1-79 msec (~29 msec)
        TX size: 5-494 octets (~493 octets)
        TX speed: ~2444 Kb/s (min ~2920 Kb/s max ~3706 Kb/s)
        Connected: #76
        Disconnected: #87537
        Disconnect Reason: 0x22
  Found TX L2CAP channel with CID 4 (ATT)
        TX packets: 35/35
        TX Latency: 1-45 msec (~45 msec)
        TX size: 5-55 octets (~11 octets)
        TX speed: ~2 Kb/s (min ~1 Kb/s max ~2 Kb/s)
  Found RX L2CAP channel with CID 4 (ATT)
        RX packets: 35/35
        RX Latency: 0-90 msec (~78 msec)
        RX size: 5-48 octets (~12 octets)
        RX speed: ~2 Kb/s (min ~1 Kb/s max ~2 Kb/s)
  Found TX L2CAP channel with CID 5 (L2CAP Signaling (LE))
        TX packets: 1/1
        TX Latency: 41-41 msec (~41 msec)
        TX size: 18-18 octets (~18 octets)
  Found TX L2CAP channel with CID 64
        PSM 128 (0x0080)
        Mode: LE Credit
        MTU: 488
        MPS: 488
        TX packets: 29120/29114
        TX Latency: 1-79 msec (~29 msec)
        TX size: 494-494 octets (~494 octets)
        TX speed: ~3414 Kb/s (min ~2853 Kb/s max ~3714 Kb/s)
  Found RX L2CAP channel with CID 5 (L2CAP Signaling (LE))
        RX packets: 29105/29105
        RX Latency: 0-50 msec (~24 msec)
        RX size: 12-18 octets (~12 octets)
        RX speed: ~82 Kb/s (min ~69 Kb/s max ~90 Kb/s)
"""

# Output with gnuplot charts prepended (simulated)
SAMPLE_WITH_CHARTS = """\
 100000 +-+---+
        +| + |
   10000 +-| |
        ++----+
        0   10

""" + SAMPLE_OUTPUT


class TestParseBasic:
    """Basic parsing of btmon --analyze output."""

    def test_version(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        assert result.version == "5.86"

    def test_total_packets(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        assert result.total_packets == 87632

    def test_controller_count(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        assert len(result.controllers) == 2

    def test_dummy_controller(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        ctrl = result.controllers[0]
        assert ctrl.index == 65535
        assert ctrl.bd_addr == "00:00:00:00:00:00"
        assert ctrl.commands == 0

    def test_real_controller(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        ctrl = result.controllers[1]
        assert ctrl.index == 0
        assert ctrl.bd_addr == "80:13:16:55:F7:F2"
        assert ctrl.commands == 14
        assert ctrl.events == 29228
        assert ctrl.acl_packets == 58296
        assert ctrl.sco_packets == 0
        assert ctrl.iso_packets == 0


class TestParseConnection:
    """Connection-level stat parsing."""

    def test_connection_found(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        ctrl = result.controllers[1]
        assert len(ctrl.connections) == 1
        conn = ctrl.connections[0]
        assert conn.conn_type == "LE-ACL"
        assert conn.handle == 2048

    def test_connection_address(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        assert conn.address == "80:13:16:55:F7:8E"
        assert conn.address_name == "Intel Corporate"

    def test_connection_rx_stats(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        assert conn.rx_packets_sent == 29140
        assert conn.rx_packets_complete == 29140
        assert conn.rx_speed_avg == 59
        assert conn.rx_speed_min == 69
        assert conn.rx_speed_max == 90

    def test_connection_tx_stats(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        assert conn.tx_packets_sent == 29156
        assert conn.tx_packets_complete == 29150
        assert conn.tx_speed_avg == 2444
        assert conn.tx_speed_min == 2920
        assert conn.tx_speed_max == 3706

    def test_connection_latency(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        assert conn.rx_latency_min == 0
        assert conn.rx_latency_max == 11881
        assert conn.rx_latency_avg == 24
        assert conn.tx_latency_min == 1
        assert conn.tx_latency_max == 79
        assert conn.tx_latency_avg == 29

    def test_connection_size(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        assert conn.tx_size_min == 5
        assert conn.tx_size_max == 494
        assert conn.tx_size_avg == 493

    def test_connect_disconnect_frames(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        assert conn.connected_frame == 76
        assert conn.disconnected_frame == 87537
        assert conn.disconnect_reason == "0x22"


class TestParseChannels:
    """L2CAP channel stat parsing."""

    def test_channel_count(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        assert len(conn.channels) == 5

    def test_att_tx_channel(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        chan = conn.channels[0]
        assert chan.direction == "TX"
        assert chan.cid == 4
        assert chan.cid_name == "ATT"
        assert chan.packets_sent == 35
        assert chan.packets_complete == 35
        assert chan.speed_avg == 2

    def test_att_rx_channel(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        chan = conn.channels[1]
        assert chan.direction == "RX"
        assert chan.cid == 4
        assert chan.cid_name == "ATT"

    def test_signaling_channel_no_speed(self):
        """CID 5 with 1 packet has no speed stats."""
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        chan = conn.channels[2]  # TX CID 5
        assert chan.direction == "TX"
        assert chan.cid == 5
        assert chan.packets_sent == 1
        assert chan.speed_avg is None

    def test_data_channel_with_psm(self):
        """CID 64 with PSM, Mode, MTU, MPS."""
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        chan = conn.channels[3]
        assert chan.direction == "TX"
        assert chan.cid == 64
        assert chan.psm == 128
        assert chan.psm_hex == "0x0080"
        assert chan.mode == "LE Credit"
        assert chan.mtu == 488
        assert chan.mps == 488
        assert chan.packets_sent == 29120
        assert chan.packets_complete == 29114
        assert chan.speed_avg == 3414
        assert chan.speed_min == 2853
        assert chan.speed_max == 3714

    def test_data_channel_latency(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        chan = conn.channels[3]  # TX CID 64
        assert chan.latency_min == 1
        assert chan.latency_max == 79
        assert chan.latency_avg == 29

    def test_data_channel_size(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        conn = result.controllers[1].connections[0]
        chan = conn.channels[3]  # TX CID 64
        assert chan.size_min == 494
        assert chan.size_max == 494
        assert chan.size_avg == 494


class TestAllHelpers:
    """Test all_channels() and all_connections() helpers."""

    def test_all_channels_count(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        channels = list(result.all_channels())
        assert len(channels) == 5

    def test_all_connections_count(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        connections = list(result.all_connections())
        assert len(connections) == 1


class TestChartSkipping:
    """Parser skips gnuplot chart output before the text summary."""

    def test_parses_with_charts(self):
        result = parse_btmon_analyze(SAMPLE_WITH_CHARTS)
        assert result.version == "5.86"
        assert result.total_packets == 87632
        assert len(result.controllers) == 2


class TestFormatSummary:
    """Test format_summary() output."""

    def test_summary_contains_key_info(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        summary = result.format_summary()
        assert "87632 packets" in summary
        assert "Controller index 0" in summary
        assert "LE-ACL handle 2048" in summary
        assert "CID 64" in summary
        assert "PSM 128" in summary
        assert "LE Credit" in summary
        assert "~3414 Kb/s" in summary

    def test_summary_skips_dummy_controller(self):
        result = parse_btmon_analyze(SAMPLE_OUTPUT)
        summary = result.format_summary()
        assert "index 65535" not in summary


class TestEmptyInput:
    """Edge cases."""

    def test_empty_string(self):
        result = parse_btmon_analyze("")
        assert result.total_packets == 0
        assert result.controllers == []

    def test_no_header(self):
        result = parse_btmon_analyze("some random text\nnothing useful\n")
        assert result.version is None
        assert result.controllers == []

    def test_header_only(self):
        text = "Bluetooth monitor ver 5.86\nTrace contains 0 packets\n"
        result = parse_btmon_analyze(text)
        assert result.version == "5.86"
        assert result.total_packets == 0
