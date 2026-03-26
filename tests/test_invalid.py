"""Tests for invalid and edge-case inputs."""

from annotate import annotate_trace, parse_packets, prefilter
from detect import detect


class TestParsePacketsInvalid:
    """parse_packets() should handle garbage gracefully."""

    def test_empty_string(self):
        packets = parse_packets("")
        assert packets == []

    def test_whitespace_only(self):
        packets = parse_packets("   \n  \n  ")
        assert packets == []

    def test_no_packet_headers(self):
        packets = parse_packets("just some random text\nwith no btmon data\n")
        assert packets == []

    def test_btmon_header_only(self):
        packets = parse_packets("Bluetooth monitor ver 5.86\n")
        assert packets == []

    def test_truncated_packet(self):
        """A single packet header with no body should still parse."""
        text = "> HCI Event: LE Meta Event (0x3e) plen 7  #1 [hci0] 1.000\n"
        packets = parse_packets(text)
        assert len(packets) == 1
        assert packets[0].direction == ">"

    def test_binary_garbage(self):
        """Binary data should not crash the parser."""
        text = "\x00\x01\x02\xff\xfe garbage\n"
        packets = parse_packets(text)
        # Should return empty or at most parse what it can
        assert isinstance(packets, list)


class TestAnnotateTraceInvalid:
    """annotate_trace() should handle edge cases."""

    def test_empty_text(self):
        packets, diags, found = annotate_trace("", "Audio / LE Audio")
        assert packets == []
        assert found is False

    def test_unknown_focus(self):
        text = "> HCI Event: LE Meta Event (0x3e) plen 7  #1 [hci0] 1.000\n"
        packets, diags, found = annotate_trace(text, "Nonexistent Focus Area")
        assert found is False

    def test_wrong_focus_no_tags(self):
        """A2DP trace with LE Audio annotator should produce no LE Audio tags."""
        a2dp_text = (
            "Bluetooth monitor ver 5.86\n"
            "> HCI Event: LE Meta Event (0x3e) plen 7  #1 [hci0] 1.000\n"
            "      LE Connection Complete (0x01)\n"
        )
        packets, diags, found = annotate_trace(a2dp_text, "Audio / LE Audio")
        assert found is True
        # No LE Audio-specific tags expected on a connection event
        le_tags = [p for p in packets
                   if any(t in p.tags for t in ["ASCS", "ASE_CP", "CIS"])]
        assert len(le_tags) == 0


class TestPrefilterInvalid:
    """prefilter() should handle edge cases."""

    def test_empty_text(self):
        output, diags = prefilter("", "Audio / LE Audio")
        assert isinstance(output, str)
        assert isinstance(diags, list)

    def test_no_tagged_packets(self):
        """Trace with no relevant packets should still return text."""
        text = (
            "Bluetooth monitor ver 5.86\n"
            "= Note: Linux version 6.1.0 (x86_64)  0.000000\n"
        )
        output, diags = prefilter(text, "Audio / LE Audio")
        assert isinstance(output, str)


class TestDetectInvalid:
    """detect() edge cases (complements test_detect.py)."""

    def test_single_matching_line(self):
        """A single AVDTP line should detect a2dp with score 1."""
        text = "      AVDTP: Discover\n"
        results = detect(text)
        names = [r.area.name for r in results]
        assert "a2dp" in names
        a2dp = next(r for r in results if r.area.name == "a2dp")
        assert a2dp.activity_count == 1
