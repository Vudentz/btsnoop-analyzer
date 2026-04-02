"""Tests for diagnose.py - diagnostics markdown formatting."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from packet import Diagnostic, Packet  # noqa: E402
from diagnose import format_diagnostics_markdown  # noqa: E402


def _make_pkt(frame=1, ts=1.0, annotation=None, tags=None, summary=""):
    """Helper to create a minimal Packet for testing."""
    p = Packet(direction=">", summary=summary, body=[],
               line_start=0, line_end=0, frame=frame, timestamp=ts)
    p._raw_header = f"> {summary}"
    p.annotation = annotation or ""
    p.tags = tags or []
    return p


class TestDiagnosticsTable:
    """Tests that the diagnostics table renders correctly."""

    def test_no_diagnostics(self):
        md = format_diagnostics_markdown([], [])
        assert "No diagnostics generated." in md

    def test_simple_diagnostic_in_table(self):
        d = Diagnostic("ERROR: something went wrong", frame=10,
                        timestamp=5.123, tags=["L2CAP"])
        md = format_diagnostics_markdown([], [d])
        assert "| #10 | 5.123s | `L2CAP` | ERROR: something went wrong |" in md

    def test_absence_diagnostic_has_warning_emoji(self):
        d = Diagnostic("ABSENCE: Start never sent")
        md = format_diagnostics_markdown([], [d])
        assert ":warning: ABSENCE: Start never sent" in md

    def test_info_diagnostic_has_info_emoji(self):
        d = Diagnostic("INFO: connection established")
        md = format_diagnostics_markdown([], [d])
        assert ":information_source: INFO: connection established" in md

    def test_note_diagnostic_has_info_emoji(self):
        d = Diagnostic("NOTE: something noteworthy")
        md = format_diagnostics_markdown([], [d])
        assert ":information_source: NOTE: something noteworthy" in md

    def test_graceful_disconnect_shown(self):
        pkt = _make_pkt(frame=42, ts=10.5, annotation="Graceful disconnect",
                        tags=["HCI"])
        md = format_diagnostics_markdown([pkt], [])
        assert "| #42 | 10.500s | `HCI` | Graceful disconnect |" in md

    def test_diagnostic_no_frame_no_ts_no_tags(self):
        d = Diagnostic("ERROR: orphan error")
        md = format_diagnostics_markdown([], [d])
        assert "| - | - | - | ERROR: orphan error |" in md


class TestMultiLineDiagnostic:
    """Tests that multi-line diagnostics stay inside the table cell."""

    def test_multiline_stays_in_table(self):
        """Multi-line diagnostic must NOT break the table with code blocks."""
        msg = ("STATE: SEID 1 AVDTP state transitions:\n"
               "        33.075s          idle -> configured\n"
               "        33.106s    configured -> open")
        d = Diagnostic(msg, frame=265, timestamp=33.075, tags=["AVDTP"])
        md = format_diagnostics_markdown([], [d])
        # Must NOT contain fenced code blocks that break the table
        assert "```" not in md
        # The table must have exactly one header + separator + one data row
        lines = [l for l in md.split("\n") if l.startswith("|")]
        assert len(lines) == 3  # header, separator, data row

    def test_multiline_uses_br_separators(self):
        msg = ("STATE: transitions:\n"
               "    1.0s idle -> open\n"
               "    2.0s open -> close")
        d = Diagnostic(msg, frame=1, timestamp=1.0, tags=["AVDTP"])
        md = format_diagnostics_markdown([], [d])
        assert "<br>" in md

    def test_multiline_uses_inline_code_spans(self):
        msg = ("STATE: transitions:\n"
               "    1.0s idle -> open\n"
               "    2.0s open -> close")
        d = Diagnostic(msg, frame=1, timestamp=1.0, tags=["AVDTP"])
        md = format_diagnostics_markdown([], [d])
        # Continuation lines should be wrapped in backticks
        assert "`1.0s idle -> open`" in md
        assert "`2.0s open -> close`" in md

    def test_multiline_dedents_common_whitespace(self):
        msg = ("STATE: test:\n"
               "        line1\n"
               "        line2")
        d = Diagnostic(msg)
        md = format_diagnostics_markdown([], [d])
        # 8 spaces of common indent should be stripped
        assert "`line1`" in md
        assert "`line2`" in md

    def test_multiline_preserves_relative_indent(self):
        msg = ("STATE: test:\n"
               "    short\n"
               "        long indent")
        d = Diagnostic(msg)
        md = format_diagnostics_markdown([], [d])
        # min indent is 4, so "short" has 0 relative,
        # "long indent" has 4 relative spaces
        assert "`short`" in md
        assert "`    long indent`" in md

    def test_multiline_skips_empty_lines(self):
        msg = ("STATE: test:\n"
               "\n"
               "    data line")
        d = Diagnostic(msg)
        md = format_diagnostics_markdown([], [d])
        # Empty lines should be skipped, not rendered as empty code spans
        assert "``" not in md
        assert "`data line`" in md

    def test_multiline_followed_by_regular_diag(self):
        """A multi-line diagnostic followed by a regular one must both
        render as table rows without the table breaking."""
        multi = Diagnostic(
            "STATE: transitions:\n    1.0s idle -> open",
            frame=10, timestamp=1.0, tags=["AVDTP"])
        regular = Diagnostic(
            "ERROR: something failed",
            frame=20, timestamp=2.0, tags=["L2CAP"])
        md = format_diagnostics_markdown([], [multi, regular])
        lines = [l for l in md.split("\n") if l.startswith("|")]
        # header + separator + 2 data rows
        assert len(lines) == 4
        # Both should be proper table rows
        assert any("STATE: transitions:" in l for l in lines)
        assert any("ERROR: something failed" in l for l in lines)

    def test_multiline_all_blank_continuation(self):
        """If continuation lines are all blank, just use first line."""
        msg = "STATE: empty:\n\n\n"
        d = Diagnostic(msg)
        md = format_diagnostics_markdown([], [d])
        assert "STATE: empty:" in md
        # Should not have <br> since there's no real content
        table_rows = [l for l in md.split("\n")
                      if l.startswith("|") and "STATE:" in l]
        assert len(table_rows) == 1
