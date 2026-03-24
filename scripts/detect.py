#!/usr/bin/env python3
"""
detect.py - Auto-detect problem areas and clip btmon logs.

Scans decoded btmon output for protocol-specific patterns derived from
the btmon documentation's "Automating Analysis" sections.  Each area
defines activity patterns (protocol is present) and error patterns
(something went wrong).  Areas are scored and ranked so the analyzer
can focus on the most relevant portions of a large trace.

The clip() function extracts log sections around matched lines using
btmon packet boundaries, producing a compact excerpt that an LLM can
analyze without hitting context limits.

Usage as a module:
    from detect import detect, clip

Usage standalone (for debugging):
    python3 scripts/detect.py < decoded_trace.txt
"""

import re
import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# btmon packet boundary detection
# ---------------------------------------------------------------------------

# btmon output lines that start a new packet/event.  These begin with
# a direction indicator or special marker:
#   < HCI Command:       (host -> controller)
#   > HCI Event:         (controller -> host)
#   @ Device Connected   (monitor meta-events)
#   = Note:              (btmon internal)
# Or a timestamp line like:
#   2024-01-15 10:30:45.123456
PACKET_START_RE = re.compile(
    r'^(?:[<>=@]|'                    # direction/meta markers
    r'\d{4}-\d{2}-\d{2}\s+\d{2}:)',  # timestamp prefix
)


def is_packet_start(line):
    """Return True if line marks the beginning of a btmon packet."""
    return bool(PACKET_START_RE.match(line))


# ---------------------------------------------------------------------------
# Area definitions: patterns derived from btmon doc automation sections
# ---------------------------------------------------------------------------

@dataclass
class AbsenceCheck:
    """Detect errors when an expected pattern is absent.

    If ``prerequisite`` matches at least one line but ``expected`` matches
    none, this counts as an error with the given ``message``.  This
    catches protocol-flow breaks like "PA sync established but BIG Info
    never received."
    """
    prerequisite: str   # regex -- must be present
    expected: str       # regex -- should follow; absence = error
    message: str        # human-readable diagnostic


@dataclass
class AreaDef:
    """Definition of a detectable protocol area."""
    name: str
    # Focus area string matching FOCUS_DOCS key in analyze.py
    focus: str
    # Patterns that indicate this protocol is present in the trace
    activity: list = field(default_factory=list)
    # Patterns that indicate an error or failure in this area
    errors: list = field(default_factory=list)
    # Absence-based error checks (prerequisite present + expected absent)
    absence_checks: list = field(default_factory=list)


AREAS = [
    AreaDef(
        name="a2dp",
        focus="Audio / A2DP",
        activity=[
            r"AVDTP:",
            r"Media Codec:",
            r"PSM: 25",
        ],
        errors=[
            r"Response Reject",
            r"Error code:",
            r"AVDTP:.*Abort",
        ],
    ),
    AreaDef(
        name="hfp",
        focus="Audio / HFP",
        activity=[
            r"RFCOMM:",
            r"PSM: 3\b",
            r"Setup Synchronous",
            r"Enhanced Setup Synchronous",
            r"Synchronous Connection Complete",
        ],
        errors=[
            r"Synchronous Connection Complete.*Status:(?!.*Success)",
            r"Connection Rejected",
            r"SCO Offset Rejected",
            r"SCO Interval Rejected",
        ],
    ),
    AreaDef(
        name="le_audio",
        focus="Audio / LE Audio",
        activity=[
            # Unicast (CIS) patterns
            r"ASE Control Point",
            r"ASE ID:",
            r"Set CIG Parameters",
            r"Create CIS",
            r"CIS Established",
            r"Setup ISO Data Path",
            # Broadcast (BIG) patterns
            r"Basic Audio Announcement",
            r"Create BIG",
            r"BIG Complete",
            r"BIG Create Sync",
            r"BIG Sync Established",
            r"BIG Info Advertising Report",
            # BASS / PA patterns (broadcast receiver flow)
            r"Add Source",
            r"Periodic Advertising Create Sync",
            r"Periodic Advertising Sync Established",
            r"Periodic Advertising Sync Transfer Received",
            r"Periodic Advertising Sync Transfer Parameters",
            r"Periodic Advertising Report",
        ],
        errors=[
            r"CIS Established.*Status:(?!.*Success)",
            r"BIG Sync Established.*Status:(?!.*Success)",
            r"BIG Sync Lost",
            r"BIG Terminate",
            r"State:.*Releasing",
        ],
        absence_checks=[
            AbsenceCheck(
                prerequisite=r"Periodic Advertising Sync (?:Established|Transfer Received)",
                expected=r"BIG Info Advertising Report",
                message="PA synced but BIG Info never received -- "
                        "BIG does not exist on this PA train",
            ),
            AbsenceCheck(
                prerequisite=r"BIG Info Advertising Report",
                expected=r"BIG Create Sync",
                message="BIG Info received but host never sent "
                        "BIG Create Sync",
            ),
            AbsenceCheck(
                prerequisite=r"BIG Create Sync",
                expected=r"BIG Sync Established",
                message="BIG Create Sync sent but BIG Sync never "
                        "established",
            ),
        ],
    ),
    AreaDef(
        name="connections",
        focus="Connection issues",
        activity=[
            r"Connection Complete",
            r"LE Connection Complete",
            r"Enhanced LE Connection Complete",
            r"Disconnect",
        ],
        errors=[
            r"Connection Complete.*Status:(?!.*Success)",
            r"LE Connection Complete.*Status:(?!.*Success)",
            r"Disconnect.*Reason:",
            r"Connection Timeout",
            r"Connection Failed",
        ],
    ),
    AreaDef(
        name="smp",
        focus="Pairing / Security",
        activity=[
            r"Pairing Request",
            r"Pairing Response",
            r"Pairing Public Key",
            r"DHKey Check",
            r"Encryption Change",
        ],
        errors=[
            r"Pairing Failed",
            r"Encryption Change.*Status:(?!.*Success)",
        ],
    ),
    AreaDef(
        name="l2cap",
        focus="L2CAP channel issues",
        activity=[
            r"L2CAP:.*Connection Request",
            r"L2CAP:.*Connection Response",
            r"LE Connection Request",
            r"LE Connection Response",
            r"PSM:",
        ],
        errors=[
            r"Connection Response.*Result:(?!.*Success)",
            r"Parameters rejected",
            r"Command Reject",
        ],
    ),
    AreaDef(
        name="advertising",
        focus="Advertising / Scanning",
        activity=[
            r"Advertising Report",
            r"Set Extended Adv",
            r"Set Advertising",
            r"Adv Enable",
            r"Periodic Advertising",
        ],
        errors=[
            # Advertising rarely has explicit errors; scan timeout is
            # the main failure mode but isn't logged as an error.
        ],
    ),
    AreaDef(
        name="hci_init",
        focus="Controller enumeration",
        activity=[
            r"Read Local Version",
            r"Read BD ADDR",
            r"Read Buffer Size",
            r"Set Event Mask",
            r"Read Local Supported",
            r"LE Set Event Mask",
            r"LE Read Buffer Size",
        ],
        errors=[
            r"Command Status.*Status:(?!.*Success)",
            r"Command Complete.*Status:(?!.*Success)",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@dataclass
class DetectedArea:
    """Result of detecting a protocol area in a trace."""
    area: AreaDef
    activity_count: int = 0
    error_count: int = 0
    # Line numbers (0-based) where errors were found
    error_lines: list = field(default_factory=list)
    # Line numbers where activity was found
    activity_lines: list = field(default_factory=list)
    # Absence-based error messages that fired
    absence_errors: list = field(default_factory=list)

    @property
    def score(self):
        """Higher score = more likely to be the problem area.

        Errors are weighted 10x over activity, so an area with even
        one error outranks an area with only activity matches.
        Absence errors count as errors.
        """
        total_errors = self.error_count + len(self.absence_errors)
        return total_errors * 10 + self.activity_count

    @property
    def has_errors(self):
        return self.error_count > 0 or len(self.absence_errors) > 0


def detect(text):
    """Scan decoded btmon output and detect active protocol areas.

    Returns a list of DetectedArea sorted by score (highest first).
    Only areas with at least one match are returned.
    """
    lines = text.splitlines()
    results = []

    for area_def in AREAS:
        det = DetectedArea(area=area_def)

        # Compile patterns once per area
        act_patterns = [re.compile(p) for p in area_def.activity]
        err_patterns = [re.compile(p) for p in area_def.errors]

        for i, line in enumerate(lines):
            for pat in act_patterns:
                if pat.search(line):
                    det.activity_count += 1
                    det.activity_lines.append(i)
                    break  # One match per line is enough

            for pat in err_patterns:
                if pat.search(line):
                    det.error_count += 1
                    det.error_lines.append(i)
                    break

        # Run absence-based checks: prerequisite present but expected
        # absent means a protocol flow broke at a known gate.
        for check in area_def.absence_checks:
            prereq_re = re.compile(check.prerequisite)
            expect_re = re.compile(check.expected)
            has_prereq = False
            has_expected = False
            for line in lines:
                if not has_prereq and prereq_re.search(line):
                    has_prereq = True
                if not has_expected and expect_re.search(line):
                    has_expected = True
                if has_prereq and has_expected:
                    break
            if has_prereq and not has_expected:
                det.absence_errors.append(check.message)

        if det.activity_count > 0 or det.error_count > 0 \
                or det.absence_errors:
            results.append(det)

    results.sort(key=lambda d: d.score, reverse=True)
    return results


# ---------------------------------------------------------------------------
# Log clipping
# ---------------------------------------------------------------------------

def _find_packet_start(lines, idx):
    """Walk backwards from idx to find the start of the containing packet."""
    while idx > 0 and not is_packet_start(lines[idx]):
        idx -= 1
    return idx


def _find_packet_end(lines, idx):
    """Walk forwards from idx to find the end of the containing packet.

    Returns the index of the last line in this packet (one before the
    next packet start, or the last line of the file).
    """
    idx += 1
    while idx < len(lines) and not is_packet_start(lines[idx]):
        idx += 1
    return idx - 1


def clip(text, area_name, context_packets=5, max_chars=30000):
    """Extract log sections relevant to an area.

    Finds all lines matching the area's patterns (activity + errors),
    expands each match to include the full containing packet plus
    ``context_packets`` packets before and after.  Overlapping windows
    are merged.  The result is a compact excerpt suitable for LLM
    analysis.

    Args:
        text: Full decoded btmon output.
        area_name: Name field from AreaDef (e.g. "a2dp", "hfp").
        context_packets: Number of packets to include before/after
            each match.
        max_chars: Maximum output size.  If the clipped output exceeds
            this, it is truncated with a gap marker.

    Returns:
        Clipped text, or the original text if no matches found.
    """
    area_def = None
    for a in AREAS:
        if a.name == area_name:
            area_def = a
            break
    if area_def is None:
        return text

    lines = text.splitlines()
    if not lines:
        return text

    # Find all matching line indices
    all_patterns = ([re.compile(p) for p in area_def.activity] +
                    [re.compile(p) for p in area_def.errors])
    match_lines = set()
    for i, line in enumerate(lines):
        for pat in all_patterns:
            if pat.search(line):
                match_lines.add(i)
                break

    if not match_lines:
        return text

    # Build packet boundary index for efficient lookup
    packet_starts = []
    for i, line in enumerate(lines):
        if is_packet_start(line):
            packet_starts.append(i)
    if not packet_starts or packet_starts[0] != 0:
        packet_starts.insert(0, 0)

    # For each match, find the containing packet's index in packet_starts,
    # then expand by context_packets in each direction
    import bisect
    selected_ranges = []
    for match_line in sorted(match_lines):
        # Find which packet this line belongs to
        pkt_idx = bisect.bisect_right(packet_starts, match_line) - 1
        pkt_idx = max(0, pkt_idx)

        # Expand context
        start_pkt = max(0, pkt_idx - context_packets)
        end_pkt = min(len(packet_starts) - 1, pkt_idx + context_packets)

        range_start = packet_starts[start_pkt]
        # End of the last context packet
        if end_pkt + 1 < len(packet_starts):
            range_end = packet_starts[end_pkt + 1] - 1
        else:
            range_end = len(lines) - 1

        selected_ranges.append((range_start, range_end))

    # Merge overlapping ranges
    selected_ranges.sort()
    merged = [selected_ranges[0]]
    for start, end in selected_ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + 1:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))

    # Build output
    parts = []
    prev_end = -1
    for i, (start, end) in enumerate(merged):
        if prev_end >= 0 and start > prev_end + 1:
            skipped = start - prev_end - 1
            parts.append(f"\n[... {skipped} lines skipped ...]\n")
        section = "\n".join(lines[start:end + 1])
        parts.append(section)
        prev_end = end

    result = "\n".join(parts)

    # Truncate if still too large
    if len(result) > max_chars:
        # Keep beginning and end
        head_chars = int(max_chars * 0.6)
        tail_chars = int(max_chars * 0.35)
        head = result[:head_chars]
        tail = result[-tail_chars:]
        # Clean line boundaries
        head = head[:head.rfind("\n") + 1]
        tail_start = tail.find("\n") + 1
        tail = tail[tail_start:]
        result = (head +
                  "\n[... truncated to fit context window ...]\n" +
                  tail)

    return result


def clip_for_focus(text, focus, context_packets=5, max_chars=30000):
    """Clip log for a focus area string (as used in FOCUS_DOCS).

    Maps focus area names to area definition names and calls clip().
    """
    # Map focus strings to area names
    focus_to_area = {a.focus: a.name for a in AREAS}

    # Handle the parent "Audio" focus: clip all three audio areas
    if focus == "Audio":
        parts = []
        for sub in ("a2dp", "hfp", "le_audio"):
            clipped = clip(text, sub, context_packets, max_chars // 3)
            if clipped != text:  # Only include if patterns matched
                parts.append(f"=== {sub.upper()} section ===\n{clipped}")
        if parts:
            return "\n\n".join(parts)
        return text

    area_name = focus_to_area.get(focus)
    if area_name:
        return clip(text, area_name, context_packets, max_chars)
    return text


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    """Read decoded btmon from stdin, print detection results."""
    text = sys.stdin.read()
    if not text.strip():
        print("No input on stdin.", file=sys.stderr)
        sys.exit(1)

    results = detect(text)

    if not results:
        print("No protocol areas detected.")
        return

    print(f"Detected {len(results)} active area(s):\n")
    for det in results:
        marker = " ** ERRORS **" if det.has_errors else ""
        print(f"  {det.area.name:15s}  score={det.score:4d}  "
              f"activity={det.activity_count:4d}  "
              f"errors={det.error_count:3d}{marker}")
        print(f"  {'':15s}  focus: {det.area.focus}")
        if det.error_lines:
            preview = det.error_lines[:5]
            more = f" (+{len(det.error_lines) - 5} more)" \
                if len(det.error_lines) > 5 else ""
            print(f"  {'':15s}  error lines: "
                  f"{', '.join(str(l) for l in preview)}{more}")
        if det.absence_errors:
            for msg in det.absence_errors:
                print(f"  {'':15s}  ABSENCE: {msg}")
        print()

    # Show top area's clipped output size
    top = results[0]
    clipped = clip(text, top.area.name)
    ratio = len(clipped) / len(text) * 100 if text else 0
    print(f"Top area '{top.area.name}' clip: {len(clipped)} chars "
          f"({ratio:.0f}% of original {len(text)} chars)")


if __name__ == "__main__":
    main()
