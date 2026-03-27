"""
packet.py - Shared types for btsnoop trace parsing.

Provides Packet, Diagnostic, HEADER_RE, META_RE, and parse_packets()
used across all pipeline steps (detect, annotate, prefilter, diagnose).
"""

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Packet parsing regexes
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
    r'\s+(?:\[hci\d+\]|\{0x\w+\})\s+'  # [hciN] or {0xNNNN} index
    r'(\d+\.\d+)\s*$'         # timestamp
)

# Fallback for = lines that have no [hciN] but end with a timestamp
META_RE = re.compile(
    r'^([=])\s+'
    r'(.+?)'
    r'\s+(\d+\.\d+)\s*$'
)


# ---------------------------------------------------------------------------
# Packet dataclass
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Diagnostic class
# ---------------------------------------------------------------------------

class Diagnostic:
    """A diagnostic message with optional packet reference.

    Behaves like a string (for backward compatibility with code that
    formats diagnostics as plain text) but carries optional frame,
    timestamp, and tags metadata for structured rendering.
    """

    __slots__ = ("message", "frame", "timestamp", "tags")

    def __init__(self, message, frame=None, timestamp=None, tags=None):
        self.message = message
        self.frame = frame
        self.timestamp = timestamp
        self.tags = tags or []

    def __str__(self):
        return self.message

    def __repr__(self):
        return f"Diagnostic({self.message!r}, frame={self.frame})"

    # Support string operations used in existing code
    def startswith(self, prefix):
        return self.message.startswith(prefix)

    def split(self, *args, **kwargs):
        return self.message.split(*args, **kwargs)

    def lower(self):
        return self.message.lower()

    def __contains__(self, item):
        return item in self.message

    def __add__(self, other):
        return str(self) + other

    def __radd__(self, other):
        return other + str(self)

    def __eq__(self, other):
        if isinstance(other, Diagnostic):
            return self.message == other.message
        return self.message == other

    def __hash__(self):
        return hash(self.message)


# ---------------------------------------------------------------------------
# Packet parser
# ---------------------------------------------------------------------------

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
