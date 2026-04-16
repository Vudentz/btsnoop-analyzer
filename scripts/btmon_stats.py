"""
btmon_stats.py - Parser for btmon --analyze output.

Parses the statistical summary produced by ``btmon --analyze <file>``
into structured data: controllers, connections, and L2CAP channels with
packet counts, latency, size, throughput, PSM, mode, MTU, and MPS.

The btmon --analyze output also contains gnuplot ASCII charts; this
parser ignores everything before the "Bluetooth monitor ver" line.
"""

import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ChannelStats:
    """Statistics for a single L2CAP channel."""
    direction: str          # "TX" or "RX"
    cid: int                # Channel ID (e.g. 64)
    cid_name: Optional[str] = None  # e.g. "ATT", "L2CAP Signaling (LE)"
    psm: Optional[int] = None
    psm_hex: Optional[str] = None   # e.g. "0x0080"
    mode: Optional[str] = None      # e.g. "LE Credit"
    mtu: Optional[int] = None
    mps: Optional[int] = None
    packets_sent: int = 0
    packets_complete: int = 0
    latency_min: Optional[int] = None   # msec
    latency_max: Optional[int] = None   # msec
    latency_avg: Optional[int] = None   # msec
    size_min: Optional[int] = None      # octets
    size_max: Optional[int] = None      # octets
    size_avg: Optional[int] = None      # octets
    speed_avg: Optional[int] = None     # Kb/s
    speed_min: Optional[int] = None     # Kb/s
    speed_max: Optional[int] = None     # Kb/s


@dataclass
class ConnectionStats:
    """Statistics for a single ACL connection."""
    conn_type: str          # "LE-ACL", "BR/EDR-ACL", etc.
    handle: int
    address: Optional[str] = None
    address_name: Optional[str] = None  # OUI or device name
    rx_packets_sent: int = 0
    rx_packets_complete: int = 0
    rx_latency_min: Optional[int] = None
    rx_latency_max: Optional[int] = None
    rx_latency_avg: Optional[int] = None
    rx_size_min: Optional[int] = None
    rx_size_max: Optional[int] = None
    rx_size_avg: Optional[int] = None
    rx_speed_avg: Optional[int] = None
    rx_speed_min: Optional[int] = None
    rx_speed_max: Optional[int] = None
    tx_packets_sent: int = 0
    tx_packets_complete: int = 0
    tx_latency_min: Optional[int] = None
    tx_latency_max: Optional[int] = None
    tx_latency_avg: Optional[int] = None
    tx_size_min: Optional[int] = None
    tx_size_max: Optional[int] = None
    tx_size_avg: Optional[int] = None
    tx_speed_avg: Optional[int] = None
    tx_speed_min: Optional[int] = None
    tx_speed_max: Optional[int] = None
    connected_frame: Optional[int] = None
    disconnected_frame: Optional[int] = None
    disconnect_reason: Optional[str] = None
    channels: List[ChannelStats] = field(default_factory=list)


@dataclass
class ControllerStats:
    """Statistics for a single HCI controller."""
    controller_type: str    # "BR/EDR" etc.
    index: int
    bd_addr: Optional[str] = None
    commands: int = 0
    events: int = 0
    acl_packets: int = 0
    sco_packets: int = 0
    iso_packets: int = 0
    total_packets: int = 0
    connections: List[ConnectionStats] = field(default_factory=list)


@dataclass
class BtmonAnalysis:
    """Complete parsed btmon --analyze output."""
    version: Optional[str] = None
    total_packets: int = 0
    controllers: List[ControllerStats] = field(default_factory=list)

    def all_channels(self):
        """Yield all ChannelStats across all connections."""
        for ctrl in self.controllers:
            for conn in ctrl.connections:
                for chan in conn.channels:
                    yield chan

    def all_connections(self):
        """Yield all ConnectionStats across all controllers."""
        for ctrl in self.controllers:
            for conn in ctrl.connections:
                yield conn

    def format_summary(self):
        """Format a human-readable summary for LLM context.

        Returns a multi-line string suitable for inclusion in the
        analysis prompt as additional statistical context.
        """
        lines = []
        lines.append("## btmon --analyze Statistics\n")
        lines.append(f"Trace contains {self.total_packets} packets\n")

        for ctrl in self.controllers:
            if ctrl.index == 65535:
                continue  # Skip the dummy controller
            lines.append(
                f"### Controller index {ctrl.index} "
                f"({ctrl.bd_addr or 'unknown'})")
            lines.append(
                f"  {ctrl.commands} commands, {ctrl.events} events, "
                f"{ctrl.acl_packets} ACL, {ctrl.sco_packets} SCO, "
                f"{ctrl.iso_packets} ISO\n")

            for conn in ctrl.connections:
                lines.append(
                    f"#### {conn.conn_type} handle {conn.handle}")
                if conn.address:
                    name = (f" ({conn.address_name})"
                            if conn.address_name else "")
                    lines.append(f"  Address: {conn.address}{name}")
                if conn.connected_frame is not None:
                    lines.append(
                        f"  Connected: #{conn.connected_frame}, "
                        f"Disconnected: #{conn.disconnected_frame}"
                        + (f" (reason {conn.disconnect_reason})"
                           if conn.disconnect_reason else ""))

                # Connection-level RX/TX
                for dir_label, pfx in [("RX", "rx_"), ("TX", "tx_")]:
                    pkts = getattr(conn, f"{pfx}packets_sent")
                    if pkts == 0:
                        continue
                    compl = getattr(conn, f"{pfx}packets_complete")
                    speed = getattr(conn, f"{pfx}speed_avg")
                    speed_min = getattr(conn, f"{pfx}speed_min")
                    speed_max = getattr(conn, f"{pfx}speed_max")
                    s = f"  {dir_label}: {pkts}/{compl} packets"
                    if speed is not None:
                        s += f", ~{speed} Kb/s"
                        if speed_min is not None:
                            s += f" (min ~{speed_min}, max ~{speed_max})"
                    lines.append(s)
                lines.append("")

                # Per-channel stats
                for chan in conn.channels:
                    cid_label = str(chan.cid)
                    if chan.cid_name:
                        cid_label += f" ({chan.cid_name})"
                    parts = [
                        f"  {chan.direction} L2CAP CID {cid_label}"]
                    if chan.psm is not None:
                        parts.append(f"PSM {chan.psm}")
                    if chan.mode:
                        parts.append(f"Mode: {chan.mode}")
                    if chan.mtu is not None:
                        parts.append(f"MTU: {chan.mtu}")
                    if chan.mps is not None:
                        parts.append(f"MPS: {chan.mps}")
                    lines.append(", ".join(parts))

                    pkt_line = (
                        f"    {chan.packets_sent}/{chan.packets_complete}"
                        f" packets")
                    if chan.speed_avg is not None:
                        pkt_line += f", ~{chan.speed_avg} Kb/s"
                        if chan.speed_min is not None:
                            pkt_line += (
                                f" (min ~{chan.speed_min}, "
                                f"max ~{chan.speed_max})")
                    lines.append(pkt_line)

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Regex patterns for parsing btmon --analyze text output
# ---------------------------------------------------------------------------

_RE_VERSION = re.compile(
    r"Bluetooth monitor ver (.+)")
_RE_TOTAL = re.compile(
    r"Trace contains (\d+) packets")
_RE_CONTROLLER = re.compile(
    r"Found (\S+) controller with index (\d+)")
_RE_BD_ADDR = re.compile(
    r"BD_ADDR ([\dA-Fa-f:]+)")
_RE_COUNTER = re.compile(
    r"(\d+) (commands|events|ACL packets|SCO packets|ISO packets)")
_RE_CONNECTION = re.compile(
    r"Found ([\w-]+) connection with handle (\d+)")
_RE_ADDRESS = re.compile(
    r"Address: ([\dA-Fa-f:]+)(?:\s+\((.+)\))?")
_RE_PACKETS = re.compile(
    r"(RX|TX) packets: (\d+)/(\d+)")
_RE_LATENCY = re.compile(
    r"(RX|TX) Latency: (\d+)-(\d+) msec \(~(\d+) msec\)")
_RE_SIZE = re.compile(
    r"(RX|TX) size: (\d+)-(\d+) octets \(~(\d+) octets\)")
_RE_SPEED = re.compile(
    r"(RX|TX) speed: ~(\d+) Kb/s"
    r"(?: \(min ~(\d+) Kb/s max ~(\d+) Kb/s\))?")
_RE_CONNECTED = re.compile(
    r"Connected: #(\d+)")
_RE_DISCONNECTED = re.compile(
    r"Disconnected: #(\d+)")
_RE_DISC_REASON = re.compile(
    r"Disconnect Reason: (0x[\da-fA-F]+)")
_RE_CHANNEL = re.compile(
    r"Found (TX|RX) L2CAP channel with CID (\d+)(?:\s+\((.+)\))?")
_RE_PSM = re.compile(
    r"PSM (\d+) \((0x[\da-fA-F]+)\)")
_RE_MODE = re.compile(
    r"Mode: (.+)")
_RE_MTU = re.compile(
    r"MTU: (\d+)")
_RE_MPS = re.compile(
    r"MPS: (\d+)")


def parse_btmon_analyze(text: str) -> BtmonAnalysis:
    """Parse btmon --analyze output text into structured data.

    Expects the text portion of btmon --analyze output (after any
    gnuplot charts).  The parser finds the "Bluetooth monitor ver"
    line and ignores everything before it.
    """
    result = BtmonAnalysis()

    # Find the start of the textual summary
    lines = text.splitlines()
    start_idx = 0
    for i, line in enumerate(lines):
        if "Bluetooth monitor ver" in line:
            start_idx = i
            break
    else:
        # No header found — try to parse whatever we have
        start_idx = 0

    current_ctrl = None
    current_conn = None
    current_chan = None

    for line in lines[start_idx:]:
        stripped = line.strip()
        if not stripped:
            continue

        # Strip ANSI escape codes
        stripped = re.sub(r'\x1b\[[0-9;]*m', '', stripped)

        m = _RE_VERSION.match(stripped)
        if m:
            result.version = m.group(1)
            continue

        m = _RE_TOTAL.match(stripped)
        if m:
            result.total_packets = int(m.group(1))
            continue

        m = _RE_CONTROLLER.match(stripped)
        if m:
            current_ctrl = ControllerStats(
                controller_type=m.group(1),
                index=int(m.group(2)))
            result.controllers.append(current_ctrl)
            current_conn = None
            current_chan = None
            continue

        if current_ctrl is None:
            continue

        m = _RE_BD_ADDR.search(stripped)
        if m and current_conn is None:
            current_ctrl.bd_addr = m.group(1)
            continue

        m = _RE_COUNTER.match(stripped)
        if m and current_conn is None:
            count = int(m.group(1))
            kind = m.group(2)
            if kind == "commands":
                current_ctrl.commands = count
            elif kind == "events":
                current_ctrl.events = count
            elif kind == "ACL packets":
                current_ctrl.acl_packets = count
            elif kind == "SCO packets":
                current_ctrl.sco_packets = count
            elif kind == "ISO packets":
                current_ctrl.iso_packets = count
            continue

        m = _RE_CONNECTION.match(stripped)
        if m:
            current_conn = ConnectionStats(
                conn_type=m.group(1),
                handle=int(m.group(2)))
            current_ctrl.connections.append(current_conn)
            current_chan = None
            continue

        if current_conn is not None:
            m = _RE_ADDRESS.search(stripped)
            if m and current_chan is None:
                current_conn.address = m.group(1)
                current_conn.address_name = m.group(2)
                continue

            m = _RE_CONNECTED.search(stripped)
            if m:
                current_conn.connected_frame = int(m.group(1))
                continue

            m = _RE_DISCONNECTED.search(stripped)
            if m:
                current_conn.disconnected_frame = int(m.group(1))
                continue

            m = _RE_DISC_REASON.search(stripped)
            if m:
                current_conn.disconnect_reason = m.group(1)
                continue

            m = _RE_CHANNEL.match(stripped)
            if m:
                current_chan = ChannelStats(
                    direction=m.group(1),
                    cid=int(m.group(2)),
                    cid_name=m.group(3))
                current_conn.channels.append(current_chan)
                continue

            # Channel-level fields
            if current_chan is not None:
                m = _RE_PSM.search(stripped)
                if m:
                    current_chan.psm = int(m.group(1))
                    current_chan.psm_hex = m.group(2)
                    continue

                m = _RE_MODE.match(stripped)
                if m:
                    current_chan.mode = m.group(1)
                    continue

                m = _RE_MTU.match(stripped)
                if m:
                    current_chan.mtu = int(m.group(1))
                    continue

                m = _RE_MPS.match(stripped)
                if m:
                    current_chan.mps = int(m.group(1))
                    continue

            # Packet/latency/size/speed lines apply to either the
            # current channel or the current connection
            m = _RE_PACKETS.search(stripped)
            if m:
                direction, sent, complete = (
                    m.group(1), int(m.group(2)), int(m.group(3)))
                if current_chan is not None:
                    current_chan.packets_sent = sent
                    current_chan.packets_complete = complete
                else:
                    if direction == "RX":
                        current_conn.rx_packets_sent = sent
                        current_conn.rx_packets_complete = complete
                    else:
                        current_conn.tx_packets_sent = sent
                        current_conn.tx_packets_complete = complete
                continue

            m = _RE_LATENCY.search(stripped)
            if m:
                direction = m.group(1)
                lat_min, lat_max, lat_avg = (
                    int(m.group(2)), int(m.group(3)), int(m.group(4)))
                if current_chan is not None:
                    current_chan.latency_min = lat_min
                    current_chan.latency_max = lat_max
                    current_chan.latency_avg = lat_avg
                else:
                    pfx = "rx_" if direction == "RX" else "tx_"
                    setattr(current_conn, f"{pfx}latency_min", lat_min)
                    setattr(current_conn, f"{pfx}latency_max", lat_max)
                    setattr(current_conn, f"{pfx}latency_avg", lat_avg)
                continue

            m = _RE_SIZE.search(stripped)
            if m:
                direction = m.group(1)
                sz_min, sz_max, sz_avg = (
                    int(m.group(2)), int(m.group(3)), int(m.group(4)))
                if current_chan is not None:
                    current_chan.size_min = sz_min
                    current_chan.size_max = sz_max
                    current_chan.size_avg = sz_avg
                else:
                    pfx = "rx_" if direction == "RX" else "tx_"
                    setattr(current_conn, f"{pfx}size_min", sz_min)
                    setattr(current_conn, f"{pfx}size_max", sz_max)
                    setattr(current_conn, f"{pfx}size_avg", sz_avg)
                continue

            m = _RE_SPEED.search(stripped)
            if m:
                direction = m.group(1)
                avg = int(m.group(2))
                spd_min = int(m.group(3)) if m.group(3) else None
                spd_max = int(m.group(4)) if m.group(4) else None
                if current_chan is not None:
                    current_chan.speed_avg = avg
                    current_chan.speed_min = spd_min
                    current_chan.speed_max = spd_max
                else:
                    pfx = "rx_" if direction == "RX" else "tx_"
                    setattr(current_conn, f"{pfx}speed_avg", avg)
                    setattr(current_conn, f"{pfx}speed_min", spd_min)
                    setattr(current_conn, f"{pfx}speed_max", spd_max)
                continue

    return result


def run_btmon_analyze(btmon_path: str, trace_path: str,
                      timeout: int = 120) -> Optional[BtmonAnalysis]:
    """Run btmon --analyze and parse the output.

    Returns a BtmonAnalysis object, or None if btmon fails or is not
    found.
    """
    try:
        result = subprocess.run(
            [btmon_path, "--analyze", trace_path],
            capture_output=True,
            timeout=timeout,
        )
        # btmon --analyze may return non-zero but still produce output
        output = result.stdout.decode("utf-8", errors="replace")
        if not output.strip():
            return None
        return parse_btmon_analyze(output)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
