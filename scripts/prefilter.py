"""
prefilter.py - Prefiltered log output (Step 2).

Produces a structured prefiltered result for LLM consumption by
separating raw btmon packets from semantic annotations.  Key packets
get full body, context packets get header-only, and skipped packets
are replaced with gap markers.

Usage as a module:
    from prefilter import prefilter, format_filter_markdown
"""


# ---------------------------------------------------------------------------
# Packet formatting helpers
# ---------------------------------------------------------------------------

def _format_packet(pkt, include_body=True):
    """Format a packet for prefiltered output, with annotation prefix."""
    parts = []
    if pkt.annotation:
        parts.append(f"### {pkt.annotation} [{' | '.join(pkt.tags)}]")
    parts.append(pkt._raw_header)
    if include_body:
        parts.extend(pkt.body)
    return "\n".join(parts)


def _format_packet_raw(pkt, include_body=True):
    """Format a packet as raw btmon output (no annotation markers)."""
    parts = [pkt._raw_header]
    if include_body:
        parts.extend(pkt.body)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Prefilter (Step 2)
# ---------------------------------------------------------------------------

def prefilter(text, focus, max_chars=24000, packets=None, diags=None):
    """Produce a structured prefiltered result for LLM consumption.

    The output separates raw btmon packets from semantic annotations so
    the LLM receives clean trace data alongside decoded metadata.

    Steps:
        1. Parse decoded btmon text into packets (or use pre-annotated)
        2. Run the focus-specific annotator(s) to tag packets
        3. Build raw trace (key packets with full body, context with
           header-only, skip gap markers) — no annotation markers
        4. Build annotations section (timeline, per-packet tags and
           decoded meanings, diagnostics)
        5. Build combined summary header

    Args:
        text: Full decoded btmon output.
        focus: Focus area string (e.g. "Audio / LE Audio").
        max_chars: Character budget for the output.
        packets: Optional pre-annotated Packet list (skips re-parsing).
        diags: Optional pre-computed diagnostics list.

    Returns:
        (prefiltered_text, diagnostics_list)
        The prefiltered_text contains clearly separated sections:
        a summary header, a raw trace section, and an annotation
        section.  diagnostics_list contains absence errors and info
        messages.
    """
    if packets is not None:
        # Use pre-annotated data
        all_diags = diags if diags is not None else []
        if not packets:
            return text, all_diags
    else:
        from annotate import annotate_trace
        packets, all_diags, found = annotate_trace(text, focus)
        if not packets:
            return text, []
        if not found:
            # No specific annotator -- return original text truncated
            return text[:max_chars], []

    # Separate packets by priority
    key_pkts = [p for p in packets if p.priority == "key"]
    ctx_pkts = [p for p in packets if p.priority == "context"]

    # --- Build summary header ---
    header_lines = [f"=== Prefiltered btmon log: {focus} ==="]
    header_lines.append(f"Total packets: {len(packets)}, "
                        f"Key: {len(key_pkts)}, "
                        f"Context: {len(ctx_pkts)}, "
                        f"Skipped: {len(packets) - len(key_pkts) - len(ctx_pkts)}")

    if packets:
        header_lines.append(
            f"Time span: {packets[0].timestamp:.3f}s - "
            f"{packets[-1].timestamp:.3f}s "
            f"({packets[-1].timestamp - packets[0].timestamp:.1f}s)")

    if all_diags:
        header_lines.append("")
        header_lines.append("Diagnostics:")
        for d in all_diags:
            header_lines.append(f"  * {d}")

    header = "\n".join(header_lines)

    # --- Build annotations section ---
    # Timeline + per-packet annotation table (separate from raw trace)
    ann_lines = ["=== Annotations ===", ""]
    ann_lines.append("Key event timeline:")
    for pkt in key_pkts[:30]:  # Cap timeline at 30 entries
        ann_lines.append(
            f"  {pkt.timestamp:>12.3f}s  #{pkt.frame:<5d}  "
            f"{pkt.annotation}")

    if len(key_pkts) > 30:
        ann_lines.append(
            f"  ... and {len(key_pkts) - 30} more key events")

    # Per-packet annotation table: frame -> decoded meaning + tags
    ann_lines.append("")
    ann_lines.append("Per-packet annotations (frame -> decoded meaning [tags]):")
    included_pkts = [p for p in packets
                     if p.priority in ("key", "context") and p.annotation]
    for pkt in included_pkts[:60]:
        ann_lines.append(
            f"  #{pkt.frame:<5d} {pkt.timestamp:>9.3f}s  "
            f"{pkt.annotation}  [{' | '.join(pkt.tags)}]")
    if len(included_pkts) > 60:
        ann_lines.append(
            f"  ... and {len(included_pkts) - 60} more annotations")

    annotations = "\n".join(ann_lines)

    # --- Budget allocation ---
    # Reserve space for header + annotations, rest goes to raw trace
    overhead = len(header) + len(annotations) + 200  # separators + margin
    trace_budget = max_chars - overhead
    if trace_budget < 1000:
        # Not enough room for raw packets -- return header + annotations
        return header + "\n\n" + annotations, all_diags

    # --- Build raw trace section ---
    raw_parts = ["=== Raw btmon packets ===", ""]
    prev_idx = -1
    chars_used = 0

    # Merge key and context packets in order
    tagged = [(p.line_start, p) for p in packets
              if p.priority in ("key", "context")]
    tagged.sort(key=lambda x: x[0])

    for _, pkt in tagged:
        # Raw packet text (no annotation markers)
        formatted = _format_packet_raw(
            pkt, include_body=(pkt.priority == "key"))
        cost = len(formatted) + 50  # gap marker overhead

        if chars_used + cost > trace_budget:
            # Context packets can be dropped to save budget
            if pkt.priority == "context":
                continue
            # Key packet but out of budget -- switch to header-only
            formatted = _format_packet_raw(pkt, include_body=False)
            cost = len(formatted) + 50

        if chars_used + cost > trace_budget:
            # Truly out of budget
            raw_parts.append(
                f"\n[... budget exhausted, "
                f"{len(key_pkts)} key packets total ...]\n")
            break

        # Insert gap marker if there's a skip
        if prev_idx >= 0 and pkt.line_start > prev_idx + 1:
            gap_packets = sum(1 for p in packets
                              if prev_idx < p.line_start < pkt.line_start
                              and p.priority == "skip")
            if gap_packets > 0:
                raw_parts.append(
                    f"\n[... {gap_packets} packets skipped ...]\n")

        raw_parts.append(formatted)
        chars_used += cost
        prev_idx = pkt.line_end

    raw_trace = "\n".join(raw_parts)

    # --- Combine into final output with clear section separators ---
    combined = "\n\n".join([header, annotations, raw_trace])
    return combined, all_diags


def format_filter_markdown(packets, focus, trace_chars, max_chars,
                           prefiltered_text=None):
    """Format prefilter summary as Step 2: Filter.

    Shows packet counts, time span, budget usage, and key/context/skipped
    breakdown.  Optionally includes the prefiltered trace in a collapsible
    text box for easy copy/paste.

    Args:
        packets: List of Packet objects (already annotated).
        focus: Focus area string.
        trace_chars: Number of characters in the prefiltered trace.
        max_chars: Character budget limit.
        prefiltered_text: Optional prefiltered trace text to include
            in a collapsible ``<details>`` block.

    Returns:
        Markdown string suitable for posting as a GitHub issue comment.
    """
    key_pkts = [p for p in packets if p.priority == "key"]
    ctx_pkts = [p for p in packets if p.priority == "context"]
    skip_count = len(packets) - len(key_pkts) - len(ctx_pkts)

    lines = ["## Step 2: Filter", ""]
    lines.append(f"**Focus:** {focus}")
    lines.append(f"**Total packets:** {len(packets)}")
    lines.append(f"**Key:** {len(key_pkts)} | "
                 f"**Context:** {len(ctx_pkts)} | "
                 f"**Skipped:** {skip_count}")
    if packets:
        span = packets[-1].timestamp - packets[0].timestamp
        lines.append(f"**Time span:** {packets[0].timestamp:.3f}s - "
                     f"{packets[-1].timestamp:.3f}s ({span:.1f}s)")
    if max_chars > 0:
        pct = trace_chars * 100 // max_chars
        lines.append(f"**Budget:** {trace_chars:,} / {max_chars:,} chars "
                     f"({pct}% used)")
    lines.append("")

    if prefiltered_text:
        lines.append("<details>")
        lines.append("<summary>Prefiltered log</summary>")
        lines.append("")
        lines.append("```")
        lines.append(prefiltered_text)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)
