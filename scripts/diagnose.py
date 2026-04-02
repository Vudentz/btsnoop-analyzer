"""
diagnose.py - Diagnostics formatting (Step 4).

Formats annotator diagnostics (absence errors, stream info, config
details, state tables) as markdown for GitHub issue comments.

Usage as a module:
    from diagnose import format_diagnostics_markdown
"""


def format_diagnostics_markdown(packets, diags):
    """Format diagnostics as Step 4: Diagnostics table.

    Includes graceful disconnect packets as rows with frame/timestamp,
    and annotator diagnostics (STREAM, CONFIG, STATE, ABSENCE, NOTE,
    INFO) with frame/timestamp/tags when available from Diagnostic
    objects.

    Args:
        packets: List of Packet objects (already annotated).
        diags: List of Diagnostic objects (or strings) from annotators.

    Returns:
        Markdown string suitable for posting as a GitHub issue comment.
    """
    lines = ["## Step 4: Diagnostics", ""]

    graceful = [p for p in packets
                if p.annotation and "Graceful disconnect" in p.annotation]
    has_diags = graceful or diags
    if has_diags:
        lines.append("| # | Timestamp | Tags | Diagnostic |")
        lines.append("|--:|----------:|------|------------|")
        # Graceful disconnects as diagnostic rows
        for pkt in graceful:
            tags = ", ".join(f"`{t}`" for t in pkt.tags)
            lines.append(
                f"| #{pkt.frame} | {pkt.timestamp:.3f}s | "
                f"{tags} | {pkt.annotation} |")
        # Annotator diagnostics with structured fields
        for d in diags:
            # Build frame/timestamp/tags columns from Diagnostic
            frame_col = f"#{d.frame}" if hasattr(d, "frame") \
                and d.frame is not None else "-"
            ts_col = f"{d.timestamp:.3f}s" if hasattr(d, "timestamp") \
                and d.timestamp is not None else "-"
            d_tags = d.tags if hasattr(d, "tags") and d.tags else []
            tags_col = ", ".join(f"`{t}`" for t in d_tags) \
                if d_tags else "-"

            msg = str(d)
            if msg.startswith("ABSENCE:"):
                lines.append(
                    f"| {frame_col} | {ts_col} | {tags_col} | "
                    f":warning: {msg} |")
            elif msg.startswith("INFO:") or msg.startswith("NOTE:"):
                lines.append(
                    f"| {frame_col} | {ts_col} | {tags_col} | "
                    f":information_source: {msg} |")
            elif "\n" in msg:
                # Multi-line diagnostics (e.g. STATE tables): keep
                # everything in one table cell using <br> + inline
                # code spans so the table is never interrupted.
                parts = msg.split("\n")
                first = parts[0]
                rest_lines = parts[1:]
                # Dedent continuation lines (strip common leading
                # whitespace) and render as inline code spans.
                non_empty = [l for l in rest_lines if l.strip()]
                if non_empty:
                    min_indent = min(
                        len(l) - len(l.lstrip()) for l in non_empty)
                    cell_parts = [first]
                    for line in rest_lines:
                        if line.strip():
                            cell_parts.append(
                                f"`{line[min_indent:]}`")
                    cell = "<br>".join(cell_parts)
                else:
                    cell = first
                lines.append(
                    f"| {frame_col} | {ts_col} | {tags_col} | "
                    f"{cell} |")
            else:
                lines.append(
                    f"| {frame_col} | {ts_col} | {tags_col} | "
                    f"{msg} |")
        lines.append("")
    else:
        lines.append("No diagnostics generated.")
        lines.append("")

    return "\n".join(lines)
