#!/usr/bin/env python3
"""
analyze.py - btsnoop trace analyzer

Downloads a btsnoop trace from a GitHub issue, decodes it with btmon,
optionally anonymizes the output, and runs a 5-step analysis pipeline:

  Step 1: Detection    - Auto-detect protocol focus area (detect.py)
  Step 2: Filter       - Prefilter stats and budget usage (annotate.py)
  Step 3: Annotation   - Key Frames table (annotate.py)
  Step 4: Diagnostics  - Graceful disconnects + annotator diagnostics (annotate.py)
  Step 5: LLM Analysis - Structured diagnostic report (templates.py + LLM)

Each step writes a markdown file to --output-dir (detect.md, filter.md,
annotate.md, diagnose.md, analyze.md) for posting as GitHub comments.

Usage (full pipeline with output directory):
    python3 scripts/analyze.py \
        --trace-url URL \
        --description "user description" \
        --focus "General" \
        --anonymize \
        --provider github \
        --btmon-path ./bluez/monitor/btmon \
        --docs-path ./bluez/doc/btmon.rst \
        --output-dir results

Usage (single output file, no per-step files):
    python3 scripts/analyze.py \
        --trace-url URL \
        --description "user description" \
        --focus "Audio / A2DP" \
        --provider openai \
        --btmon-path ./bluez/monitor/btmon \
        --docs-path ./bluez/doc/btmon.rst \
        --output analysis.md

Environment variables:
    OPENAI_API_KEY      - for --provider openai
    ANTHROPIC_API_KEY   - for --provider anthropic
    GH_MODELS_TOKEN     - for --provider github (PAT with models:read scope)
    GITHUB_TOKEN        - fallback for --provider github
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error

from detect import detect, clip_for_focus, select_focus
from detect import format_markdown as detect_markdown
from templates import template_instructions
from annotate import annotate_trace
from annotate import format_annotation_markdown as annotate_markdown
from prefilter import prefilter
from prefilter import format_filter_markdown as filter_markdown
from diagnose import format_diagnostics_markdown as diagnostics_markdown
from btmon_stats import run_btmon_analyze


def log(msg):
    """Print with immediate flush for CI visibility."""
    print(msg, flush=True)


def download_trace(url, dest_path):
    """Download the trace file from the given URL."""
    log(f"Downloading trace from {url}")
    try:
        req = urllib.request.Request(url)
        # GitHub attachment URLs may need auth for private repos
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"token {token}")
        with urllib.request.urlopen(req, timeout=60) as resp, \
                open(dest_path, "wb") as f:
            f.write(resp.read())
        log(f"Downloaded {os.path.getsize(dest_path)} bytes")
    except urllib.error.URLError as e:
        log(f"Failed to download trace: {e}")
        sys.exit(1)


def decode_trace(btmon_path, trace_path):
    """Run btmon -r to decode the trace file."""
    log(f"Decoding trace with {btmon_path}")
    try:
        result = subprocess.run(
            [btmon_path, "-r", trace_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout
        if result.returncode != 0 and not output:
            log(f"btmon stderr: {result.stderr}")
            sys.exit(1)
        lines = output.splitlines()
        log(f"Decoded {len(lines)} lines")
        return output
    except FileNotFoundError:
        log(f"btmon not found at {btmon_path}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log("btmon decoding timed out after 120s")
        sys.exit(1)


def analyze_trace(btmon_path, trace_path):
    """Run btmon --analyze to get statistical summary.

    Returns a BtmonAnalysis object with per-connection and per-channel
    statistics, or None if btmon --analyze fails.
    """
    log("Running btmon --analyze for trace statistics...")
    result = run_btmon_analyze(btmon_path, trace_path, timeout=120)
    if result is not None:
        n_conns = sum(1 for _ in result.all_connections())
        n_chans = sum(1 for _ in result.all_channels())
        log(f"btmon --analyze: {result.total_packets} packets, "
            f"{n_conns} connections, {n_chans} channels")
    else:
        log("Warning: btmon --analyze produced no output")
    return result


def anonymize_output(decoded_text):
    """Replace MAC addresses with consistent pseudonyms.

    Each unique MAC gets a fake address (00:00:00:00:00:01, :02, ...)
    preserving device relationships while hiding real addresses.
    """
    log("Anonymizing trace output")
    mac_map = {}
    counter = 0
    mac_re = re.compile(r'[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}')

    def replace_mac(match):
        nonlocal counter
        mac = match.group(0).upper()
        if mac not in mac_map:
            counter += 1
            mac_map[mac] = f"00:00:00:00:00:{counter:02X}"
        return mac_map[mac]

    result = mac_re.sub(replace_mac, decoded_text)
    log(f"Anonymized {counter} unique MAC addresses")
    return result


def truncate_for_context(text, max_chars=100000):
    """Truncate text to fit within LLM context limits.

    Keeps the first and last portions to preserve connection setup
    and final events (often disconnection/errors).
    """
    if len(text) <= max_chars:
        return text

    # Keep 60% from start (connection setup, discovery) and 40% from end
    # (errors, disconnection)
    head_chars = int(max_chars * 0.6)
    tail_chars = int(max_chars * 0.4)

    head = text[:head_chars]
    tail = text[-tail_chars:]

    # Find clean line boundaries
    head = head[:head.rfind("\n") + 1]
    tail_start = tail.find("\n") + 1
    tail = tail[tail_start:]

    total_lines = text.count("\n")
    head_lines = head.count("\n")
    tail_lines = tail.count("\n")
    skipped = total_lines - head_lines - tail_lines

    separator = (
        f"\n\n[... {skipped} lines truncated to fit context window ...]\n\n"
    )
    return head + separator + tail


# Map focus area strings (from issue template) to doc file names.
# Each focus area loads the base btmon.rst plus focus-specific files.
FOCUS_DOCS = {
    "Connection issues": ["btmon-connections.rst"],
    "Controller enumeration": ["btmon-hci-init.rst"],
    "Pairing / Security": ["btmon-smp.rst"],
    "GATT discovery": ["btmon-gatt.rst"],
    "Audio": ["btmon-le-audio.rst", "btmon-a2dp.rst", "btmon-hfp.rst"],
    "Audio / LE Audio": ["btmon-le-audio.rst"],
    "Audio / A2DP": ["btmon-a2dp.rst"],
    "Audio / HFP": ["btmon-hfp.rst"],
    "L2CAP channel issues": ["btmon-l2cap.rst"],
    "Advertising / Scanning": ["btmon-advertising.rst"],
    "Disconnection analysis": ["btmon-connections.rst"],
    "Channel Sounding": ["btmon-cs.rst"],
}


# Canonical focus area names.  Keys must match FOCUS_DOCS, TEMPLATES,
# and ANNOTATORS exactly.
_KNOWN_FOCUS = set(FOCUS_DOCS.keys()) | {"General (full analysis)"}

# Map common free-text variations to canonical keys.
_FOCUS_ALIASES = {
    "audio streaming (a2dp / le audio)": "Audio",
    "audio streaming":                   "Audio",
    "a2dp":                              "Audio / A2DP",
    "le audio":                          "Audio / LE Audio",
    "hfp":                               "Audio / HFP",
    "connection":                        "Connection issues",
    "connections":                       "Connection issues",
    "pairing":                           "Pairing / Security",
    "security":                          "Pairing / Security",
    "smp":                               "Pairing / Security",
    "gatt":                              "GATT discovery",
    "advertising":                       "Advertising / Scanning",
    "scanning":                          "Advertising / Scanning",
    "l2cap":                             "L2CAP channel issues",
    "disconnect":                        "Disconnection analysis",
    "disconnection":                     "Disconnection analysis",
    "general":                           "General (full analysis)",
    "channel sounding":                  "Channel Sounding",
    "cs":                                "Channel Sounding",
    "ranging":                           "Channel Sounding",
    "ras":                               "Channel Sounding",
}


def normalize_focus(raw):
    """Map user-provided focus string to a canonical focus area key.

    If the string is already a known key, return it unchanged.
    Otherwise, try case-insensitive alias matching, then substring
    matching against known keys.  Falls back to General if nothing
    matches.
    """
    if raw in _KNOWN_FOCUS:
        return raw

    lower = raw.lower().strip()

    # Exact alias match (case-insensitive)
    if lower in _FOCUS_ALIASES:
        return _FOCUS_ALIASES[lower]

    # Substring match: e.g. "Audio streaming (A2DP / LE Audio)"
    # contains "a2dp" and "le audio"
    for alias, canonical in sorted(_FOCUS_ALIASES.items(),
                                   key=lambda x: -len(x[0])):
        if alias in lower:
            return canonical

    # Substring match against canonical keys
    for key in _KNOWN_FOCUS:
        if key.lower() in lower or lower in key.lower():
            return key

    log(f"Warning: unrecognized focus '{raw}', using General")
    return "General (full analysis)"


def load_docs(docs_path, focus=None):
    """Load btmon documentation as knowledge base context.

    When a specific focus area is given and matching split doc files
    exist, load only the focus-specific file(s) instead of the full
    btmon.rst.  This avoids truncating relevant content when the
    context window is small (e.g. GitHub Models free tier).
    """
    docs_dir = os.path.dirname(docs_path)

    # Try focus-specific docs first
    if focus and focus in FOCUS_DOCS:
        parts = []
        for name in FOCUS_DOCS[focus]:
            path = os.path.join(docs_dir, name)
            try:
                with open(path, "r") as f:
                    parts.append(f.read())
                log(f"Loaded focus docs: {name}")
            except FileNotFoundError:
                log(f"Warning: focus doc not found: {path}")
        if parts:
            return "\n\n".join(parts)
        log("Focus docs not found, falling back to full btmon.rst")

    # Fallback: load the main btmon.rst
    try:
        with open(docs_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        log(f"Warning: docs not found at {docs_path}")
        return ""


def build_prompt(decoded_text, docs_text, description, focus,
                 auto_detected=False, absence_errors=None,
                 btmon_stats=None):
    """Build the analysis prompt for the LLM."""
    clip_note = ""
    if "=== Prefiltered btmon log:" in decoded_text:
        clip_note = (
            "\n\nNote: The trace below has been prefiltered into three "
            "clearly separated sections:"
            "\n1. A SUMMARY HEADER with packet counts, time span, and "
            "diagnostics."
            "\n2. An ANNOTATIONS section containing a key event timeline "
            "and per-packet decoded meanings with protocol tags "
            "(e.g. [ASCS | ASE_CP], [CIS | HCI]). These are semantic "
            "labels produced by the analyzer — use them to understand "
            "what each packet does."
            "\n3. A RAW TRACE section containing the actual btmon packet "
            "output (headers and bodies) with no annotation markers "
            "mixed in. Lines like '[... N packets skipped ...]' indicate "
            "omitted bulk data (e.g. ISO streaming packets)."
            "\n\nCross-reference the annotations with the raw trace using "
            "frame numbers (e.g. #4, #22) to understand each packet."
            "\n\nIMPORTANT for verdict: A trace where all operations "
            "succeed (Status: Success), streaming completes normally, "
            "and the connection ends with a graceful disconnect "
            "(Remote User Terminated / Connection Terminated By Local "
            "Host) is a PASS — not a failure. Normal ISO/CIS data "
            "streaming volume is expected for LE Audio and is not an "
            "issue. Only report actual errors, rejects, or unexpected "
            "disconnections as issues."
        )
    elif auto_detected:
        clip_note = (
            "\n\nNote: The focus area was auto-detected from error "
            "patterns in the trace. The trace below has been clipped to "
            "show only the sections relevant to the detected problem "
            "area, with surrounding context packets preserved. Lines "
            "marked '[... N lines skipped ...]' indicate gaps between "
            "relevant sections."
        )
    if absence_errors:
        hints = "\n".join(f"  - {msg}" for msg in absence_errors)
        clip_note += (
            "\n\nThe analyzer identified these protocol-flow "
            "issues:\n"
            f"{hints}\n"
            "Investigate these as likely root causes."
        )

    system_prompt = f"""You are a Bluetooth protocol analyst specializing in \
BlueZ btmon trace analysis. You have deep knowledge of HCI, L2CAP, ATT/GATT, \
SMP, and LE Audio protocols.

The following documentation describes btmon output format, protocol flows, \
error codes, and analysis techniques:

<btmon-documentation>
{docs_text}
</btmon-documentation>

Your task is to analyze a decoded btsnoop trace and produce a diagnostic \
report. Be specific — reference actual handle values, opcodes, error codes, \
and timestamps from the trace. Identify the root cause when possible.{clip_note}

Format your report in GitHub-flavored markdown."""

    # Append btmon --analyze statistics as user context
    stats_section = ""
    if btmon_stats is not None:
        stats_section = (
            "\n\n## btmon Statistics\n\n"
            "The following per-connection and per-channel statistics "
            "were computed by btmon --analyze.  Use these authoritative "
            "throughput, latency, and packet-count figures in your "
            "analysis instead of trying to compute them from individual "
            "packets.\n\n```\n"
            f"{btmon_stats.format_summary()}\n```")

    # Get the structured output template for this focus area
    output_instructions = template_instructions(focus, auto_detected)

    user_prompt = f"""## Analysis Request

**User description:** {description}
**Focus area:** {focus}
{stats_section}

## Decoded btsnoop trace

```
{decoded_text}
```

## Output format

{output_instructions}"""

    return system_prompt, user_prompt


class LLMError(Exception):
    """Raised when an LLM API call fails."""


def call_openai(system_prompt, user_prompt, model=None):
    """Call OpenAI API."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise LLMError("OPENAI_API_KEY not set")

    model = model or "gpt-4o"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 4096,
        "temperature": 0.2,
    }).encode()

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise LLMError(f"OpenAI API error {e.code}: {body[:500]}")
    except urllib.error.URLError as e:
        raise LLMError(f"OpenAI API connection error: {e}")


def call_anthropic(system_prompt, user_prompt, model=None):
    """Call Anthropic API."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise LLMError("ANTHROPIC_API_KEY not set")

    model = model or "claude-sonnet-4-20250514"
    payload = json.dumps({
        "model": model,
        "max_tokens": 4096,
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read())
        return data["content"][0]["text"]
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise LLMError(f"Anthropic API error {e.code}: {body[:500]}")
    except urllib.error.URLError as e:
        raise LLMError(f"Anthropic API connection error: {e}")


def call_github(system_prompt, user_prompt, model=None):
    """Call GitHub Models API.

    Requires a PAT with models:read scope stored as GH_MODELS_TOKEN,
    or falls back to GITHUB_TOKEN (which may not have Models access).
    """
    token = os.environ.get("GH_MODELS_TOKEN") or \
        os.environ.get("GITHUB_TOKEN")
    if not token:
        raise LLMError(
            "GH_MODELS_TOKEN (or GITHUB_TOKEN) not set")

    model = model or "openai/gpt-4o-mini"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 4096,
        "temperature": 0.2,
    }).encode()

    req = urllib.request.Request(
        "https://models.github.ai/inference/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        msg = f"GitHub Models API error {e.code}: {body[:500]}"
        if e.code in (401, 403):
            msg += (
                "\nHint: The built-in GITHUB_TOKEN may not have access "
                "to GitHub Models. Create a PAT with 'models:read' "
                "scope and store it as the GH_MODELS_TOKEN repository "
                "secret.")
        raise LLMError(msg)
    except urllib.error.URLError as e:
        raise LLMError(f"GitHub Models API connection error: {e}")


PROVIDERS = {
    "openai": call_openai,
    "anthropic": call_anthropic,
    "github": call_github,
}


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a btsnoop trace with LLM assistance"
    )
    parser.add_argument(
        "--trace-url", required=True,
        help="URL to download the btsnoop trace file"
    )
    parser.add_argument(
        "--description", default="No description provided",
        help="User's description of the issue"
    )
    parser.add_argument(
        "--focus", default="General (full analysis)",
        help="Analysis focus area"
    )
    parser.add_argument(
        "--anonymize", action="store_true",
        help="Anonymize MAC addresses in decoded output"
    )
    parser.add_argument(
        "--provider", default="openai", choices=PROVIDERS.keys(),
        help="LLM provider to use"
    )
    parser.add_argument(
        "--model", default=None,
        help="Override the default model for the chosen provider"
    )
    parser.add_argument(
        "--btmon-path", default="./bluez/monitor/btmon",
        help="Path to btmon binary"
    )
    parser.add_argument(
        "--docs-path", default="./bluez/doc/btmon.rst",
        help="Path to btmon.rst documentation"
    )
    parser.add_argument(
        "--output", default=None,
        help="Write LLM analysis to file instead of stdout"
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Directory for per-step output files "
             "(detect.md, annotate.md, analyze.md)"
    )
    args = parser.parse_args()


    # Download trace
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
        trace_path = tmp.name
    download_trace(args.trace_url, trace_path)

    # Decode
    decoded = decode_trace(args.btmon_path, trace_path)

    # Run btmon --analyze for statistical summary (before deleting trace)
    btmon_stats = analyze_trace(args.btmon_path, trace_path)

    os.unlink(trace_path)

    if not decoded.strip():
        log("Error: btmon produced no output")
        sys.exit(1)

    # Anonymize if requested
    if args.anonymize:
        decoded = anonymize_output(decoded)

    # Provider-specific context limits (in chars, ~4 chars per token).
    # GitHub Models free tier (gpt-4o-mini): 8K tokens input total.
    # Reserve ~1.5K tokens for system prompt and ~600 tokens for template
    # instructions.  With docs at 4K chars (~1K tokens), that totals
    # ~3.1K tokens of overhead.  The remaining ~4.9K tokens (~16K chars
    # at ~3.3 chars/token for btmon traces) goes to the trace.
    CONTEXT_LIMITS = {
        "github":    {"trace": 16000, "docs": 4000},
        "openai":    {"trace": 100000, "docs": 50000},
        "anthropic": {"trace": 100000, "docs": 50000},
    }
    limits = CONTEXT_LIMITS.get(args.provider, CONTEXT_LIMITS["openai"])

    focus = normalize_focus(args.focus)
    if focus != args.focus:
        log(f"Normalized focus: '{args.focus}' -> '{focus}'")
    auto_detected = False
    auto_detected_focus = None
    absence_errors = []
    detect_results = []

    def write_step(name, content):
        """Write per-step output if --output-dir is set."""
        if args.output_dir:
            path = os.path.join(args.output_dir, f"{name}.md")
            with open(path, "w") as f:
                f.write(content)
            log(f"Step output written to {path}")

    # --- Step 1: Detection ---
    # Always run detection to get area scores and coexistence info.
    # When focus is General, auto-detect picks the best area.
    # When user provides a focus, detection still runs for diagnostics.
    log("Running detection on decoded trace...")
    detect_results = detect(decoded)
    if detect_results:
        for det in detect_results:
            marker = " ** ERRORS **" if det.has_errors else ""
            log(f"  {det.area.name:15s}  score={det.score:4d}  "
                f"activity={det.activity_count}  "
                f"errors={det.error_count}{marker}")
            for msg in det.absence_errors:
                log(f"  {'':15s}  ABSENCE: {msg}")

    if focus == "General (full analysis)":
        if detect_results:
            # Use select_focus() for smarter area selection:
            # prefers audio over background, detects coexistence
            focus, absence_errors, coexistence = \
                select_focus(detect_results)
            auto_detected = True
            auto_detected_focus = focus
            log(f"Auto-detected focus: {focus}")
            for note in coexistence:
                log(f"  COEXISTENCE: {note}")
                absence_errors.append(f"COEXISTENCE: {note}")
        else:
            log("No specific protocol area detected, using full trace")
    else:
        # User provided a focus — still check for coexistence
        if detect_results:
            by_name = {d.area.name: d for d in detect_results}
            from detect import _check_adv_coexistence, _AUDIO_AREAS
            # Find the detected area(s) matching the user's focus
            coexistence = []
            if focus == "Audio":
                # Combined Audio focus — check coexistence against
                # all active audio areas
                audio_areas = [d for d in detect_results
                               if d.area.name in _AUDIO_AREAS]
                if audio_areas:
                    _check_adv_coexistence(
                        by_name, audio_areas, coexistence)
            else:
                focus_area = next(
                    (d for d in detect_results if d.area.focus == focus),
                    None)
                if focus_area:
                    _check_adv_coexistence(
                        by_name, focus_area, coexistence)
            for note in coexistence:
                log(f"  COEXISTENCE: {note}")
                absence_errors.append(f"COEXISTENCE: {note}")

    # Write detection comment
    detect_md = detect_markdown(
        detect_results, focus, auto_detected_focus=auto_detected_focus)
    write_step("detect", detect_md)

    # --- Step 2: Filter ---
    # --- Step 3: Annotation ---
    annotated_packets = []
    annotator_diags = []
    filter_trace_chars = 0

    # Clip the log to the relevant section for the focus area.
    # Use the annotator-based prefilter when available — it does
    # protocol-aware packet annotation and budget-aware filtering.
    # Fall back to pattern-based clip_for_focus for areas without
    # a dedicated annotator, or truncate_for_context for General.
    if focus != "General (full analysis)":
        # First run annotation to get packets and diags for the
        # annotation comment, then build the prefiltered log
        annotated_packets, annotator_diags, annotator_found = \
            annotate_trace(decoded, focus)

        if annotator_found and (annotator_diags or annotated_packets):
            # Build prefiltered log from already-annotated packets
            prefiltered, _ = prefilter(
                decoded, focus, max_chars=limits["trace"],
                packets=annotated_packets, diags=annotator_diags)
            original_len = len(decoded)
            decoded = prefiltered
            filter_trace_chars = len(decoded)
            absence_errors = absence_errors + annotator_diags
            log(f"Prefiltered trace: {len(decoded)} chars "
                f"({len(decoded) * 100 // original_len}% of "
                f"{original_len} chars), "
                f"{len(annotator_diags)} annotator diagnostics")
        else:
            # No annotator for this area — try pattern-based clipping
            clipped = clip_for_focus(decoded, focus,
                                     max_chars=limits["trace"])
            if clipped != decoded:
                original_len = len(decoded)
                decoded = clipped
                filter_trace_chars = len(decoded)
                log(f"Clipped trace: {len(decoded)} chars "
                    f"({len(decoded) * 100 // original_len}% of "
                    f"{original_len} chars)")
            else:
                decoded = truncate_for_context(decoded,
                                               max_chars=limits["trace"])
                filter_trace_chars = len(decoded)
    else:
        decoded = truncate_for_context(decoded,
                                        max_chars=limits["trace"])
        filter_trace_chars = len(decoded)

    # Write filter comment (Step 2)
    filter_md = filter_markdown(
        annotated_packets, focus, filter_trace_chars, limits["trace"],
        prefiltered_text=decoded)
    write_step("filter", filter_md)

    # Write annotation comment (Step 3)
    annotate_md = annotate_markdown(annotated_packets, focus)
    write_step("annotate", annotate_md)

    # Write diagnostics comment (Step 4)
    diagnose_md = diagnostics_markdown(annotated_packets, annotator_diags)
    write_step("diagnose", diagnose_md)

    # --- Step 5: LLM Analysis ---
    # Load docs (focus-specific when available)
    docs = load_docs(args.docs_path, focus=focus)
    docs = truncate_for_context(docs, max_chars=limits["docs"])

    log(f"Trace: {len(decoded)} chars, Docs: {len(docs)} chars "
        f"(limits: {limits})")

    # Build prompt and call LLM
    system_prompt, user_prompt = build_prompt(
        decoded, docs, args.description, focus,
        auto_detected=auto_detected,
        absence_errors=absence_errors,
        btmon_stats=btmon_stats,
    )

    log(f"Sending to {args.provider} for analysis...")
    provider_fn = PROVIDERS[args.provider]
    try:
        analysis = provider_fn(system_prompt, user_prompt, args.model)
    except LLMError as e:
        log(f"LLM analysis failed: {e}")
        analysis = (
            "## Step 5: LLM Analysis\n\n"
            "> **LLM analysis unavailable** — the API call failed.\n"
            "> Steps 1-4 (detection, filtering, annotation, "
            "diagnostics) completed successfully.\n\n"
            "<details>\n<summary>Error details</summary>\n\n"
            f"```\n{e}\n```\n\n"
            "To enable LLM analysis, create a "
            "[Personal Access Token](https://github.com/settings/tokens) "
            "with `models:read` scope and add it as a repository secret "
            "named `GH_MODELS_TOKEN`.\n"
            "</details>"
        )
        if args.output_dir:
            write_step("analyze", analysis)
        if args.output:
            with open(args.output, "w") as f:
                f.write(analysis)
            log(f"Analysis (error) written to {args.output}")
        elif not args.output_dir:
            print(analysis)
        return

    # Strip <output-template> wrapper that some LLMs echo back
    analysis = re.sub(
        r"^\s*<output-template>\s*\n?", "", analysis)
    analysis = re.sub(
        r"\n?\s*</output-template>\s*$", "", analysis)

    # Wrap in a "Step 5" heading for consistency when using --output-dir
    if args.output_dir:
        analysis = f"## Step 5: LLM Analysis\n\n{analysis}"

    # Output
    if args.output_dir:
        write_step("analyze", analysis)
    if args.output:
        with open(args.output, "w") as f:
            f.write(analysis)
        log(f"Analysis written to {args.output}")
    elif not args.output_dir:
        print(analysis)


if __name__ == "__main__":
    main()
