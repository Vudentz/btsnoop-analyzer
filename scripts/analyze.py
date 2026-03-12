#!/usr/bin/env python3
"""
analyze.py - btsnoop trace analyzer

Downloads a btsnoop trace from a GitHub issue, decodes it with btmon,
optionally anonymizes the output, and sends it to an LLM for analysis
using the btmon documentation as a knowledge base.

Usage:
    python3 scripts/analyze.py \
        --trace-url URL \
        --description "user description" \
        --focus "General" \
        --anonymize \
        --provider openai \
        --btmon-path ./bluez/monitor/btmon \
        --docs-path ./bluez/doc/btmon.rst

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
    "Pairing / Security": ["btmon-smp.rst"],
    "GATT discovery": ["btmon-gatt.rst"],
    "Audio streaming (A2DP / LE Audio)": ["btmon-le-audio.rst"],
    "L2CAP channel issues": ["btmon-l2cap.rst"],
    "Advertising / Scanning": ["btmon-advertising.rst"],
    "Disconnection analysis": ["btmon-connections.rst"],
}


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


def build_prompt(decoded_text, docs_text, description, focus):
    """Build the analysis prompt for the LLM."""
    system_prompt = f"""You are a Bluetooth protocol analyst specializing in \
BlueZ btmon trace analysis. You have deep knowledge of HCI, L2CAP, ATT/GATT, \
SMP, and LE Audio protocols.

The following documentation describes btmon output format, protocol flows, \
error codes, and analysis techniques:

<btmon-documentation>
{docs_text}
</btmon-documentation>

Your task is to analyze a decoded btsnoop trace and provide a structured \
report. Be specific — reference actual handle values, opcodes, error codes, \
and timestamps from the trace. Identify the root cause when possible.

Format your report in GitHub-flavored markdown."""

    user_prompt = f"""## Analysis Request

**User description:** {description}
**Focus area:** {focus}

## Decoded btsnoop trace

```
{decoded_text}
```

## Instructions

Analyze this trace and provide a report with these sections:

### Summary
Brief overview of what happened in the trace (1-3 sentences).

### Connection Timeline
Key events in chronological order with timestamps.

### Protocol Analysis
Detailed analysis focused on "{focus}". Reference specific handles, \
opcodes, CIDs, and error codes from the trace.

### Issues Found
Any errors, unexpected behavior, or protocol violations. For each issue:
- What happened (with timestamp and specific values)
- Why it matters
- Possible root cause

### Recommendations
Actionable suggestions for debugging or resolving the identified issues."""

    return system_prompt, user_prompt


def call_openai(system_prompt, user_prompt, model=None):
    """Call OpenAI API."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        log("OPENAI_API_KEY not set")
        sys.exit(1)

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
        log(f"OpenAI API error {e.code}: {body[:500]}")
        sys.exit(1)
    except urllib.error.URLError as e:
        log(f"OpenAI API connection error: {e}")
        sys.exit(1)


def call_anthropic(system_prompt, user_prompt, model=None):
    """Call Anthropic API."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        log("ANTHROPIC_API_KEY not set")
        sys.exit(1)

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
        log(f"Anthropic API error {e.code}: {body[:500]}")
        sys.exit(1)
    except urllib.error.URLError as e:
        log(f"Anthropic API connection error: {e}")
        sys.exit(1)


def call_github(system_prompt, user_prompt, model=None):
    """Call GitHub Models API.

    Requires a PAT with models:read scope stored as GH_MODELS_TOKEN,
    or falls back to GITHUB_TOKEN (which may not have Models access).
    """
    token = os.environ.get("GH_MODELS_TOKEN") or \
        os.environ.get("GITHUB_TOKEN")
    if not token:
        log("GH_MODELS_TOKEN (or GITHUB_TOKEN) not set")
        sys.exit(1)

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
        log(f"GitHub Models API error {e.code}: {body[:500]}")
        if e.code in (401, 403):
            log("Hint: The built-in GITHUB_TOKEN may not have access to "
                "GitHub Models. Create a PAT with 'models:read' scope and "
                "store it as the GH_MODELS_TOKEN repository secret.")
        sys.exit(1)
    except urllib.error.URLError as e:
        log(f"GitHub Models API connection error: {e}")
        sys.exit(1)


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
        help="Write analysis to file instead of stdout"
    )
    args = parser.parse_args()


    # Download trace
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
        trace_path = tmp.name
    download_trace(args.trace_url, trace_path)

    # Decode
    decoded = decode_trace(args.btmon_path, trace_path)
    os.unlink(trace_path)

    if not decoded.strip():
        log("Error: btmon produced no output")
        sys.exit(1)

    # Anonymize if requested
    if args.anonymize:
        decoded = anonymize_output(decoded)

    # Provider-specific context limits (in chars, ~4 chars per token).
    # GitHub Models free tier (gpt-4o-mini): 8K tokens input total.
    # Reserve ~1K tokens for system prompt template + formatting overhead.
    # That leaves ~7K tokens (~28K chars) shared between docs and trace.
    CONTEXT_LIMITS = {
        "github":    {"trace": 24000, "docs": 4000},
        "openai":    {"trace": 100000, "docs": 50000},
        "anthropic": {"trace": 100000, "docs": 50000},
    }
    limits = CONTEXT_LIMITS.get(args.provider, CONTEXT_LIMITS["openai"])

    # Truncate for context window
    decoded = truncate_for_context(decoded, max_chars=limits["trace"])

    # Load docs (focus-specific when available)
    docs = load_docs(args.docs_path, focus=args.focus)
    docs = truncate_for_context(docs, max_chars=limits["docs"])

    log(f"Trace: {len(decoded)} chars, Docs: {len(docs)} chars "
        f"(limits: {limits})")

    # Build prompt and call LLM
    system_prompt, user_prompt = build_prompt(
        decoded, docs, args.description, args.focus
    )

    log(f"Sending to {args.provider} for analysis...")
    provider_fn = PROVIDERS[args.provider]
    analysis = provider_fn(system_prompt, user_prompt, args.model)

    # Output
    if args.output:
        with open(args.output, "w") as f:
            f.write(analysis)
        log(f"Analysis written to {args.output}")
    else:
        print(analysis)


if __name__ == "__main__":
    main()
