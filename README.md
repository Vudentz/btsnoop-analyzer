# btsnoop-analyzer

Automated Bluetooth HCI trace analysis powered by LLMs. Upload a btsnoop
trace via a GitHub issue and get a structured protocol analysis posted as a
comment.

## How It Works

1. **Open an issue** using the "Analyze btsnoop trace" template
2. **Attach your trace file** (`.log`, `.snoop`, `.btsnoop`, or `.cfa`)
3. **Describe the scenario** and pick a focus area
4. A GitHub Actions workflow automatically:
   - Clones [BlueZ](https://git.kernel.org/pub/scm/bluetooth/bluez.git) and
     builds `btmon`
   - Decodes the trace with `btmon -r`
   - Optionally anonymizes MAC addresses and device names
   - Sends the decoded output + [btmon documentation](https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/btmon.rst)
     to an LLM for analysis
   - Posts the analysis report as a comment on your issue

## Setup

### 1. Create the repository

Fork or use this repo as a template on GitHub.

### 2. Configure an LLM provider

Set the `LLM_PROVIDER` repository variable (Settings > Secrets and
variables > Actions > Variables) to one of:

| Provider    | Variable value | Required secret        | Default model           |
|-------------|---------------|------------------------|-------------------------|
| GitHub Models | `github`    | `GITHUB_TOKEN` (built-in) | `openai/gpt-4o`      |
| OpenAI      | `openai`      | `OPENAI_API_KEY`       | `gpt-4o`                |
| Anthropic   | `anthropic`   | `ANTHROPIC_API_KEY`    | `claude-sonnet-4-20250514` |

**GitHub Models** is the default and requires no additional secrets — it uses
the built-in `GITHUB_TOKEN`.

To override the model, set the `LLM_MODEL` repository variable (e.g.,
`gpt-4o-mini`, `claude-sonnet-4-20250514`).

### 3. Add API keys (if not using GitHub Models)

Go to Settings > Secrets and variables > Actions > Secrets and add:
- `OPENAI_API_KEY` — for the OpenAI provider
- `ANTHROPIC_API_KEY` — for the Anthropic provider

## Privacy

btsnoop traces contain Bluetooth MAC addresses and may contain device names
or other identifiable information.

By default, the analyzer **anonymizes** MAC addresses before sending the
decoded trace to the LLM. Each unique address is replaced with a sequential
pseudonym (`00:00:00:00:00:01`, `00:00:00:00:00:02`, ...) so device
relationships are preserved while actual addresses are hidden.

Users can opt out of anonymization via a checkbox in the issue template if
they need the raw addresses for more accurate analysis.

**Note:** Even with anonymization, the raw trace file is publicly visible
in the GitHub issue attachment. Users should not upload traces containing
sensitive data they don't want public.

## Local Usage

You can run the analyzer locally without GitHub Actions:

```bash
# Clone and build btmon
git clone --depth 1 https://git.kernel.org/pub/scm/bluetooth/bluez.git
cd bluez && ./bootstrap-configure && make monitor/btmon && cd ..

# Run analysis
export OPENAI_API_KEY="sk-..."  # or ANTHROPIC_API_KEY, etc.
python3 scripts/analyze.py \
  --trace-url https://example.com/trace.log \
  --description "Audio disconnects after 30s" \
  --focus "Audio streaming (A2DP / LE Audio)" \
  --anonymize \
  --provider openai \
  --btmon-path ./bluez/monitor/btmon \
  --docs-path ./bluez/doc/btmon.rst
```

Or decode a local file directly:

```bash
# Decode the trace
./bluez/monitor/btmon -r /path/to/trace.log > decoded.txt

# Anonymize (optional)
./scripts/anonymize.sh < decoded.txt > decoded-anon.txt
```

## Repository Structure

```
btsnoop-analyzer/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   └── analyze-trace.yml    # Issue form: trace upload, description, focus
│   └── workflows/
│       └── analyze-trace.yml    # CI workflow: build btmon, run analysis, post comment
├── scripts/
│   ├── analyze.py               # Main entry: download, decode, anonymize, prompt, call LLM
│   ├── detect.py                # Auto-detection: area scoring, absence checks, log clipping
│   ├── annotate.py              # Packet parser + 8 focus-specific annotators + prefilter
│   ├── templates.py             # Structured output templates per focus area
│   └── anonymize.sh             # Shell-based MAC anonymization (standalone use)
├── ARCHITECTURE.md              # Pipeline architecture documentation
└── README.md
```

For a detailed walkthrough of how the analysis pipeline works — from
issue submission to posted diagnostic report — see
[ARCHITECTURE.md](ARCHITECTURE.md).

## Analysis Report Format

The LLM produces a structured report using focus-area-specific templates
(`scripts/templates.py`) that enforce consistent output. Each report includes:

- **Summary** — Verdict and one-line description
- **Protocol-Specific Tables** — Codec configuration, state transitions,
  connection parameters, etc. (varies by focus area)
- **Event Timeline** — Key events with timestamps and handle values
- **Issues Found** — Errors, protocol violations, absence-based issues
  (expected events that never occurred)
- **Recommendations** — Actionable debugging suggestions

When the user selects "General (full analysis)", the analyzer auto-detects
the relevant protocol area from error patterns and protocol activity in the
trace, then applies the matching template and documentation.

## Knowledge Base

The analysis uses BlueZ's
[doc/btmon.rst](https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/btmon.rst)
as context, which covers:

- HCI command/event format and connection tracking
- GATT database reconstruction from discovery sequences
- SMP pairing flows (Secure Connections and Legacy)
- L2CAP channel tracking and signaling
- LE Audio protocol flows (PACS, ASCS, CIS/BIG)
- Protocol error codes (ATT, L2CAP, HCI)
- Advertising and scanning

## License

LGPL-2.1 — Same as BlueZ.
