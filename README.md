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
│   │   └── analyze-trace.yml    # Issue template with trace upload form
│   └── workflows/
│       └── analyze-trace.yml    # GitHub Actions workflow
├── scripts/
│   ├── analyze.py               # Main analysis script
│   └── anonymize.sh             # MAC address anonymization
└── README.md
```

## Analysis Report Format

The LLM produces a structured report with:

- **Summary** — What happened in 1-3 sentences
- **Connection Timeline** — Key events in chronological order
- **Protocol Analysis** — Detailed analysis of the focus area with specific
  handle values, opcodes, and error codes
- **Issues Found** — Errors, unexpected behavior, or protocol violations
- **Recommendations** — Actionable debugging suggestions

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
