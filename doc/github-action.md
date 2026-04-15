# Using btsnoop-analyzer as a GitHub Action

btsnoop-analyzer can be used as a reusable GitHub Action in any
repository. The action runs the full 5-step analysis pipeline and
produces markdown result files that your workflow can use however you
like -- post as issue comments, upload as artifacts, include in PR
reviews, etc.

## Quick Start

Add btsnoop-analyzer to any workflow:

```yaml
name: Analyze Bluetooth trace

on:
  issues:
    types: [opened]

permissions:
  issues: write
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - name: Analyze trace
        id: analyze
        uses: Vudentz/btsnoop-analyzer@master
        with:
          trace-url: 'https://example.com/trace.log'
          description: 'Audio disconnects after 30 seconds'
          focus: 'Audio / A2DP'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Post results as issue comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const analysis = fs.readFileSync('${{ steps.analyze.outputs.analyze }}', 'utf8');
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: analysis
            });
```

## Inputs

| Input | Required | Default | Description |
|-------|:--------:|---------|-------------|
| `trace-url` | **Yes** | -- | URL to the btsnoop trace file (`.log`, `.snoop`, `.btsnoop`, `.cfa`) |
| `description` | No | `No description provided` | User description of the scenario |
| `focus` | No | `General (full analysis)` | Analysis focus area (see [Focus Areas](#focus-areas)) |
| `anonymize` | No | `true` | Anonymize MAC addresses before LLM processing |
| `provider` | No | `github` | LLM provider: `github`, `openai`, or `anthropic` |
| `model` | No | Provider default | Override the default LLM model |
| `btmon-path` | No | Auto-built | Path to a pre-built btmon binary |
| `docs-path` | No | Auto-built | Path to btmon.rst documentation file |
| `output-dir` | No | `results` | Directory to write the result markdown files |
| `python-version` | No | `3.12` | Python version to use |

## Outputs

| Output | Description |
|--------|-------------|
| `output-dir` | Path to the directory containing all result files |
| `detect` | Path to `detect.md` (Step 1: Protocol detection) |
| `filter` | Path to `filter.md` (Step 2: Prefilter summary) |
| `annotate` | Path to `annotate.md` (Step 3: Packet annotation) |
| `diagnose` | Path to `diagnose.md` (Step 4: Diagnostics) |
| `analyze` | Path to `analyze.md` (Step 5: LLM analysis) |

## Focus Areas

The `focus` input accepts one of the following values:

- `General (full analysis)` -- auto-detect the problem area
- `Connection issues`
- `Controller enumeration`
- `Pairing / Security`
- `GATT discovery`
- `Audio`
- `Audio / LE Audio`
- `Audio / A2DP`
- `Audio / HFP`
- `L2CAP channel issues`
- `Advertising / Scanning`
- `Disconnection analysis`

## LLM Provider Configuration

The action requires an LLM API key passed as an environment variable.
Set secrets in your repository under **Settings > Secrets and
variables > Actions > Secrets**.

| Provider | `provider` value | Required env variable | Default model |
|----------|:----------------:|----------------------|:-------------:|
| GitHub Models | `github` | `GITHUB_TOKEN` (built-in) | `openai/gpt-4o` |
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-4o` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-20250514` |

**GitHub Models** is the simplest option -- it uses the built-in
`GITHUB_TOKEN` and requires no additional secrets.

### Using OpenAI or Anthropic

```yaml
- name: Analyze trace
  uses: Vudentz/btsnoop-analyzer@master
  with:
    trace-url: ${{ steps.parse.outputs.trace_url }}
    provider: openai
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Overriding the model

```yaml
- name: Analyze trace
  uses: Vudentz/btsnoop-analyzer@master
  with:
    trace-url: ${{ steps.parse.outputs.trace_url }}
    provider: github
    model: openai/gpt-4o-mini
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Examples

### `/analyze` slash command (recommended for external repos)

The simplest way to add btsnoop-analyzer to your repository. Users
comment `/analyze` on any issue to trigger analysis. Add this single
file to `.github/workflows/btsnoop-analyze.yml`:

```yaml
name: Analyze on mention

on:
  issue_comment:
    types: [created]

jobs:
  analyze:
    if: >-
      github.event.issue.pull_request == null &&
      contains(github.event.comment.body, '/analyze')
    uses: Vudentz/btsnoop-analyzer/.github/workflows/analyze-on-mention.yml@master
    secrets: inherit
```

The reusable workflow handles everything: parsing the command,
finding the trace URL, running the 5-step pipeline, and posting
results as issue comments.

Supported command forms:
- `/analyze` -- find trace URL in the comment or issue body
- `/analyze <url>` -- analyze a specific trace URL
- `/analyze --focus "Audio / LE Audio"` -- specify focus area
- `/analyze <url> --focus "Audio / A2DP"` -- both URL and focus

### Issue-triggered analysis with all 5 comments

This is the most common pattern -- replicate the behavior of the
btsnoop-analyzer repository in your own project:

```yaml
name: Analyze btsnoop trace

on:
  issues:
    types: [opened, reopened]

permissions:
  issues: write
  contents: read

jobs:
  analyze:
    if: contains(github.event.issue.body, '.log') || contains(github.event.issue.body, '.snoop')
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - name: Parse issue body
        id: parse
        uses: actions/github-script@v7
        with:
          script: |
            const body = context.payload.issue.body || '';
            const urlPatterns = [
              /https:\/\/github\.com\/[^\s)]+\.(?:log|snoop|btsnoop|cfa)/gi,
              /https:\/\/github\.com\/user-attachments\/(?:files|assets)\/[^\s)]+/gi,
            ];
            let traceUrl = '';
            for (const pattern of urlPatterns) {
              const match = body.match(pattern);
              if (match) { traceUrl = match[0]; break; }
            }
            if (!traceUrl) {
              core.setFailed('No trace file URL found in issue body');
              return;
            }
            core.setOutput('trace_url', traceUrl);

      - name: Post analyzing comment
        uses: actions/github-script@v7
        with:
          script: |
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: '**btsnoop Analyzer** is processing your trace...'
            });

      - name: Analyze trace
        id: analyze
        uses: Vudentz/btsnoop-analyzer@master
        with:
          trace-url: ${{ steps.parse.outputs.trace_url }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Post results
        if: success()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const files = ['detect.md', 'filter.md', 'annotate.md', 'diagnose.md', 'analyze.md'];
            for (const file of files) {
              const content = fs.readFileSync(`${{ steps.analyze.outputs.output-dir }}/${file}`, 'utf8');
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: content
              });
            }
```

### Pull request annotation

Analyze a trace attached to a PR and post a summary review comment:

```yaml
name: Trace review

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  pull-requests: write
  contents: read

jobs:
  review:
    if: contains(github.event.pull_request.body, '.log')
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - name: Extract trace URL
        id: parse
        uses: actions/github-script@v7
        with:
          script: |
            const body = context.payload.pull_request.body || '';
            const match = body.match(/https:\/\/github\.com\/[^\s)]+\.(?:log|snoop|btsnoop|cfa)/i);
            if (match) core.setOutput('trace_url', match[0]);
            else core.setFailed('No trace URL found');

      - name: Analyze trace
        id: analyze
        uses: Vudentz/btsnoop-analyzer@master
        with:
          trace-url: ${{ steps.parse.outputs.trace_url }}
          focus: 'General (full analysis)'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Post review comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const analysis = fs.readFileSync('${{ steps.analyze.outputs.analyze }}', 'utf8');
            await github.rest.pulls.createReview({
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_number: context.issue.number,
              body: analysis,
              event: 'COMMENT'
            });
```

### Upload results as artifacts

Save analysis results as downloadable workflow artifacts:

```yaml
- name: Analyze trace
  id: analyze
  uses: Vudentz/btsnoop-analyzer@master
  with:
    trace-url: 'https://example.com/trace.log'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- name: Upload results
  uses: actions/upload-artifact@v4
  with:
    name: trace-analysis
    path: ${{ steps.analyze.outputs.output-dir }}
```

### Using a pre-built btmon

If your workflow already has btmon available (e.g., from a BlueZ CI
pipeline), skip the automatic build by providing `btmon-path`:

```yaml
- name: Analyze trace
  uses: Vudentz/btsnoop-analyzer@master
  with:
    trace-url: 'https://example.com/trace.log'
    btmon-path: ./bluez/monitor/btmon
    docs-path: ./bluez/doc/btmon.rst
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This saves ~2 minutes of build time per run.

## How It Works

The action runs a 5-step pipeline:

| Step | Output | LLM | Description |
|:----:|--------|:---:|-------------|
| 1 | `detect.md` | No | Auto-detect protocol area by scoring pattern matches |
| 2 | `filter.md` | No | Budget-aware trace filtering (key/context/skip) |
| 3 | `annotate.md` | No | Parse packets, apply annotators with semantic tags |
| 4 | `diagnose.md` | No | Format diagnostics: disconnects, warnings, summaries |
| 5 | `analyze.md` | **Yes** | LLM-generated structured diagnostic report |

Steps 1-4 are fully deterministic (no LLM). Step 5 sends the
prefiltered trace and BlueZ documentation to the configured LLM
with a structured fill-in-the-blank template.

For full pipeline details, see [ARCHITECTURE.md](../ARCHITECTURE.md).

## Privacy

btsnoop traces contain Bluetooth MAC addresses and may contain device
names. By default (`anonymize: true`), the action replaces all MAC
addresses with sequential pseudonyms (`00:00:00:00:00:01`, etc.)
before sending data to the LLM. Set `anonymize: false` to send raw
addresses for more accurate analysis.

**Note:** The raw trace file at `trace-url` is not modified. Only the
decoded text sent to the LLM is anonymized.

## Requirements

- **Runner:** `ubuntu-latest` (or any Ubuntu-based runner with `apt-get`)
- **Timeout:** Allow at least 10-15 minutes (btmon build takes ~2 min,
  analysis takes 1-3 min)
- **LLM access:** At least one of the supported LLM provider
  credentials must be available as environment variables

## Limitations

- The action builds btmon from source on every run unless `btmon-path`
  is provided. Consider caching the BlueZ build for faster runs.
- Only runs on Linux (Ubuntu) runners due to BlueZ build dependencies.
- Large trace files may exceed the LLM's context window. The prefilter
  step handles this automatically but very large traces will have more
  aggressive filtering.
