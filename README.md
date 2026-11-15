# VulnBench Python — JS 1.0

Executable Python port of the vulnerability detection workflow in [Snyk VulnBench](https://github.com/snyk-labs/snyk-vulnbench). The exact inspected revision is recorded in `UPSTREAM.json`. The upstream repository is unchanged. Original JavaScript fixture projects, V1 detection task JSON, model configurations, rule mappings, finding aliases, and default prompts are included. Upstream licensing is in `LICENSE.upstream`.

Scores measure **agreement with the selected reference set**, not independently established vulnerability correctness. Automatically generated Snyk findings are unreviewed reference candidates.

## Install and authenticate

Use Python 3.11+ on Linux or macOS. Work from this extracted project directory (the checkout is the supported distribution, including `evals/` and `fixtures/`).

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
```

Install the official Snyk CLI (`npm install -g snyk`), run `snyk auth`, and ensure the organization has Snyk Code enabled. `SNYK_TOKEN` may be used in automated environments. Reference preparation and baseline execution use the installed CLI directly without a shell.

Claude uses the **official `claude-agent-sdk` Python package**, including its Claude Code runtime, not ordinary Anthropic API calls. Authenticate Claude Code using its supported account login or set `ANTHROPIC_API_KEY`. Do not put credentials in config JSON. Linux sandbox execution requires Claude Code's supported sandbox dependencies, including bubblewrap and socat; follow Claude Code's installation instructions. Authentication and paid executions are the user's environment prerequisites.

## Three workflows

```bash
# Existing references are protected: this command refuses if findings.json exists.
python main.py generate-references --fixture js-project-tigerteam

# Explicit regeneration, preserving the prior reference in the scan artifacts:
python main.py generate-references --fixture js-project-tigerteam --overwrite

python main.py run --task js-project-tigerteam-find-vulns \
  --config claude-opus-4-6-medium --repetitions 5

python main.py run --task js-project-tigerteam-find-vulns \
  --config snyk-code --repetitions 5
```

The bundled tigerteam fixture already has upstream references, so generation requires `--overwrite`. This is intentional protection. For new fixtures, create `fixtures/NAME/project/` and invoke generation without overwrite. Raw SARIF, full stdout/stderr, invocation, exit status, generated candidates, and prior reference backups live under `results/references/`. SARIF rule IDs are available in the raw artifact, and normalized candidates retain type, location, severity, description, and stable IDs derived from fixture/rule/path/line plus duplicate occurrence. Result order is retained. `--include-ignores` explicitly broadens the scan. References include unreviewed provenance and an artifact hash; review them before treating them as curated. This command is new Python automation of upstream fixture-authoring Steps 2–4, not an existing upstream one-command feature.

Repeat `--task` and `--config` for a Cartesian experiment. Each repetition starts a fresh runner session and a fresh project copy. Repetitions and agent turns are independent. `--dry-run` validates selection and prints resolved prompts/configuration without invoking detectors. `--output PATH` selects the JSONL destination; otherwise a unique experiment file is created. Nonzero process status reports failed runs; failures remain in JSONL and are excluded from averages.

```bash
python main.py run --task js-project-tigerteam-find-vulns --config claude-opus-4-6-medium --repetitions 5 --dry-run
python main.py aggregate results/experiment-ID.jsonl
python main.py repeatability results/experiment-ID.jsonl
```

Use `python main.py --root PATH ...` for a separate fixture/config tree. Task JSON uses the original `fixture`, `category`, `systemPrompt`, `prompt`, and `maxTurns` fields; omitted prompts use `evals/prompts.json`, extracted verbatim from the pinned TypeScript `FIND_VULNS_DEFAULTS`. Task maxTurns takes precedence over configuration maxTurns, matching upstream.

Configure model runs in `evals/run-configs.json`: `model`, `effort`, `maxTurns`, `timeoutMs`, `allowedTools`, `systemPrompt`, `prompt`, optional `thinking`, and `structuredOutput`. Effort `default` delegates to the runtime; unsupported effort values fail explicitly. Structured output requests an object containing a `findings` array. Text mode supports the original fenced `FINDINGS_JSON` convention and V1 fallback extraction. Command configs support `executable` and `args`, with `{fixturePath}` substitution; legacy `command` is split without a shell. Only the Snyk Code parser is supported.

## Results and protocols

Each JSONL record includes task/fixture/config IDs, complete resolved task and configuration, reference SHA256, repetition, timestamp, final text, normalized findings, metrics, failure/error, and scoring details. Scoring includes TP/FP/FN, precision, recall, F1, per-finding reference assignments, unmatched findings, and type/severity breakdowns. Failed executions have `score: null`.

V1 scoring normalizes reported categories and greedily consumes the first unmatched reference of the same type, preserving both orders. File and line never participate. Duplicate reports are retained, and excess reports become false positives. With no reports precision is 0; with no references overall recall is 1; F1 is 0 if precision plus recall is 0. A zero-reference breakdown has recall 0, as upstream does.

Repeatability is separate: reference-matched recurrence uses reference IDs; unmatched recurrence uses normalized type + POSIX file + exact line within task/config. Duplicate occurrences count once per execution. Output retains unique signatures, frequency histograms, and once/several/all counts. `seen_all` means all **successful observed executions**; requested repetitions and successful count are both reported. Analyze one experiment JSONL at a time. Aggregation reports per-task/config mean precision/recall/F1, sample F1 standard deviation, duration, and success/failure counts.

SDK usage is saved as reported, including cache counters when present; cost and turns come from the SDK terminal result. Tool hooks record wall time and character-count/4 estimates separately from SDK token usage. Files accessed records only observable native filesystem tools. Bash file reads cannot be enumerated reliably. Snyk metrics retain stdout, stderr, status, duration, finding count, and files **referenced by findings**, not an assertion that these were its only scanned files. Valid Snyk vulnerability exit status 1 is accepted; malformed SARIF and operational statuses 2/3 fail rather than receive misleading zero scores.

## Isolation and differences

Only `project/` is copied into a unique temporary directory; fixture metadata and references are excluded. Workspaces are cleaned on success and exceptions. Symlinks are rejected to avoid copying external targets. The Claude runner disables user/project settings and unrelated MCP servers, restricts native file-tool paths with a hook, enables the CLI sandbox, forbids unsandboxed Bash fallbacks, and sends reference-directory read denial plus project read/write allowances through Claude Code settings. The Python SDK's typed SandboxSettings lacks the TypeScript filesystem field, so filesystem settings use the documented CLI settings interface. This relies on the installed CLI enforcing its sandbox; mocked tests do not establish operating-system containment. It is not a container or a defense against a hostile sandbox escape. For stronger isolation, run the detector in a dedicated container with only the project mounted and keep results/references on the host. SDK/runtime sandbox setup failures are recorded as failures; the runner does not retry unsandboxed.

The original JavaScript fixtures remain JavaScript. Fixing workflows, V2 scoring, model gateways, MCP prompt variants, and unrelated runners are intentionally outside this V1 port. Parser fallback follows V1 behavior, including its simple first-array regex. Invalid scanner output is handled more strictly than the permissive upstream parser. Partial tool calls without a post hook have no fabricated duration; interrupted SDK sessions may have no terminal usage. Dependency ranges should be locked for published experiments; record runtime versions alongside artifacts when comparing environments.

## Source mapping and verification

| TypeScript source | Python counterpart |
|---|---|
| `src/types.ts` | `vulnbench/models.py`, `evals/prompts.json` |
| `src/evals/loader.ts` | `vulnbench/config.py` |
| `src/isolated-workspace.ts` | `vulnbench/workspace.py` |
| `src/parsers/snyk-code.ts` | `vulnbench/parsers/snyk_sarif.py`, `rules.json` |
| Fixture authoring skill Steps 2–4 | `vulnbench/references/generate.py` (new automation) |
| `src/command-runner.ts`, `src/runners/snyk-command.ts` | `vulnbench/runners/snyk_code.py` |
| `src/runner.ts`, `src/runners/claude-code.ts` | `vulnbench/runners/claude_code.py`, `metrics.py` |
| `src/scorer.ts` | `vulnbench/scoring.py`, `parsers/claude_findings.py`, `aliases.json` |
| `src/index.ts`, result persistence | `main.py`, `experiment.py`, `storage.py` |
| `src/aggregator.ts` | `vulnbench/aggregation.py` (V1 subset) |
| JS 1.0 paper signature methodology | `vulnbench/repeatability.py` |

Tests cover mappings, SARIF, malformed output, fenced findings, duplicates, greedy matching, empty denominators, workspace cleanup/isolation, repetitions, CLI subprocess status/timeouts, reference generation/backups, baseline immutability, SDK option/usage handling, and repeatability. A retained subset of the pinned original TypeScript scorer serves as a differential oracle over generated cases; that test requires Node 22.18+ with TypeScript stripping (validated on Node 24). Node is not required to run the Python framework. Live authenticated scans and paid model calls are not part of automated tests.
