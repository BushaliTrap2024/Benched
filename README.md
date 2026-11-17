# VulnBench Python — JS 1.0

Executable Python port of the vulnerability detection workflow in [Snyk VulnBench](https://github.com/snyk-labs/snyk-vulnbench). The exact inspected revision is recorded in `UPSTREAM.json`. The upstream repository is unchanged. Original JavaScript fixture projects, V1 detection task JSON, model configurations, rule mappings, finding aliases, and default prompts are included. Upstream licensing is in `LICENSE.upstream`.

Scores measure **agreement with the selected reference set**, not independently established vulnerability correctness. Automatically generated Snyk findings are unreviewed reference candidates.

## Install and authenticate

Use Python 3.11+. Snyk scans support native Windows as well as Linux/macOS; Claude scans require a supported built-in Claude Code sandbox. See the Windows instructions below. Work from this extracted project directory (the checkout is the supported distribution, including `evals/` and `fixtures/`).

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
```

Install the official Snyk CLI (`npm install -g snyk`), run `snyk auth`, and ensure the organization has Snyk Code enabled. `SNYK_TOKEN` may be used in automated environments. Reference preparation and baseline execution use the installed CLI directly without a shell.

Claude uses the **official `claude-agent-sdk` Python package**, including its Claude Code runtime, not ordinary Anthropic API calls. Authenticate Claude Code using its supported account login or set `ANTHROPIC_API_KEY`. Do not put credentials in config JSON. Linux sandbox execution requires Claude Code's supported sandbox dependencies, including bubblewrap and socat; follow Claude Code's installation instructions. Authentication and paid executions are the user's environment prerequisites.


## Native Windows: VS Code and PowerShell

**Snyk baseline and reference generation are implemented for native Windows. Claude Code evaluation cannot currently satisfy this benchmark's required native Windows shell isolation.** The Python SDK can launch native `claude.exe`, but Anthropic's [Claude Code sandbox documentation](https://code.claude.com/docs/en/sandboxing) says native Windows shell commands run unsandboxed. Passing filesystem settings does not create an OS boundary on an unsupported platform. Benched therefore returns a clear `containment` failure **before any model query**, rather than producing an unprotected benchmark score.

The separate `@anthropic-ai/sandbox-runtime` project has a Windows backend, but that is not equivalent to a supported Claude Code SDK Bash sandbox. Benched does not wrap it into a custom sandbox or substitute file-tool hooks for shell isolation. Installing Git for Windows/Git Bash does not resolve this limitation. Docker, Ubuntu, and WSL2 are **not requirements** for installing Benched or running Snyk natively. A protected native Windows Claude scan remains unavailable until the official Claude Code SDK/runtime supports the required boundary.

Open the cloned repository folder in VS Code, choose **Terminal → New Terminal**, and use PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[test]"
pytest -q
```

If PowerShell policy prevents activation, use the virtual environment directly; changing execution policy is unnecessary:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
```

Install the [official Snyk CLI for Windows](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli): either the standalone executable renamed to `snyk.exe` on `PATH`, or the npm package. For npm:

```powershell
npm.cmd install -g snyk
snyk.cmd auth
```

For the standalone binary, use `snyk.exe auth`. Verify the installation with `where.exe snyk` and `snyk.cmd --version` or `snyk.exe --version`. The organization must have Snyk Code enabled. You may also use `$env:SNYK_TOKEN` via your normal secure environment configuration; do not commit tokens.

```powershell
# Fresh isolated project copy; existing reference file remains unchanged.
python main.py run --task js-project-tigerteam-find-vulns --config snyk-code --repetitions 1

# Generates separate unreviewed candidates; preserves the curated original.
python main.py generate-references --fixture js-project-tigerteam

# Configuration validation succeeds without executing Claude.
python main.py run --task js-project-tigerteam-find-vulns --config claude-opus-4-6-medium --repetitions 1 --dry-run

# Currently exits with a clear containment error on native Windows; no model query.
python main.py run --task js-project-tigerteam-find-vulns --config claude-opus-4-6-medium --repetitions 1
```

Snyk `.cmd` shims are resolved to the installed npm package's declared Node entrypoint and launched with an argument vector, without `cmd.exe` or PowerShell interpreting scanner arguments. Global npm and local `node_modules/.bin` layouts are supported; standalone `snyk.exe` executes directly. Unknown/custom batch wrappers fail with instructions to use a native executable. Windows timeout/cancellation cleanup uses `taskkill.exe /T /F` to stop the process tree, and partial UTF-8 output is retained. Cleanup failures are reported, not treated as successful scans. Legacy `command` configuration uses Windows `CommandLineToArgvW`; the original `executable` + `args` form remains preferred.

Reference generation accepts local Windows drive paths and `file:///C:/...` SARIF URIs, normalizes candidates to POSIX project-relative paths, and rejects drive-relative/remote UNC locations. Prompts, JSONL, and scanner artifacts explicitly use UTF-8. Workspaces remain fresh `TemporaryDirectory` copies of `project/` only; symlinks and Windows junction/reparse points are rejected before copying. Windows symlink tests skip when Developer Mode/admin permission is unavailable. Node 22.18+ is needed only for TypeScript differential tests and npm-based Snyk installations; the standalone Snyk binary needs no Node installation.

For actual platform test results and unverified limitations, see [WINDOWS_COMPATIBILITY.md](WINDOWS_COMPATIBILITY.md). The [GitHub Actions matrix](https://github.com/BushaliTrap2024/Benched/actions/runs/43678028466) passed on native Windows (**121 passed, 2 skipped**), Linux, and macOS, including Windows-only real subprocess/shim tests. Authenticated scanner calls were not run. OS-level Bash reference denial is not claimed on native Windows, where the official SDK sandbox is unsupported.

## Three workflows

```bash
# Generate candidates separately; the original findings.json is preserved.
python main.py generate-references --fixture js-project-tigerteam

# Explicitly install generated candidates, preserving the original in artifacts:
python main.py generate-references --fixture js-project-tigerteam --overwrite

python main.py run --task js-project-tigerteam-find-vulns \
  --config claude-opus-4-6-medium --repetitions 5

python main.py run --task js-project-tigerteam-find-vulns \
  --config snyk-code --repetitions 5
```

The bundled tigerteam fixture already has upstream references. By default generation preserves those bytes and writes **only** `results/references/ID/candidate-findings.json`; it does not install a new scoring reference, even for a new fixture. Review candidates before selecting them. `--overwrite` explicitly installs the unreviewed candidates as `fixtures/NAME/findings.json`, preserves a byte-exact `previous-findings.json` backup, and refuses to overwrite concurrent reviewer edits.

Each generation bundle retains `scan.sarif.json`, full `stdout.txt`/`stderr.txt`, `execution.json`, `candidate-findings.json`, `mapping.json` (rule IDs/levels), and `severity-comparison.json`. CLI `--json-file-output` is authoritative when present; raw stdout is retained separately even when it is a human summary. Failed and timed-out invocations retain available raw/partial output and leave references unchanged. The checked-in representative SARIF is explicitly synthetic test data, not a claimed live scan.

Automatic severity follows upstream `mapLevel`: **error → high, warning → medium, note → low, missing/other → medium**. It never produces `critical`. Curated references may assign different severities: tigerteam's command-injection reference is `critical`, whereas a SARIF `error` maps to `high`. The comparison artifact reports exact type/file/line pairs solely for review; that diagnostic never changes V1 scoring or copies curated severities into candidates. Unknown rule IDs remain `other` and require review. IDs are stable from fixture/rule/normalized-path/line plus duplicate occurrence, and source order is retained. Supported locations include project-relative paths, repo-relative fixture paths, absolute/file URIs, and absolute `originalUriBaseIds` entries. Escaping locations and unknown URI bases fail explicitly.

`--include-ignores` explicitly broadens the scan. This command is new Python automation of upstream fixture-authoring Steps 2–4, not an existing upstream one-command feature.

Repeat `--task` and `--config` for a Cartesian experiment. Each repetition starts a fresh runner session and a fresh project copy. Repetitions and agent turns are independent. `--dry-run` validates selection and prints resolved prompts/configuration without invoking detectors. `--output PATH` selects the JSONL destination; otherwise a unique experiment file is created. Nonzero process status reports failed runs; failures remain in JSONL and contribute zero F1 to project/configuration means and sample standard deviations. Their recorded duration, tokens, and nullable cost are included; precision and recall exclude failures. Missing repetitions are not scored as failures, and failed runs contribute no observed findings to repeatability.

```bash
python main.py run --task js-project-tigerteam-find-vulns --config claude-opus-4-6-medium --repetitions 5 --dry-run
python main.py aggregate results/experiment-ID.jsonl --level all
python main.py aggregate results/experiment-ID.jsonl --level config
python main.py repeatability results/experiment-ID.jsonl
```

Use `python main.py --root PATH ...` for a separate fixture/config tree. Task JSON uses the original `fixture`, `category`, `systemPrompt`, `prompt`, and `maxTurns` fields; omitted prompts use `evals/prompts.json`, extracted verbatim from the pinned TypeScript `FIND_VULNS_DEFAULTS`. Task maxTurns takes precedence over configuration maxTurns, matching upstream.

Configure model runs in `evals/run-configs.json`: `model`, `effort`, `maxTurns`, `timeoutMs`, `allowedTools`, `systemPrompt`, `prompt`, optional `thinking`, and `structuredOutput`. Effort `default` delegates to the runtime; unsupported effort values fail explicitly. Structured output requests an object containing a `findings` array. Text mode supports the original fenced `FINDINGS_JSON` convention and V1 fallback extraction. Command configs support `executable` and `args`, with `{fixturePath}` substitution; legacy `command` is split without a shell. Only the Snyk Code parser is supported.

## Results and protocols

Each JSONL record includes task/fixture/config IDs, complete resolved task and configuration, reference SHA256, repetition, timestamp, final text, normalized findings, metrics, failure/error, and scoring details. Scoring includes TP/FP/FN, precision, recall, F1, per-finding reference assignments, unmatched findings, and type/severity breakdowns. Failed executions have `score: null`.

V1 scoring normalizes reported categories and greedily consumes the first unmatched reference of the same type, preserving both orders. File and line never participate. Duplicate reports are retained, and excess reports become false positives. With no reports precision is 0; with no references overall recall is 1; F1 is 0 if precision plus recall is 0. A zero-reference breakdown has recall 0, as upstream does.

Repeatability is separate from scoring. Both `reference_matched` and `unmatched` now use **task + config + normalized reported type + basename(file) + reported line**, retaining the original finding, repetition, finding index, and matched reference ID for each occurrence. `all_findings` deduplicates across the two outcomes. A duplicate signature counts once per repetition while all occurrences remain available. `--signature-path relative-path` selects a full normalized path instead of basename; this explicitly changes the paper's path normalization. Equal basenames in different directories therefore merge in default paper mode but remain distinguishable in original occurrence metadata or full-path mode.

The paper's chart handoff separately defines true-positive recurrence using **task + config + reference ID**. That published view is retained as `reference_coverage`; it is not mislabeled as location-sensitive model repeatability. On the published 250 model executions, unmatched recurrence is 161 unique / 80 once / 22 all-five; reference coverage is 158 unique / 134 all-five. Location-sensitive matched signatures are 187 unique / 120 all-five. These are distinct questions, not interchangeable counts. See the [paper](https://arxiv.org/abs/2606.15762v1), [chart methodology](https://github.com/snyk-labs/snyk-vulnbench/blob/385a3751046b62f30b61f9dfadb26d6d7dfc52aa/public/2026-05-28-llm-repeatability/article-visuals.md), and regression tests.

`seen_all` uses **requested** repetitions, so failures/missing runs do not imply perfect planned repeatability. Outputs include successful count and `complete`. Analyze one experiment at a time; duplicate successful task/config/repetition keys are rejected.

Aggregation defaults to `{tasks: [...], configurations: [...]}`; use `--level task` for the previous task-row-only CLI shape or `--level config` for model configuration headlines. The Python `aggregate(records)` function retains its original task-row API; `aggregate_by_config(records)` adds configuration rows. Repetitions are averaged within each task, then task means receive equal weight (macro averages), regardless of finding counts or unequal repetition counts. Headline sample standard deviation is calculated over each repetition's mean across tasks, as in `src/aggregator.ts`, not over all pooled runs or per-task deviations. Configurations with different effort/tools remain separate even when sharing a model name. Failures are excluded and reported explicitly; incomplete matrices show task counts, expected runs, and per-repetition coverage. Entirely absent tasks cannot be inferred from a JSONL file: `complete` applies only to task IDs present in that input. Token/cost averages are nullable when unavailable.

SDK usage is saved as reported, including cache counters when present; cost and turns come from the SDK terminal result. Tool hooks record wall time and character-count/4 estimates separately from SDK token usage. Files accessed records only observable native filesystem tools. Bash file reads cannot be enumerated reliably. Snyk metrics retain stdout, stderr, status, duration, finding count, and files **referenced by findings**, not an assertion that these were its only scanned files. Valid Snyk vulnerability exit status 1 is accepted; malformed SARIF and operational statuses 2/3 fail rather than receive misleading zero scores.

## Isolation and differences

Only `project/` is copied into a unique temporary directory; fixture metadata and references are excluded. Workspaces are cleaned on success and exceptions, and source symlinks are rejected. Native filesystem hooks reject outside paths (including escaping Glob patterns and symlinks created during a run). PreToolUse hooks use SDK `on_failure="block"`; unsupported hook enforcement fails the SDK initialization. Tools are limited to Read/Glob/Grep/Bash/Write/Edit. Requests to disable Bash sandboxing are denied.

The complete sandbox policy goes through **one `settings` JSON object**, with SDK-enforced `failIfUnavailable: true`. In tested SDK **0.2.182**, separately supplying `sandbox=` replaces `settings["sandbox"]` and loses filesystem rules; a transport regression test guards against that bug. The policy enables sandboxing, forbids unsandboxed Bash fallback, denies reads of the benchmark tree (including fixtures/results) and the temporary parent, re-allows the isolated project for reading, allows project writes, and denies reference writes. Linux preflight requires bubblewrap/socat and a functioning namespace probe before any model call. User/project settings and unrelated MCP servers are disabled. The preflight is a prerequisite check, not proof of reference-read enforcement.

**Containment validation limitation:** this managed host lacks socat, and a direct bubblewrap probe cannot create its user namespace. The runner therefore fails closed. Native hook denials, SDK policy serialization, and real CLI hook-registration initialization were checked; actual OS-enforced Bash reference denial could not run here. The optional official sandbox-runtime integration first verifies an allowed project read, then attempts absolute-reference, symlink, saved-reference-artifact, and parent-reference reads. It skips with a reason when the sandbox cannot start and never retries unsandboxed. No claim of end-to-end Bash containment is made from a mock or a failed startup. See `VALIDATION.md`.

The original JavaScript fixtures remain JavaScript. Fixing workflows, V2 scoring, model gateways, MCP prompt variants, and unrelated runners are intentionally outside this V1 port. Parser fallback follows V1 behavior, including its simple first-array regex. Invalid scanner output is handled more strictly than the permissive upstream parser. Partial tool calls without a post hook have no fabricated duration; interrupted SDK sessions may have no terminal usage. The Python SDK is pinned to the validated release; other dependency versions should also be locked for published experiments; record runtime versions alongside artifacts when comparing environments.

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

Tests cover published-data headline/signature reproduction, mappings, SARIF, malformed output, fenced findings, duplicates, greedy matching, empty denominators, workspace cleanup/isolation, repetitions, CLI subprocess status/timeouts, reference generation/backups, baseline immutability, SDK option/usage handling, and repeatability. A retained subset of the pinned original TypeScript scorer serves as a differential oracle over generated cases; that test requires Node 22.18+ with TypeScript stripping (validated on Node 24). Node is not required to run the Python framework. Live authenticated scans and paid model calls are not part of automated tests.


## Optional no-payment integrations

```bash
# Initialize the actual bundled Claude CLI and register hooks; sends no model prompt.
VULNBENCH_SDK_INTEGRATION=1 pytest -q -m sdk_integration

# Needs the official srt executable, bubblewrap/socat on Linux, and permitted namespaces.
# Install @anthropic-ai/sandbox-runtime separately; it is a test dependency only.
VULNBENCH_SRT=/path/to/srt pytest -q -m containment_integration -rs
```

Regular tests never make paid model calls. The real-SDK protocol test uses a deterministic in-memory CLI peer, explicitly not a real detector scan or proof of OS isolation. Real model/scanner scans require valid authentication and a working sandbox; no unauthenticated or unsandboxed scan is counted as successful. The earlier implementation review is recorded in `VALIDATION.md`; current portability test results and SDK startup-refusal behavior are in `WINDOWS_COMPATIBILITY.md`.
