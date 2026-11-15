# Implementation review validation

This records the earlier implementation review. For subsequent Windows changes and hosted cross-platform results, see [WINDOWS_COMPATIBILITY.md](WINDOWS_COMPATIBILITY.md).

Validated on Python 3.12, Node 24.22.1, `claude-agent-sdk` **0.2.182**, and bundled Claude Code **2.1.325**. The SDK is now pinned in `pyproject.toml`. The optional standalone Anthropic sandbox runtime inspected was **0.0.83**; it is not a production dependency of this Python framework.

## Actual test results

From the repository root using the installed validation virtual environment:

```text
python -m pytest tests -q -rs
94 passed, 2 skipped in 3.37s
```

The default skips are the explicitly enabled real-CLI initialization and unavailable standalone OS sandbox integration. Tests use deterministic SDK messages/control-protocol frames and representative scanner subprocesses; paid API calls are not part of this suite.

With real SDK initialization explicitly enabled and the locally installed official sandbox runtime selected:

```text
VULNBENCH_SDK_INTEGRATION=1 VULNBENCH_SRT=/path/to/srt python -m pytest tests -q -rs
95 passed, 1 skipped in 3.52s

SKIPPED: OS sandbox unavailable; no unsandboxed retry:
Sandbox prerequisites missing: socat
```

`git diff --check` and Python bytecode compilation also passed. `vulnbench/scoring.py`, original fixture/reference bytes, prompt JSON, aliases, and mapping JSON were not modified. V1 scorer differential tests still compare against the pinned original TypeScript implementation; new aggregation differential tests compare against the upstream TypeScript aggregator.

## What was checked

| Check | Evidence / status |
|---|---|
| V1 greedy type-only scoring | Existing scorer untouched; duplicate, denominator, and original-TypeScript differential regressions pass. Reported file/line remain irrelevant to scoring. |
| Published repeatability | Reduced original 300-run dataset checked in with provenance. Across 250 model runs: 161 unique unmatched / 80 once / 22 all-five; reference-ID coverage: 158 unique / 134 all-five. These match the publication. |
| Location-sensitive matched findings | 187 reported matched signatures / 120 all-five on the same dataset, with original locations and reference-match metadata retained. This is the requested extension; it is not passed off as the paper's reference-ID count. |
| Model/config aggregation | All six published configuration means, precision, recall, and headline standard deviations reproduced; unequal repetition weighting, failures, coverage, and null usage tested. |
| Installed SDK compatibility | Real SDK types, option-to-CLI settings serialization, thinking-budget translation, message parsing, control-frame hook dispatch, final/structured output, empty arrays, and failure handling tested. |
| Actual Claude CLI startup | Real bundled CLI initialized and registered a fail-closed PreToolUse hook through the SDK. No user/model prompt was submitted. This establishes initialization compatibility, not a completed agent scan. |
| Native filesystem tool guards | Outside absolute/relative paths, escaping Glob patterns, symlink reads/recursive searches, and unsupported tools denied in callback tests. A real SDK control-protocol test confirms the denial response on its wire. Actual model-directed native tool execution was not run. |
| Bash containment | Policy is preserved in actual SDK serialization. Unsandboxed requests and unavailable sandbox startup fail closed. **OS-enforced reference-read denial remains unverified on this host**, as detailed below. |
| Snyk authoring pipeline | Representative SARIF, JSON-file precedence, CLI subprocess exit 1, duplicate IDs, source order, URI paths/bases, unmapped rules, severity differences, backups, timeout partial output, malformed/failed scans, and concurrent reviewer edits tested. Synthetic SARIF is labeled as such; no test is represented as a live Snyk result. |
| CLI | Reference generation and task/config aggregation plus repeatability options exercised in subprocess tests. |

## Containment limitation and honest failure behavior

A direct bubblewrap namespace probe returned:

```text
bwrap: setting up uid map: Read-only file system
```

The official standalone sandbox runtime was also invoked with a command attempting to read a synthetic `findings.json`; it stopped before executing the command:

```text
Error: Sandbox dependencies not available: socat not installed
```

That is **not** counted as a successful reference-read denial. The optional test first requires a successful allowed-project read before it can establish actual denied-reference behavior. On a suitable host it checks absolute reference reads, a symlink from the project, saved reference artifacts in results, and a parent-directory reference. Here it skips rather than retrying outside the sandbox. No namespace restrictions were bypassed or weakened.

The runner now fails before invoking a model if required Linux sandbox dependencies or its namespace probe fail. Its policy travels in a single settings object, avoiding SDK 0.2.182's destructive merge when `sandbox=` is also set. Native hooks are a separate guard and use `on_failure="block"`. These measures correct identified problems, but this report does not claim complete end-to-end containment was proven here.

## Live scans

**No real model or Snyk scan was performed.** Authentication was checked without exposing credentials:

- `claude auth status --json` reported `loggedIn: false`, `authMethod: none`.
- No `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, or `ANTHROPIC_AUTH_TOKEN` was present.
- No installed `snyk` CLI or `SNYK_TOKEN` was available. Stored Snyk account configuration was not inspected.
- The host sandbox prerequisites also prevent a valid sandboxed Claude scan.

A working sandbox and valid authentication are required before a live smoke scan can be called successful. No mocked, startup-only, or published historical result is counted as a newly executed scan.

## Sources and protocol distinctions

- User-supplied paper: [arXiv:2606.15762v1](https://arxiv.org/abs/2606.15762v1), especially scoring, repeated-run variance, and signature limitations.
- Pinned upstream revision: `385a3751046b62f30b61f9dfadb26d6d7dfc52aa` (also in `UPSTREAM.json`). Read-only inspection included `src/aggregator.ts`, `src/scorer.ts`, `src/runner.ts`, `src/isolated-workspace.ts`, the fixture-authoring skill Steps 2–4, and the article chart handoff.
- [Chart handoff](https://github.com/snyk-labs/snyk-vulnbench/blob/385a3751046b62f30b61f9dfadb26d6d7dfc52aa/public/2026-05-28-llm-repeatability/article-visuals.md): unmatched signature explicitly uses `basename(file)`; true-positive chart recurrence uses reference IDs. We retain that reference view separately from the new reported-location view and provide optional full-path signatures.
- Published data: `reports/vulnbench-js-1.0/benchmark-2026-05-20T23-06-29-348Z.jsonl`. The reduced test data keeps only fields needed for signatures and headline reproduction, with source provenance. No published TP/FP labels or scores were recomputed with a different matching protocol.
- Upstream aggregation uses equal-task macro means and sample standard deviation over per-repetition headline means. Failed executions are excluded explicitly in this Python port, with incomplete coverage disclosed rather than silently assigning successful zero scores.
