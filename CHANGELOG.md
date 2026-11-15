# Review changes

- Repeatability now preserves reported type/file/line signatures for both matched and unmatched findings, including per-occurrence reference ID and finding index. Separate `reference_coverage` reproduces the publication's reference-ID view. Default basename normalization matches the paper handoff; optional full-path mode distinguishes equal basenames in different directories. Incomplete experiments cannot claim `seen_all` across requested repetitions; duplicate successful repetitions fail explicitly.
- Added configuration-level macro averages over task means and headline sample standard deviation over per-repetition task means. Added duration, tokens, cost, and explicit coverage/failure counts. Configurations remain separate even when they share a model name.
- Fixed SDK 0.2.182 sandbox settings replacement: the complete policy now travels in one `settings` object. Native file hooks fail closed, guard escaping Glob patterns and newly created symlinks, and reject requests for unsandboxed Bash. Missing/blocked sandbox prerequisites prevent model execution. The tested SDK release is pinned.
- Fixed joined assistant text, subagent-text filtering, valid empty-array extraction, malformed structured-output detection, TypeScript thinking-budget translation, and failed-tool telemetry. Usage remains SDK-reported; tool tokens remain estimates.
- Reference generation now writes separate unreviewed candidates by default and preserves the original reference bytes. Raw SARIF/file-output, stdout/stderr, rule mappings, and severity comparisons are separate artifacts. Explicit `--overwrite` retains a backup and refuses concurrent reference edits. Timeouts retain partial scanner output. URI normalization and failed/malformed SARIF handling have regression tests.
- V1 scoring, greedy normalized-type matching, original fixtures, references, and default prompts are unchanged. See `VALIDATION.md` for actual checks and limits.

## Native Windows portability

- Added native Windows Snyk executable/npm-shim resolution and process-tree termination, shared by baseline scans and reference generation.
- Added local drive/file-URI normalization, explicit UTF-8 I/O, and pre-copy junction/reparse-point rejection.
- Preserved Linux/macOS Claude checks and added SDK `failIfUnavailable`. Native Windows now explains the official runtime's missing Bash sandbox and fails before any model call.
- Added Windows branch tests, real Windows-only subprocess integrations, PowerShell instructions, and a cross-platform CI matrix. See `WINDOWS_COMPATIBILITY.md` for actual results and the remaining Claude limitation.
