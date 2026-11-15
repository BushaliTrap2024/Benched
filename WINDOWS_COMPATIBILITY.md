# Native Windows compatibility and validation

## Supported behavior and explicit limit

The Snyk baseline and reference generator now share Windows-aware process execution. They accept standalone Snyk executables and standard npm `snyk.cmd` installations. The npm package entrypoint is passed directly to Node, preserving paths with spaces/Unicode and shell metacharacters as argument data. Native Windows cleanup uses `taskkill /T /F` instead of Unix process groups. Failed cleanup is surfaced explicitly, with available scanner output, rather than silently reporting a successful timeout cleanup.

Claude Code's native Windows SDK launch support and filesystem sandbox support are different capabilities. The pinned Python SDK 0.2.182 can launch a native `claude.exe`; its source explicitly refuses `.cmd` Claude wrappers. But the official Claude Code runtime documentation says its shell sandbox does not run on native Windows. There is **no verified Windows-compatible SDK equivalent** to the required TypeScript `sandbox.filesystem` policy. Benched fails clearly before any model query on native Windows. It does not remove reference protections, run unsandboxed, or require a custom/Docker/WSL sandbox.

The standalone Anthropic sandbox-runtime Windows backend is a separate interface, not evidence that Claude Code's built-in Bash tool will use it. It is not wired into this benchmark.

## Differences from the TypeScript implementation

- The inspected upstream `src/runner.ts` delegates `filesystem.allowWrite`/`denyRead` to the Agent SDK. Its lack of a Windows guard does not establish that Claude Code enforces those settings there.
- Python keeps the complete filesystem policy in one SDK `settings` object because separately passing `sandbox=` replaces that object in SDK 0.2.182. It now explicitly supplies `failIfUnavailable: true`; official SDK docs note that this fail-closed default otherwise differs between Python and TypeScript. Linux/macOS prerequisite checks and native file-tool hooks are retained.
- Native Windows receives a specific unsupported-isolation error, instead of the previous generic unsupported-platform error. No model call occurs. This deliberate limit is required to preserve the benchmark's answer-key boundary.
- Process launch/termination differs by host API; the normalized findings, scorer, experiment loop, result fields, aggregation, and repeatability protocol do not change.
- UTF-8 I/O, Windows URI normalization, and junction rejection are portability fixes. No fixture, reference, prompt/task/configuration data, scoring source, model aggregation source, or repeatability source is changed.

## Validation scope

Development and local validation were performed on **Linux**, not on a native Windows workstation. Tests include simulated Windows branches plus Windows-only integration tests that are skipped off Windows. Native Windows execution must not be inferred from the simulated branches.

The Windows-only integration tests exercise actual `CommandLineToArgvW`, drive-letter and file-URI handling, npm shim execution through Node, and scanner descendant termination using `taskkill`. A full CLI reference-generation subprocess test also uses an npm-style scanner fixture on Windows. These are deterministic scanner fixtures, not authenticated Snyk scans.

The cross-platform GitHub Actions workflow runs the regular suite on `windows-latest`, `ubuntu-latest`, and `macos-latest`. CI outcomes, if available, are recorded below; configuring a job alone is not a passing native Windows result.

Actual model-driven native/Bash reference-access denial cannot be demonstrated on native Windows using an unsupported Claude Code sandbox. The existing optional OS containment integration remains intact on supported platforms: it requires an allowed project read before counting denied-reference attempts. This Linux host still lacks socat and cannot create bubblewrap user namespaces, so that integration skips rather than running commands outside the sandbox.

## Sources inspected

- [Claude Code sandbox support and scope](https://code.claude.com/docs/en/sandboxing): native Windows shell execution lacks the built-in sandbox; native file tools run outside the shell sandbox.
- [Python SDK sandbox reference](https://code.claude.com/docs/en/agent-sdk/python#sandbox-configuration): filesystem settings forwarding and explicit `failIfUnavailable` behavior.
- [Official Python SDK subprocess transport](https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/_internal/transport/subprocess_cli.py), also inspected in installed SDK **0.2.182**: native Windows `claude.exe` discovery and batch-wrapper refusal.
- [Snyk Windows installation](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli) and [official npm entrypoint](https://github.com/snyk/cli/blob/main/package.json).
- Original VulnBench `src/runner.ts` at revision `385a3751046b62f30b61f9dfadb26d6d7dfc52aa`.

## Actual local results

Linux, Python 3.12, Node 24.22.1, SDK 0.2.182 / Claude Code 2.1.325:

```text
python -m pytest tests -q -rs
117 passed, 6 skipped in 3.66s
```

Four skips require native Windows APIs (Windows argument parsing/file URIs, descendant termination, npm shim execution, NTFS junction rejection). Two skips are optional real CLI startup and unavailable OS sandbox containment. Simulated Windows branches and original V1 regressions pass. `git diff --check` and bytecode compilation pass; protected benchmark sources/data have no diff.

The explicitly enabled real CLI initialization test passed by confirming the CLI's **startup refusal** with `failIfUnavailable: true` and missing socat. This was not successful agent initialization or a scan; no model prompt was sent. Its earlier expectation of successful initialization was updated to distinguish a genuine fail-closed refusal from a supported initialized session. The optional official sandbox-runtime containment test still skips on this Linux host; an actual allowed-project / denied-reference Bash execution remains unverified here.

No authenticated Claude or Snyk scan was performed during this portability work. No native Windows workstation was available locally. CI results are separate from these local results and must be read from the cross-platform workflow run.
