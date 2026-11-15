"""Claude Code adapter using the official Python Agent SDK."""
import asyncio
import json
from importlib.metadata import version
from pathlib import Path
import shutil
import sys
import time

from ..models import Finding, RunOutput
from ..metrics import tool_stats
from ..parsers.claude_findings import parse_findings, extract_findings_payload

SUPPORTED_TOOLS = {'Read', 'Glob', 'Grep', 'Bash', 'Write', 'Edit'}


class ContainmentError(RuntimeError):
    pass


def sandbox_settings(cwd: Path, reference_root: Path) -> dict:
    """One settings object: SDK 0.2.182 replaces, not merges, sandbox=."""
    return {
        'sandbox': {
            'enabled': True,
            'autoAllowBashIfSandboxed': True,
            'allowUnsandboxedCommands': False,
            'filesystem': {
                'denyRead': [str(reference_root.resolve().parent), str(cwd.resolve().parent)],
                'allowRead': [str(cwd.resolve())],
                'allowWrite': [str(cwd.resolve())],
                # Prevent exceptions for implicit git/config write locations.
                'denyWrite': [str(reference_root.resolve())],
            },
        },
        'permissions': {'deny': [f'Read(/{reference_root.resolve()}/**)']},
    }


async def check_sandbox_available() -> None:
    """Fail before model execution if the native sandbox cannot start.

    This checks platform prerequisites, not reference-read enforcement. The
    optional runtime containment integration test exercises that policy.
    """
    if sys.platform == 'linux':
        missing = [name for name in ('bwrap', 'socat') if shutil.which(name) is None]
        if missing:
            raise ContainmentError('Sandbox prerequisites missing: ' + ', '.join(missing))
        process = await asyncio.create_subprocess_exec(
            'bwrap', '--ro-bind', '/', '/', '--unshare-user', '--unshare-pid',
            '--', '/bin/true', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), 10)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        if process.returncode:
            raise ContainmentError('Bubblewrap sandbox unavailable: ' + stderr.decode(errors='replace').strip())
    elif sys.platform == 'darwin':
        if shutil.which('sandbox-exec') is None:
            raise ContainmentError('sandbox-exec is unavailable')
    else:
        raise ContainmentError(f'Unsupported Claude sandbox platform: {sys.platform}')


def denied_tool_reason(tool: str, args: dict, cwd: Path) -> str | None:
    """Native tools need path checks; Bash relies on the actual CLI sandbox."""
    if tool not in SUPPORTED_TOOLS:
        return f'Tool outside declared benchmark set: {tool}'
    if tool == 'Bash':
        if args.get('dangerouslyDisableSandbox'):
            return 'Unsandboxed Bash is forbidden'
        return None
    paths = [args.get('file_path')] if tool in ('Read', 'Write', 'Edit') else [args.get('path', '.')]
    if tool == 'Glob':
        # Glob can escape through the pattern even when path is omitted.
        paths.append(args.get('pattern', '*'))
    for value in paths:
        if not isinstance(value, str) or '\0' in value:
            return 'Invalid native tool path'
        if tool == 'Glob' and (any(c in value for c in ('{', '}', '~'))):
            return 'Ambiguous Glob path expansion is unsupported'
        target = (cwd / value).resolve()
        if not target.is_relative_to(cwd.resolve()):
            return 'Outside isolated project'
    if tool in ('Glob', 'Grep'):
        # A Bash call can create links after the initial workspace copy. Native
        # recursive tools must not follow those links to unmounted references.
        for entry in cwd.rglob('*'):
            if entry.is_symlink() and not entry.resolve().is_relative_to(cwd.resolve()):
                return 'Recursive native search contains an external symlink'
    return None


class ClaudeCodeRunner:
    def __init__(self, reference_root=None):
        self.reference_root = Path(reference_root).resolve() if reference_root else Path(__file__).resolve().parents[2] / 'fixtures'

    async def run(self, task, config, cwd):
        from claude_agent_sdk import query, ClaudeAgentOptions, HookMatcher, AssistantMessage, TextBlock, ResultMessage
        cwd = Path(cwd).resolve()
        start = time.monotonic()
        calls, active, files, denials = [], {}, set(), []
        metrics = {'toolCalls': calls, 'tool_denials': denials, 'sdk_version': version('claude-agent-sdk')}
        final, terminal = '', None

        async def pre(data, tool_id, context):
            tool, args = data.get('tool_name', ''), data.get('tool_input', {})
            reason = denied_tool_reason(tool, args, cwd)
            if reason:
                denials.append({'tool': tool, 'reason': reason})
                return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': reason}}
            if tool in ('Read', 'Write', 'Edit'):
                files.add(str((cwd / args['file_path']).resolve().relative_to(cwd)))
            active[tool_id] = (time.monotonic(), tool, len(json.dumps(args)) / 4)
            return {}

        async def post(data, tool_id, context):
            if tool_id in active:
                began, tool, estimated = active.pop(tool_id)
                failed = data.get('hook_event_name') == 'PostToolUseFailure'
                calls.append(dict(tool=tool, durationMs=(time.monotonic()-began)*1000,
                                  inputTokensEst=estimated,
                                  outputTokensEst=len(json.dumps(data.get('tool_response', data.get('error', '')), default=str))/4,
                                  failed=failed))
            return {}

        try:
            if set(config.allowedTools) - SUPPORTED_TOOLS:
                raise ValueError('Only the six contained benchmark tools are supported')
            if cwd == self.reference_root or self.reference_root.is_relative_to(cwd) or cwd.is_relative_to(self.reference_root):
                raise ContainmentError('Agent cwd must be isolated from the fixture/reference tree')
            extra = config.model_extra
            effort = None if config.effort == 'default' else config.effort
            if effort not in (None, 'low', 'medium', 'high', 'xhigh', 'max'):
                raise ValueError('Unsupported Python SDK effort')
            thinking = dict(extra.get('thinking', {'type': 'adaptive'}))
            if 'budgetTokens' in thinking:
                thinking['budget_tokens'] = thinking.pop('budgetTokens')
            await check_sandbox_available()
            metrics['sandbox_preflight'] = 'passed'
            options = ClaudeAgentOptions(
                cwd=str(cwd), model=config.model, system_prompt=extra.get('systemPrompt', task.systemPrompt),
                max_turns=task.maxTurns or config.maxTurns, effort=effort, thinking=thinking,
                tools=config.allowedTools, allowed_tools=config.allowedTools, permission_mode='bypassPermissions',
                setting_sources=[], strict_mcp_config=True, mcp_servers={},
                # Do NOT also pass sandbox=: it drops filesystem settings in
                # the installed SDK's SubprocessCLITransport._build_settings_value.
                settings=json.dumps(sandbox_settings(cwd, self.reference_root)),
                hooks={'PreToolUse': [HookMatcher(hooks=[pre], on_failure='block')],
                       'PostToolUse': [HookMatcher(hooks=[post])],
                       'PostToolUseFailure': [HookMatcher(hooks=[post])]},
                output_format={'type': 'json_schema', 'schema': {
                    'type': 'object', 'properties': {'findings': {'type': 'array', 'items': Finding.model_json_schema()}},
                    'required': ['findings'], 'additionalProperties': False,
                }} if config.structuredOutput else None,
            )
            async with asyncio.timeout(config.timeoutMs / 1000):
                async for message in query(prompt=extra.get('prompt', task.prompt), options=options):
                    if isinstance(message, AssistantMessage) and message.parent_tool_use_id is None:
                        texts = [block.text for block in message.content if isinstance(block, TextBlock)]
                        if texts:
                            final = '\n'.join(texts)
                    elif isinstance(message, ResultMessage):
                        terminal = message
            if terminal is None:
                raise ValueError('SDK stream ended without result')
            metrics.update(usage=terminal.usage, totalCostUsd=terminal.total_cost_usd,
                           totalTurns=terminal.num_turns, session_id=terminal.session_id,
                           cli_duration_ms=terminal.duration_ms)
            final = terminal.result or final
            if terminal.is_error:
                raise RuntimeError('; '.join(terminal.errors or [terminal.subtype]))
            structured = terminal.structured_output
            if structured is not None:
                if not isinstance(structured, dict) or 'findings' not in structured:
                    raise ValueError('Structured output must contain a findings array')
                payload = structured['findings']
            else:
                payload = extract_findings_payload(final)
            if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
                raise ValueError('Missing or malformed findings array')
            findings = parse_findings(payload)
            output = RunOutput(final_text=final, findings=findings)
        except Exception as error:
            kind = 'containment' if isinstance(error, ContainmentError) else 'timeout' if isinstance(error, TimeoutError) else 'runner'
            output = RunOutput(final_text=final, failure=kind, error=str(error))
        metrics.update(sessionDurationMs=(time.monotonic()-start)*1000,
                       files_accessed=sorted(files), incomplete_tool_calls=len(active))
        metrics['toolStats'] = tool_stats(calls)
        output.metrics = metrics
        return output
