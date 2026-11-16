"""Optional, no-payment integrations; skip missing runtime capabilities honestly."""
import asyncio
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import pytest
from vulnbench.runners.claude_code import check_sandbox_available, ContainmentError, sandbox_settings


@pytest.mark.sdk_integration
def test_real_claude_cli_initializes_or_fails_closed_without_model_prompt(tmp_path, record_property):
    if os.environ.get('VULNBENCH_SDK_INTEGRATION') != '1':
        pytest.skip('Set VULNBENCH_SDK_INTEGRATION=1 for real CLI initialization; no model query')
    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher, ResultError
    async def guard(*args): return {}
    async def initialize():
        options=ClaudeAgentOptions(cwd=tmp_path,setting_sources=[],strict_mcp_config=True,mcp_servers={},
            settings=json.dumps(sandbox_settings(tmp_path,tmp_path/'unmounted-references')),
            env={'CLAUDE_CONFIG_DIR':str(tmp_path/'cli-config'),'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'},
            hooks={'PreToolUse':[HookMatcher(hooks=[guard],on_failure='block')]})
        # connect initializes only; it never sends a user prompt or query.
        try:
            async with ClaudeSDKClient(options=options) as client:
                info=await client.get_server_info()
                assert info['hook_on_failure_supported'] is True
                assert info.get('hooks_applied') is not False
                record_property('real_cli_outcome', 'initialized with registered hooks')
        except ResultError as error:
            # With failIfUnavailable the actual CLI must refuse startup on a
            # host with missing sandbox dependencies. This is a validated
            # refusal, not a successful initialized/contained scan.
            assert 'Sandbox required but unavailable' in str(error)
            assert json.loads(options.settings)['sandbox']['failIfUnavailable'] is True
            record_property('real_cli_outcome', 'refused startup: sandbox unavailable')
    asyncio.run(initialize())


@pytest.mark.containment_integration
def test_real_bash_reference_reads_denied_by_official_sandbox(tmp_path, make_symlink):
    srt=os.environ.get('VULNBENCH_SRT') or shutil.which('srt')
    if not srt:
        pytest.skip('Anthropic sandbox runtime srt not installed; OS containment not validated')
    try:
        asyncio.run(check_sandbox_available())
    except ContainmentError as error:
        pytest.skip(f'OS sandbox unavailable; no unsandboxed retry: {error}')
    benchmark=tmp_path/'benchmark'; references=benchmark/'fixtures'
    references.mkdir(parents=True)
    secret=references/'findings.json'; secret.write_text('REFERENCE_SECRET')
    results=benchmark/'results'; results.mkdir(); (results/'previous-findings.json').write_text('REFERENCE_SECRET')
    cwd=tmp_path/'isolated/project'; cwd.mkdir(parents=True)
    (cwd/'app.js').write_text('PROJECT_SOURCE')
    make_symlink(cwd/'link', references, target_is_directory=True)
    settings=tmp_path/'srt.json'
    # srt consumes SandboxRuntimeConfig, CLI settings wraps it in sandbox.
    policy=sandbox_settings(cwd,references)['sandbox']['filesystem']
    settings.write_text(json.dumps({'filesystem':policy,'network':{'allowedDomains':[],'deniedDomains':[]}}))
    def run(command):
        return subprocess.run(
            [srt, '--settings', str(settings), '--', 'bash', '-lc', command],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
       )
    readable=run('cat app.js')
    assert readable.returncode==0, readable.stderr  # no false positive from a failed sandbox startup
    assert readable.stdout.strip()=='PROJECT_SOURCE'
    attempts=[f'cat {shlex.quote(str(secret))}', 'cat link/findings.json',
              f'cat {shlex.quote(str(results/"previous-findings.json"))}',
              'cat ../findings.json']
    (cwd.parent/'findings.json').write_text('REFERENCE_SECRET')
    for command in attempts:
        attempt=run(command)
        assert attempt.returncode!=0
        assert 'REFERENCE_SECRET' not in attempt.stdout
