"""Real installed SDK types/transport, with deterministic no-network peers."""
import asyncio
import json
from pathlib import Path
from unittest.mock import patch
import pytest
import claude_agent_sdk as sdk
from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport
from vulnbench.models import RunConfig, Task
from vulnbench.runners.claude_code import ClaudeCodeRunner, ContainmentError, denied_tool_reason, sandbox_settings


@pytest.fixture
def setup(tmp_path):
    project=tmp_path/'isolated/project'; project.mkdir(parents=True)
    refs=tmp_path/'benchmark/fixtures'; refs.mkdir(parents=True)
    (refs/'findings.json').write_text('REFERENCE_SECRET')
    task=Task(id='demo',name='Demo',fixture='demo',category='find-vulns',systemPrompt='system',prompt='audit')
    return project,refs,task


def terminal(**kwargs):
    defaults=dict(subtype='success',duration_ms=10,duration_api_ms=8,is_error=False,num_turns=2,session_id='test',usage={'input_tokens':10,'output_tokens':5},total_cost_usd=.01,result='FINDINGS_JSON:\n```json\n[]\n```')
    return sdk.ResultMessage(**(defaults|kwargs))


async def available(): pass


@pytest.mark.parametrize('tool,args',[
    ('Read',{'file_path':'../../benchmark/fixtures/findings.json'}),
    ('Read',{'file_path':'/etc/passwd'}),
    ('Write',{'file_path':'../outside.txt'}),
    ('Grep',{'path':'../../benchmark/fixtures','pattern':'SECRET'}),
    ('Glob',{'pattern':'../../benchmark/fixtures/*'}),
    ('Glob',{'pattern':'/etc/*'}),
    ('Glob',{'pattern':'{src,../../benchmark/fixtures}/*'}),
    ('Bash',{'command':'cat ../findings.json','dangerouslyDisableSandbox':True}),
    ('Agent',{'prompt':'read reference'}),
])
def test_native_path_and_unsandboxed_bash_denials(setup,tool,args):
    project,refs,_=setup
    assert denied_tool_reason(tool,args,project)


def test_symlink_and_benign_tools(setup, make_symlink):
    project,refs,_=setup
    make_symlink(project/'link', refs, target_is_directory=True)
    assert denied_tool_reason('Read',{'file_path':'link/findings.json'},project)
    assert denied_tool_reason('Glob',{'path':'link','pattern':'*'},project)
    assert denied_tool_reason('Read',{'file_path':'app.js'},project) is None
    assert denied_tool_reason('Bash',{'command':'cat app.js'},project) is None


def test_installed_sdk_preserves_entire_sandbox_config(setup):
    project,refs,_=setup
    settings=sandbox_settings(project,refs)
    options=sdk.ClaudeAgentOptions(cwd=project,settings=json.dumps(settings),sandbox=None)
    transport=SubprocessCLITransport(prompt='test',options=options)
    transport._cli_path='/unused/claude'
    command=transport._build_command()
    actual=json.loads(command[command.index('--settings')+1])
    assert actual==settings
    assert str(refs.parent) in actual['sandbox']['filesystem']['denyRead']
    assert actual['sandbox']['filesystem']['allowRead']==[str(project)]
    assert actual['sandbox']['allowUnsandboxedCommands'] is False
    # Demonstrate why both options must not be passed with this SDK release.
    lossy=sdk.ClaudeAgentOptions(settings=json.dumps(settings),sandbox={'enabled':True})
    assert 'filesystem' not in json.loads(SubprocessCLITransport(prompt='test',options=lossy)._build_settings_value())['sandbox']


@pytest.mark.parametrize('result,expected',[
    (terminal(result='Audit complete. [] No vulnerabilities found.'),None),
    (terminal(structured_output={'findings':[]}),None),
    (terminal(structured_output={'findings':[{'type':'SQLi','file':'app.js','line':3}]}),None),
    (terminal(structured_output={}), 'runner'),
    (terminal(structured_output={'findings':'not an array'}),'runner'),
    (terminal(structured_output={'findings':[42]}),'runner'),
    (terminal(result='FINDINGS_JSON: ```json broken ```'),'runner'),
    (terminal(is_error=True,errors=['not authenticated']),'runner'),
])
def test_output_shapes(setup,result,expected):
    project,refs,task=setup
    async def query(**kwargs): yield result
    with patch.object(sdk,'query',query),patch('vulnbench.runners.claude_code.check_sandbox_available',available):
        output=asyncio.run(ClaudeCodeRunner(refs).run(task,RunConfig(id='test'),project))
    assert output.failure==expected
    if not expected: assert output.metrics['usage']['input_tokens']==10


def test_assistant_text_blocks_join_and_subagents_do_not_replace_final(setup):
    project,refs,task=setup
    async def query(**kwargs):
        yield sdk.AssistantMessage(content=[sdk.TextBlock('FINDINGS_JSON:\n```json'),sdk.TextBlock('[{"type":"xss"}]\n```')],model='mock')
        yield sdk.AssistantMessage(content=[sdk.TextBlock('subagent notes')],model='mock',parent_tool_use_id='subagent')
        yield terminal(result=None)
    with patch.object(sdk,'query',query),patch('vulnbench.runners.claude_code.check_sandbox_available',available):
        output=asyncio.run(ClaudeCodeRunner(refs).run(task,RunConfig(id='test'),project))
    assert not output.failure and output.findings[0].type=='xss'


def test_hooks_timing_files_failures_and_denials(setup):
    project,refs,task=setup
    async def query(*,prompt,options):
        pre=options.hooks['PreToolUse'][0].hooks[0]
        post=options.hooks['PostToolUse'][0].hooks[0]
        failure=options.hooks['PostToolUseFailure'][0].hooks[0]
        data={'tool_name':'Read','tool_input':{'file_path':str(refs/'findings.json')}}
        denial=await pre(data,'outside',{})
        assert denial['hookSpecificOutput']['permissionDecision']=='deny'
        await pre({'tool_name':'Read','tool_input':{'file_path':'app.js'}},'inside',{})
        await post({'tool_response':'source'},'inside',{})
        await pre({'tool_name':'Bash','tool_input':{'command':'false'}},'bash',{})
        await failure({'hook_event_name':'PostToolUseFailure','error':'exit 1'},'bash',{})
        yield terminal()
    with patch.object(sdk,'query',query),patch('vulnbench.runners.claude_code.check_sandbox_available',available):
        output=asyncio.run(ClaudeCodeRunner(refs).run(task,RunConfig(id='test'),project))
    assert len(output.metrics['tool_denials'])==1
    assert output.metrics['files_accessed']==['app.js']
    assert len(output.metrics['toolCalls'])==2
    assert output.metrics['toolCalls'][1]['failed']
    assert output.metrics['toolCalls'][0]['durationMs']>=0
    assert output.metrics['usage']['input_tokens']==10  # Unchanged by tool estimates.


def test_preflight_failure_never_queries_model(setup):
    project,refs,task=setup
    async def unavailable(): raise ContainmentError('sandbox blocked')
    async def forbidden(**kwargs):
        pytest.fail('Model execution after failed sandbox preflight')
        yield terminal()
    with patch.object(sdk,'query',forbidden),patch('vulnbench.runners.claude_code.check_sandbox_available',unavailable):
        output=asyncio.run(ClaudeCodeRunner(refs).run(task,RunConfig(id='test'),project))
    assert output.failure=='containment' and 'sandbox blocked' in output.error


def test_real_sdk_control_protocol_routes_hook_callbacks(setup):
    """The installed SDK handles real control frames, not patched SDK classes.

    Only the CLI peer is deterministic; this does not prove OS enforcement.
    """
    from claude_agent_sdk._internal.transport import Transport
    project,refs,task=setup
    captured=[]
    class Peer(Transport):
        async def connect(self): self.queue=asyncio.Queue(); self.ready=True
        async def write(self,data):
            message=json.loads(data)
            if message['type']=='control_request':
                request=message['request']
                self.hook=request['hooks']['PreToolUse'][0]['hookCallbackIds'][0]
                assert request['hooks']['PreToolUse'][0]['onFailure']=='block'
                await self.queue.put({'type':'control_response','response':{'subtype':'success','request_id':message['request_id'],'response':{'hook_on_failure_supported':True,'hooks_applied':True}}})
            elif message['type']=='user':
                await self.queue.put({'type':'control_request','request_id':'probe','request':{'subtype':'hook_callback','callback_id':self.hook,'tool_use_id':'reference-read','input':{'hook_event_name':'PreToolUse','tool_name':'Read','tool_input':{'file_path':str(refs/'findings.json')}}}})
            elif message['type']=='control_response':
                captured.append(message['response']['response'])
                await self.queue.put({'type':'result','subtype':'success','duration_ms':10,'duration_api_ms':8,'is_error':False,'num_turns':1,'session_id':'peer','usage':{},'result':'FINDINGS_JSON: ```json [] ```'})
                await self.queue.put(None)
        async def read_messages(self):
            while (message:=await self.queue.get()) is not None: yield message
        async def close(self): self.ready=False
        def is_ready(self): return self.ready
        async def end_input(self): pass
    real_query=sdk.query
    async def query(*,prompt,options):
        async for message in real_query(prompt=prompt,options=options,transport=Peer()): yield message
    with patch.object(sdk,'query',query),patch('vulnbench.runners.claude_code.check_sandbox_available',available):
        output=asyncio.run(ClaudeCodeRunner(refs).run(task,RunConfig(id='test'),project))
    assert not output.failure
    assert captured[0]['hookSpecificOutput']['permissionDecision']=='deny'
    assert output.metrics['tool_denials'][0]['tool']=='Read'

def test_recursive_search_refuses_links_created_after_workspace_copy(setup, make_symlink):
    project,refs,_=setup
    make_symlink(project/'leak', refs, target_is_directory=True)
    assert denied_tool_reason('Grep',{'pattern':'SECRET'},project)
    assert denied_tool_reason('Glob',{'pattern':'**/*'},project)


def test_turns_thinking_and_budget_options_reach_installed_sdk(setup):
    project,refs,task=setup
    task.maxTurns=4
    captured=[]
    async def query(*,prompt,options):
        captured.append(options)
        transport=SubprocessCLITransport(prompt=prompt,options=options)
        transport._cli_path='/unused/claude'
        argv=transport._build_command()
        assert argv[argv.index('--max-turns')+1]=='4'
        assert argv[argv.index('--max-thinking-tokens')+1]=='1234'
        assert argv[argv.index('--effort')+1]=='medium'
        yield terminal()
    config=RunConfig(id='test',model='claude-opus-4-6',maxTurns=9,effort='medium',thinking={'type':'enabled','budgetTokens':1234},structuredOutput=True)
    with patch.object(sdk,'query',query),patch('vulnbench.runners.claude_code.check_sandbox_available',available):
        output=asyncio.run(ClaudeCodeRunner(refs).run(task,config,project))
    assert not output.failure
    assert captured[0].output_format['schema']['required']==['findings']
