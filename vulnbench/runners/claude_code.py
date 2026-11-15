import asyncio,json,time
from pathlib import Path
from ..models import Finding,RunOutput
from ..metrics import tool_stats
from ..parsers.claude_findings import parse_findings

class ClaudeCodeRunner:
    def __init__(self, reference_root=None):
        self.reference_root=Path(reference_root).resolve() if reference_root else Path(__file__).resolve().parents[2]/"fixtures"

    async def run(self,task,config,cwd):
        from claude_agent_sdk import query,ClaudeAgentOptions,HookMatcher,AssistantMessage,TextBlock,ResultMessage
        start=time.monotonic(); calls=[]; active={}; files=set(); metrics={'toolCalls':calls}; final=''; terminal=None
        async def pre(data,tool_id,context):
            tool=data.get('tool_name',''); args=data.get('tool_input',{})
            # Native file tools must remain within the disposable project.
            if tool in ('Read','Write','Edit','Glob','Grep'):
                path=args.get('file_path',args.get('path',str(cwd)))
                target=(cwd/str(path)).resolve()
                if not target.is_relative_to(cwd.resolve()):
                    return {'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny','permissionDecisionReason':'Outside isolated project'}}
                files.add(str(target.relative_to(cwd)))
            active[tool_id]=(time.monotonic(),tool,len(json.dumps(args))/4)
            return {}
        async def post(data,tool_id,context):
            if tool_id in active:
                began,tool,estimated=active.pop(tool_id)
                calls.append(dict(tool=tool,durationMs=(time.monotonic()-began)*1000,inputTokensEst=estimated,
                    outputTokensEst=len(json.dumps(data.get('tool_response',{}),default=str))/4))
            return {}
        try:
            extra=config.model_extra
            effort=None if config.effort=='default' else config.effort
            if effort not in (None,'low','medium','high','xhigh','max'): raise ValueError('Unsupported Python SDK effort')
            # Filesystem settings are passed through Claude Code settings because
            # Python SandboxSettings currently has no filesystem typed field.
            denied=[str(self.reference_root)]
            settings={'sandbox':{'filesystem':{'denyRead':denied,'allowRead':[str(cwd)],'allowWrite':[str(cwd)]}},
                      'permissions':{'deny':[f'Read({p}/**)' for p in denied[:1]]}}
            options=ClaudeAgentOptions(cwd=str(cwd),model=config.model,system_prompt=extra.get('systemPrompt',task.systemPrompt),
                max_turns=task.maxTurns or config.maxTurns,effort=effort,thinking=extra.get('thinking',{'type':'adaptive'}),
                tools=config.allowedTools,allowed_tools=config.allowedTools,permission_mode='bypassPermissions',
                setting_sources=[],strict_mcp_config=True,mcp_servers={},settings=json.dumps(settings),
                sandbox={'enabled':True,'allowUnsandboxedCommands':False},
                hooks={'PreToolUse':[HookMatcher(hooks=[pre])],'PostToolUse':[HookMatcher(hooks=[post])]},
                output_format={'type':'json_schema','schema':{'type':'object','properties':{'findings':{'type':'array','items':Finding.model_json_schema()}},'required':['findings']}} if config.structuredOutput else None)
            async with asyncio.timeout(config.timeoutMs/1000):
                async for message in query(prompt=extra.get('prompt',task.prompt),options=options):
                    if isinstance(message,AssistantMessage):
                        for block in message.content:
                            if isinstance(block,TextBlock): final=block.text
                    elif isinstance(message,ResultMessage): terminal=message
            if terminal is None: raise ValueError('SDK stream ended without result')
            metrics.update(usage=terminal.usage,totalCostUsd=terminal.total_cost_usd,totalTurns=terminal.num_turns,session_id=terminal.session_id)
            final=terminal.result or final
            if terminal.is_error: raise RuntimeError('; '.join(terminal.errors or [terminal.subtype]))
            structured=terminal.structured_output
            findings=parse_findings(structured.get('findings') if isinstance(structured,dict) else structured) if structured is not None else parse_findings(final)
            # Empty valid arrays are successful; missing/malformed findings are not.
            if structured is None and not findings:
                import re
                marker=re.search(r'FINDINGS_JSON:\s*```(?:json)?\s*([\s\S]*?)```',final,re.I)
                candidate=marker[1] if marker else final.strip()
                if json.loads(candidate)!=[]: raise ValueError('Missing or malformed findings output')
            output=RunOutput(final_text=final,findings=findings)
        except Exception as error:
            output=RunOutput(final_text=final,failure='timeout' if isinstance(error,TimeoutError) else 'runner',error=str(error))
        metrics.update(sessionDurationMs=(time.monotonic()-start)*1000,files_accessed=sorted(files))
        metrics['toolStats']=tool_stats(calls)
        output.metrics=metrics
        return output
