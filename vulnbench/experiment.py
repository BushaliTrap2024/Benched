from datetime import datetime,timezone
import hashlib
import sys
from .config import load_task,load_config
from .workspace import isolated_workspace
from .scoring import score
from .storage import append_record
from .runners.claude_code import ClaudeCodeRunner
from .runners.snyk_code import SnykCodeRunner

async def run(root,tasks,configs,repetitions,path,runner_factory=None):
    if repetitions<1: raise ValueError('Repetitions must be positive')
    records=[]
    total=len(tasks)*len(configs)*repetitions
    failed=0
    print(f'Planned executions: {total}',file=sys.stderr,flush=True)
    for task_id in tasks:
        task,fixture,refs=load_task(root,task_id)
        for config_id in configs:
            config=load_config(root,config_id)
            for repetition in range(1,repetitions+1):
                progress=len(records)+1
                print(f'[{progress}/{total}] Starting task={task.name} ({task.id}) '
                      f'fixture={task.fixture} config={config.id} repetition={repetition}/{repetitions}',
                      file=sys.stderr,flush=True)
                runner=runner_factory(config) if runner_factory else SnykCodeRunner() if config.type=='command' else ClaudeCodeRunner(root/'fixtures')
                with isolated_workspace(fixture/'project') as cwd:
                    output=await runner.run(task,config,cwd)
                record=dict(task_id=task.id,fixture_id=task.fixture,config_id=config.id,configuration=config.model_dump(),
                    task=task.model_dump(),reference_sha256=hashlib.sha256((fixture/'findings.json').read_bytes()).hexdigest(),
                    repetition=repetition,total_repetitions=repetitions,timestamp=datetime.now(timezone.utc).isoformat(),
                    **output.model_dump(),score=None if output.failure or output.error else score(output.findings,refs.vulnerabilities))
                append_record(path,record); records.append(record)
                did_fail=bool(output.failure or output.error)
                failed+=did_fail
                duration_ms=output.metrics.get('sessionDurationMs')
                duration=f'{duration_ms} ms' if duration_ms is not None else 'unknown'
                status='FAILED' if did_fail else 'SUCCEEDED'
                print(f'[{progress}/{total}] {status} duration={duration} '
                      f'completed={len(records)}/{total} failed={failed}',file=sys.stderr,flush=True)
    return records
