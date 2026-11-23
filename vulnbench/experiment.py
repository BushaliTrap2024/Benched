from datetime import datetime,timezone
import hashlib
import sys
from pathlib import Path
from .config import execution_sources,load_config
from .workspace import isolated_workspace
from .scoring import score
from .storage import append_record, read_records, reject_duplicates, source_identity, output_lock
from .runners.claude_code import ClaudeCodeRunner
from .runners.snyk_code import SnykCodeRunner

async def run(root,tasks,configs,repetitions,path,runner_factory=None, *, variant=None, all_variants=False):
    with output_lock(path):
        return await _run(root, tasks, configs, repetitions, path, runner_factory, variant, all_variants)


async def _run(root, tasks, configs, repetitions, path, runner_factory, variant, all_variants):
    if repetitions<1: raise ValueError('Repetitions must be positive')
    sources = list(execution_sources(root, tasks, variant, all_variants))
    configurations = [load_config(root, config_id) for config_id in configs]
    path = Path(path)
    existing = read_records(path) if path.exists() else []
    if variant is not None or all_variants:
        if any(record.get('variant_id') is None for record in existing):
            raise ValueError('Use a separate output file for transformed executions')
        keys = reject_duplicates(existing)
        plan = [
            dict(task_id=task.id, variant_id=variant_id, config_id=config.id, repetition=rep)
            for task, _, _, _, variant_id in sources for config in configurations
            for rep in range(1, repetitions + 1)
        ]
        overlap = keys & reject_duplicates(plan)
        if overlap:
            raise ValueError(f'Output already contains execution {min(overlap)!r}; use a fresh output file')
    elif any(record.get('variant_id') is not None for record in existing):
        raise ValueError('Use a separate output file for original executions')
    records=[]
    total=len(sources)*len(configurations)*repetitions
    failed=0
    print(f'Planned executions: {total}',file=sys.stderr,flush=True)
    for task,fixture,refs,project,variant_id in sources:
        identity = source_identity(variant_id)
        for config in configurations:
            for repetition in range(1,repetitions+1):
                progress=len(records)+1
                print(f'[{progress}/{total}] Starting task={task.name} ({task.id}) '
                      f'fixture={task.fixture} variant={variant_id} config={config.id} repetition={repetition}/{repetitions}',
                      file=sys.stderr,flush=True)
                runner=runner_factory(config) if runner_factory else SnykCodeRunner() if config.type=='command' else ClaudeCodeRunner(root/'fixtures')
                with isolated_workspace(project) as cwd:
                    output=await runner.run(task,config,cwd)
                record=dict(task_id=task.id,fixture_id=task.fixture,config_id=config.id,configuration=config.model_dump(),
                    task=task.model_dump() | identity,**identity,reference_sha256=hashlib.sha256((fixture/'findings.json').read_bytes()).hexdigest(),
                    reference_ids=[ref.id for ref in refs.vulnerabilities],
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
