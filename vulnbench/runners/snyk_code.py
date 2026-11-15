import asyncio, time, shlex
from ..models import RunOutput
from ..parsers.snyk_sarif import parse_snyk

class ProcessTimeoutError(TimeoutError):
    def __init__(self, stdout, stderr, exit_status):
        super().__init__('Scanner execution timed out')
        self.stdout, self.stderr, self.exit_status = stdout, stderr, exit_status


async def execute(argv,cwd,timeout):
    process=await asyncio.create_subprocess_exec(*argv,cwd=cwd,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True)
    communication=asyncio.create_task(process.communicate())
    try:
        stdout,stderr=await asyncio.wait_for(asyncio.shield(communication),timeout)
    except BaseException as error:
        import os,signal
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        stdout,stderr=await communication
        if isinstance(error,TimeoutError):
            raise ProcessTimeoutError(stdout.decode(errors='replace'),stderr.decode(errors='replace'),process.returncode) from error
        raise
    return stdout.decode(errors='replace'),stderr.decode(errors='replace'),process.returncode

class SnykCodeRunner:
    async def run(self,task,config,cwd):
        start=time.monotonic(); metrics={}
        try:
            extra=config.model_extra
            if extra.get('parser','snyk-code')!='snyk-code': raise ValueError('Only snyk-code parser supported')
            argv=[extra.get('executable','snyk'),*extra.get('args',['code','test','{fixturePath}','--json'])]
            if extra.get('command'): argv=shlex.split(extra['command'])
            argv=[a.replace('{fixturePath}',str(cwd)) for a in argv]
            stdout,stderr,status=await execute(argv,cwd,config.timeoutMs/1000)
            metrics.update(stdout=stdout,stderr=stderr,exit_status=status)
            findings=parse_snyk(stdout,strict=True)
            if status not in (0,1): raise ValueError(f'Snyk execution failed ({status}): {stderr or stdout}')
            metrics.update(finding_count=len(findings),files_referenced=sorted({f.file for f in findings if f.file}))
            metrics['sessionDurationMs']=(time.monotonic()-start)*1000
            return RunOutput(final_text=stdout,findings=findings,metrics=metrics)
        except Exception as error:
            metrics.update({key:getattr(error,key) for key in ('stdout','stderr','exit_status') if hasattr(error,key)})
            metrics['sessionDurationMs']=(time.monotonic()-start)*1000
            return RunOutput(metrics=metrics,failure='timeout' if isinstance(error,TimeoutError) else 'runner',error=str(error))
        finally: metrics['sessionDurationMs']=(time.monotonic()-start)*1000
