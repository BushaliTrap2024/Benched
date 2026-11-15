import asyncio
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time
from ..models import RunOutput
from ..parsers.snyk_sarif import parse_snyk


def _is_windows():
    return sys.platform == 'win32'


def resolve_command(argv, *, windows=None):
    """Resolve native executables or npm's Snyk entrypoint without cmd.exe.

    .cmd/.bat wrappers do not have argv semantics on Windows. In the standard
    npm global/local layout, execute the package's declared JS entrypoint with
    node.exe instead. No batch-script contents or scanner arguments are parsed
    by a shell. A standalone snyk.exe works directly.
    """
    argv = [str(arg) for arg in argv]
    if not argv:
        raise ValueError('Empty scanner command')
    if windows is None:
        windows = _is_windows()
    if not windows:
        return argv
    executable = shutil.which(argv[0])
    if executable is None:
        raise FileNotFoundError(f'Scanner executable not found: {argv[0]}. Install Snyk and add its folder to PATH.')
    path = Path(executable)
    if path.suffix.lower() not in ('.cmd', '.bat'):
        return [str(path), *argv[1:]]
    if path.stem.lower() != 'snyk':
        raise ValueError('Windows batch wrappers are unsupported; use a native executable with an args array')
    packages = [path.parent / 'node_modules' / 'snyk', path.parent.parent / 'snyk']
    for package in packages:
        manifest = package / 'package.json'
        if not manifest.is_file():
            continue
        metadata = json.loads(manifest.read_text(encoding='utf-8'))
        entry = metadata.get('bin', {})
        entry = entry.get('snyk') if isinstance(entry, dict) else entry
        if metadata.get('name') != 'snyk' or not isinstance(entry, str):
            continue
        script = (package / entry).resolve()
        if not script.is_relative_to(package.resolve()) or not script.is_file():
            raise ValueError('Invalid Snyk npm entrypoint; install the official CLI or use snyk.exe')
        adjacent_node = path.parent / 'node.exe'
        node = str(adjacent_node) if adjacent_node.is_file() else shutil.which('node.exe') or shutil.which('node')
        if not node or Path(node).suffix.lower() in ('.cmd', '.bat'):
            raise FileNotFoundError('node.exe is required for the npm Snyk CLI; alternatively install standalone snyk.exe')
        return [node, str(script), *argv[1:]]
    raise ValueError('Cannot resolve the npm snyk.cmd entrypoint. Reinstall the official npm package or use standalone snyk.exe.')


def split_legacy_command(command):
    if not _is_windows():
        return shlex.split(command)
    # Match Windows command-line quoting without running cmd.exe/PowerShell.
    import ctypes
    from ctypes import wintypes
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    count = ctypes.c_int()
    result = shell32.CommandLineToArgvW(command, ctypes.byref(count))
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return [result[i] for i in range(count.value)]
    finally:
        kernel32.LocalFree(result)


class ProcessTimeoutError(TimeoutError):
    def __init__(self, stdout, stderr, exit_status):
        super().__init__('Scanner execution timed out')
        self.stdout, self.stderr, self.exit_status = stdout, stderr, exit_status


async def terminate_process_tree(process, *, windows=None):
    if windows is None:
        windows = _is_windows()
    if not windows:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return
    # Windows' kill()/terminate() only stops the parent. taskkill /T includes
    # descendants, and /F is needed for non-console scanner subprocesses.
    system_root = os.environ.get('SystemRoot', r'C:\Windows')
    taskkill = str(Path(system_root) / 'System32' / 'taskkill.exe')
    killer = await asyncio.create_subprocess_exec(
        taskkill, '/PID', str(process.pid), '/T', '/F',
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    try:
        _, stderr = await asyncio.wait_for(killer.communicate(), 10)
    except BaseException:
        if killer.returncode is None:
            killer.kill()
        await killer.wait()
        if process.returncode is None:
            process.kill()
        raise
    if killer.returncode and process.returncode is None:
        process.kill()
        raise RuntimeError('Windows scanner process-tree termination failed: ' + stderr.decode(errors='replace').strip())


async def execute(argv, cwd, timeout):
    windows = _is_windows()
    command = resolve_command(argv, windows=windows)
    spawn_options = {'creationflags': getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x200)} if windows else {'start_new_session': True}
    process = await asyncio.create_subprocess_exec(
        *command, cwd=cwd, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, **spawn_options)
    stdout, stderr = bytearray(), bytearray()

    async def drain(stream, destination):
        while chunk := await stream.read(65536):
            destination.extend(chunk)

    pumps = [asyncio.create_task(drain(process.stdout, stdout)), asyncio.create_task(drain(process.stderr, stderr))]

    async def finish():
        await process.wait()
        await asyncio.gather(*pumps)

    completion = asyncio.create_task(finish())
    try:
        await asyncio.wait_for(asyncio.shield(completion), timeout)
    except BaseException as error:
        cleanup_error = None
        try:
            await terminate_process_tree(process, windows=windows)
        except Exception as failure:
            cleanup_error = failure
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        try:
            await asyncio.wait_for(asyncio.shield(completion), 10)
        except TimeoutError:
            cleanup_error = RuntimeError('Scanner process-tree cleanup did not finish; inherited output pipes remain open')
            completion.cancel()
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(completion, *pumps, return_exceptions=True)
        if cleanup_error is not None:
            cleanup_error.stdout = stdout.decode('utf-8', errors='replace')
            cleanup_error.stderr = stderr.decode('utf-8', errors='replace')
            cleanup_error.exit_status = process.returncode
            raise cleanup_error from error
        if isinstance(error, TimeoutError):
            raise ProcessTimeoutError(stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace'), process.returncode) from error
        raise
    return stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace'), process.returncode


class SnykCodeRunner:
    async def run(self, task, config, cwd):
        start = time.monotonic()
        metrics = {}
        try:
            extra = config.model_extra
            if extra.get('parser', 'snyk-code') != 'snyk-code':
                raise ValueError('Only snyk-code parser supported')
            argv = [extra.get('executable', 'snyk'), *extra.get('args', ['code', 'test', '{fixturePath}', '--json'])]
            if extra.get('command'):
                argv = split_legacy_command(extra['command'])
            argv = [a.replace('{fixturePath}', str(cwd)) for a in argv]
            stdout, stderr, status = await execute(argv, cwd, config.timeoutMs / 1000)
            metrics.update(stdout=stdout, stderr=stderr, exit_status=status)
            findings = parse_snyk(stdout, strict=True)
            if status not in (0, 1):
                raise ValueError(f'Snyk execution failed ({status}): {stderr or stdout}')
            metrics.update(finding_count=len(findings), files_referenced=sorted({f.file for f in findings if f.file}))
            metrics['sessionDurationMs'] = (time.monotonic()-start)*1000
            return RunOutput(final_text=stdout, findings=findings, metrics=metrics)
        except Exception as error:
            metrics.update({key: getattr(error, key) for key in ('stdout', 'stderr', 'exit_status') if hasattr(error, key)})
            metrics['sessionDurationMs'] = (time.monotonic()-start)*1000
            return RunOutput(metrics=metrics, failure='timeout' if isinstance(error, TimeoutError) else 'runner', error=str(error))
