"""Windows branches run with mocks on every OS; marked tests need Windows."""
import asyncio
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import pytest

from vulnbench.config import ROOT, load_task
from vulnbench.models import RunConfig, Task
from vulnbench.references.generate import _local_sarif_path, _project_relative_path
from vulnbench.runners.claude_code import ClaudeCodeRunner, ContainmentError, check_sandbox_available, sandbox_settings
from vulnbench.runners.snyk_code import ProcessTimeoutError, execute, resolve_command, split_legacy_command, terminate_process_tree
from vulnbench.storage import append_record, read_records
from vulnbench.workspace import _is_link_or_reparse_point, isolated_workspace


def npm_fixture(tmp_path, local=False):
    if local:
        shim=tmp_path/'node_modules/.bin/snyk.cmd'
        package=tmp_path/'node_modules/snyk'
    else:
        shim=tmp_path/'npm with spaces/snyk.cmd'
        package=shim.parent/'node_modules/snyk'
    shim.parent.mkdir(parents=True,exist_ok=True)
    shim.write_text('@echo off\nREM This wrapper must never execute\n',encoding='utf-8')
    (package/'bin').mkdir(parents=True,exist_ok=True)
    (package/'package.json').write_text(json.dumps({'name':'snyk','bin':{'snyk':'bin/snyk'}}),encoding='utf-8')
    script=package/'bin/snyk'
    script.write_text('process.stdout.write(JSON.stringify(process.argv.slice(2)));',encoding='utf-8')
    return shim,package,script


@pytest.mark.parametrize('local',[False,True])
def test_windows_npm_resolution_without_shell(tmp_path,local):
    shim,package,script=npm_fixture(tmp_path,local)
    def which(name):
        return str(shim) if name=='snyk' else 'node.exe' if name in ('node.exe','node') else None
    args=['code','test',r'C:\My Projects\repo & more',r'--json-file-output=C:\output path\résult.json']
    with patch('vulnbench.runners.snyk_code.shutil.which',side_effect=which):
        assert resolve_command(['snyk',*args],windows=True)==['node.exe',str(script.resolve()),*args]


def test_windows_standalone_executable_and_missing_cli():
    with patch('vulnbench.runners.snyk_code.shutil.which',return_value=r'C:\Tools\snyk.exe'):
        assert resolve_command(['snyk','code','test'],windows=True)==[r'C:\Tools\snyk.exe','code','test']
    with patch('vulnbench.runners.snyk_code.shutil.which',return_value=None):
        with pytest.raises(FileNotFoundError,match='Scanner executable not found'):
            resolve_command(['snyk'],windows=True)


def test_windows_batch_wrappers_fail_explicitly_when_not_supported(tmp_path):
    script=tmp_path/'custom.cmd'; script.write_text('anything')
    with patch('vulnbench.runners.snyk_code.shutil.which',return_value=str(script)):
        with pytest.raises(ValueError,match='Windows batch wrappers'):
            resolve_command([str(script)],windows=True)
    script=tmp_path/'snyk.cmd'; script.write_text('anything')
    with patch('vulnbench.runners.snyk_code.shutil.which',return_value=str(script)):
        with pytest.raises(ValueError,match='Cannot resolve'):
            resolve_command([str(script)],windows=True)


def test_actual_node_entrypoint_preserves_metacharacters_without_executing_cmd(tmp_path):
    node=shutil.which('node')
    if not node: pytest.skip('Node needed to execute official npm-style entrypoint fixture')
    shim,package,script=npm_fixture(tmp_path)
    def which(name): return str(shim) if name==str(shim) else node
    args=['space value','& echo NOT_A_COMMAND','%PATH%','^escape','quote"value','Unicode café']
    with patch('vulnbench.runners.snyk_code.shutil.which',side_effect=which):
        command=resolve_command([str(shim),*args],windows=True)
    output=subprocess.check_output(command,text=True,encoding='utf-8')
    assert json.loads(output)==args


def test_windows_process_creation_and_timeout_preserve_output(tmp_path):
    async def test():
        out,err=asyncio.StreamReader(),asyncio.StreamReader()
        out.feed_data('résult'.encode('utf-8')); err.feed_data(b'warning')
        stopped=asyncio.Event()
        process=SimpleNamespace(pid=42,returncode=None,stdout=out,stderr=err)
        async def wait(): await stopped.wait(); return process.returncode
        process.wait=wait
        async def stop(process,*,windows):
            assert windows is True
            process.returncode=-1; out.feed_eof(); err.feed_eof(); stopped.set()
        create=AsyncMock(return_value=process)
        with patch('vulnbench.runners.snyk_code._is_windows',return_value=True),patch('vulnbench.runners.snyk_code.resolve_command',return_value=['snyk.exe','code']),patch('vulnbench.runners.snyk_code.asyncio.create_subprocess_exec',create),patch('vulnbench.runners.snyk_code.terminate_process_tree',side_effect=stop):
            with pytest.raises(ProcessTimeoutError) as error: await execute(['snyk','code'],tmp_path,.02)
        assert error.value.stdout=='résult' and error.value.stderr=='warning'
        options=create.call_args.kwargs
        assert options['creationflags']==0x200 and 'start_new_session' not in options
    asyncio.run(test())


def test_windows_tree_termination_uses_taskkill_not_killpg():
    process=SimpleNamespace(pid=42,returncode=None,kill=lambda:pytest.fail('unexpected parent fallback'))
    killer=SimpleNamespace(returncode=0,communicate=AsyncMock(return_value=(b'',b'')))
    create=AsyncMock(return_value=killer)
    with patch('vulnbench.runners.snyk_code.asyncio.create_subprocess_exec',create):
        asyncio.run(terminate_process_tree(process,windows=True))
    args=create.call_args.args
    assert Path(args[0]).name.lower()=='taskkill.exe'
    assert args[1:]==('/PID','42','/T','/F')


def test_windows_claude_cannot_query_model_without_supported_shell_sandbox(tmp_path):
    cwd=tmp_path/'isolated/project'; cwd.mkdir(parents=True)
    references=tmp_path/'benchmark/fixtures'; references.mkdir(parents=True)
    task=Task(id='test',name='test',fixture='test',category='find-vulns',systemPrompt='system',prompt='audit')
    async def query(**kwargs):
        pytest.fail('Unsupported Windows sandbox must fail before a model query')
        yield None
    with patch('vulnbench.runners.claude_code.sys',SimpleNamespace(platform='win32')),patch('claude_agent_sdk.query',query):
        result=asyncio.run(ClaudeCodeRunner(references).run(task,RunConfig(id='test'),cwd))
    assert result.failure=='containment'
    assert 'Native Windows Claude Code' in result.error and 'No model was started' in result.error
    assert not result.findings


def test_sdk_must_fail_if_sandbox_becomes_unavailable(tmp_path):
    settings=sandbox_settings(tmp_path/'project',tmp_path/'benchmark/fixtures')['sandbox']
    assert settings['enabled'] and settings['failIfUnavailable']
    assert settings['allowUnsandboxedCommands'] is False and settings['filesystem']['denyRead']


@pytest.mark.parametrize('uri,expected',[
    (r'C:\Projects\Demo\app.js','C:/Projects/Demo/app.js'),
    ('C:/Projects/Demo/app.js','C:/Projects/Demo/app.js'),
    ('file:///C:/Projects/My%20App/app.js','C:/Projects/My App/app.js'),
    ('file://localhost/C:/Projects/Demo/app.js','C:/Projects/Demo/app.js'),
    (r'src\view.js','src/view.js'),
])
def test_windows_sarif_paths(uri,expected):
    assert _local_sarif_path(uri)==expected


@pytest.mark.parametrize('uri',['C:app.js','file://server/share/app.js',r'\\server\share\app.js'])
def test_ambiguous_or_remote_windows_sarif_paths_fail(uri):
    with pytest.raises(ValueError): _local_sarif_path(uri)


def test_utf8_prompts_and_result_records_are_locale_independent(tmp_path):
    task,_,_=load_task(ROOT,'js-project-tigerteam-find-vulns')
    defaults=json.loads((ROOT/'evals/prompts.json').read_text(encoding='utf-8'))
    assert task.systemPrompt==defaults['systemPrompt']
    path=tmp_path/'results.jsonl'; record={'message':'café — 测试'}
    append_record(path,record)
    assert json.loads(path.read_bytes().decode('utf-8'))==record
    assert read_records(path)==[record]


def test_windows_junction_attribute_rejected_without_following_it(tmp_path):
    fake=SimpleNamespace(lstat=lambda:SimpleNamespace(st_mode=0o40755,st_file_attributes=0x400))
    assert _is_link_or_reparse_point(fake)


@pytest.mark.skipif(sys.platform!='win32',reason='Requires native Windows process/command-line APIs')
def test_native_windows_legacy_argv_and_sarif_file_uri(tmp_path):
    argv=[r'C:\Program Files\Snyk\snyk.exe','code','test',r'C:\My App\project','--json']
    assert split_legacy_command(subprocess.list2cmdline(argv))==argv
    root=tmp_path/'benchmark'; project=root/'fixtures/demo/project'; project.mkdir(parents=True)
    assert _project_relative_path((project/'app.js').as_uri(),root,project)=='app.js'
    assert _project_relative_path(str(project/'app.js'),root,project)=='app.js'
    assert _project_relative_path('src/view.js',root,project)=='src/view.js'
    assert _project_relative_path('app.js',root,project,project.as_uri()+'/')=='app.js'


@pytest.mark.skipif(sys.platform!='win32',reason='Requires native Windows taskkill and subprocess APIs')
def test_native_windows_timeout_kills_child_tree(tmp_path):
    script=tmp_path/'scanner.py'; child_marker=tmp_path/'escaped-child.txt'
    child='import time,pathlib; time.sleep(4); pathlib.Path('+repr(str(child_marker))+').write_text("survived")'
    script.write_text('import subprocess,sys,time\nsubprocess.Popen([sys.executable,"-c",'+repr(child)+'])\nprint("child spawned",flush=True)\ntime.sleep(30)\n',encoding='utf-8')
    async def test():
        with pytest.raises(ProcessTimeoutError) as error:
            await execute([sys.executable,str(script)],tmp_path,1.5)
        assert 'child spawned' in error.value.stdout
        await asyncio.sleep(4.5)
        assert not child_marker.exists()
    asyncio.run(test())


@pytest.mark.skipif(sys.platform!='win32',reason='Requires native Windows npm shim resolution')
def test_native_windows_npm_snyk_shim_execution(tmp_path):
    if not shutil.which('node'): pytest.skip('Node required for npm Snyk')
    shim,_,_=npm_fixture(tmp_path)
    output,stderr,status=asyncio.run(execute([str(shim),'code','test','space & value','--json'],tmp_path,10))
    assert status==0 and not stderr
    assert json.loads(output)==['code','test','space & value','--json']

@pytest.mark.parametrize('platform,dependency', [('darwin','sandbox-exec'),('linux','bwrap')])
def test_existing_posix_sandbox_prerequisites_remain_enforced(platform,dependency):
    with patch('vulnbench.runners.claude_code.sys',SimpleNamespace(platform=platform)),patch('vulnbench.runners.claude_code.shutil.which',return_value=None):
        with pytest.raises(ContainmentError,match=dependency): asyncio.run(check_sandbox_available())


def test_macos_sandbox_prerequisite_passes_when_available():
    with patch('vulnbench.runners.claude_code.sys',SimpleNamespace(platform='darwin')),patch('vulnbench.runners.claude_code.shutil.which',return_value='/usr/bin/sandbox-exec'):
        asyncio.run(check_sandbox_available())


def test_linux_sandbox_probe_failure_is_still_fatal():
    process=SimpleNamespace(returncode=1,communicate=AsyncMock(return_value=(b'',b'namespace denied')))
    with patch('vulnbench.runners.claude_code.sys',SimpleNamespace(platform='linux')),patch('vulnbench.runners.claude_code.shutil.which',return_value='/usr/bin/available'),patch('vulnbench.runners.claude_code.asyncio.create_subprocess_exec',AsyncMock(return_value=process)):
        with pytest.raises(ContainmentError,match='namespace denied'): asyncio.run(check_sandbox_available())

@pytest.mark.skipif(sys.platform!='win32',reason='Requires a native NTFS junction')
def test_native_windows_junction_cannot_copy_external_reference(tmp_path):
    import os
    project=tmp_path/'project'; project.mkdir()
    outside=tmp_path/'reference'; outside.mkdir()
    (outside/'findings.json').write_text('REFERENCE_SECRET',encoding='utf-8')
    junction=project/'linked-reference'
    created=subprocess.run([os.environ.get('COMSPEC',r'C:\Windows\System32\cmd.exe'),'/d','/c','mklink','/J',str(junction),str(outside)],capture_output=True,text=True)
    if created.returncode: pytest.skip('Host cannot create NTFS junction: '+created.stderr)
    with pytest.raises(ValueError,match='reparse'):
        with isolated_workspace(project): pytest.fail('Junction must not be copied')
