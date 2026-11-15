import asyncio
import json
from pathlib import Path
import sys
from unittest.mock import patch
import pytest
from vulnbench.references.generate import generate, _project_relative_path
from vulnbench.runners.snyk_code import execute, ProcessTimeoutError

SAMPLE=Path(__file__).with_name('data')/'snyk-code-representative.sarif.json'


@pytest.fixture
def root(tmp_path):
    project=tmp_path/'fixtures/demo/project'; project.mkdir(parents=True)
    (project/'app.js').write_text('source')
    refs={'description':'curated original','vulnerabilities':[{'id':'original','type':'command-injection','file':'app.js','line':45,'severity':'critical','description':'curated'}]}
    (project.parent/'findings.json').write_text(json.dumps(refs,indent=2))
    return tmp_path


def test_json_file_output_authoritative_and_all_artifacts_preserved(root):
    raw=SAMPLE.read_text()
    target=root/'fixtures/demo/findings.json'; before=target.read_bytes()
    async def scanner(argv,cwd,timeout):
        output=Path(next(a.split('=',1)[1] for a in argv if a.startswith('--json-file-output=')))
        output.write_text(raw)
        return 'human scan summary','scanner warning',1
    with patch('vulnbench.references.generate.execute',scanner):
        result=asyncio.run(generate(root,'demo'))
        repeated=asyncio.run(generate(root,'demo'))
    assert target.read_bytes()==before and not result['installed']
    artifact=Path(result['artifacts'])
    assert (artifact/'previous-findings.json').read_bytes()==before
    assert (artifact/'scan.sarif.json').read_text()==raw
    assert (artifact/'stdout.txt').read_text()=='human scan summary'
    assert (artifact/'stderr.txt').read_text()=='scanner warning'
    candidates=json.loads(Path(result['candidate']).read_text())
    findings=candidates['vulnerabilities']
    assert len(findings)==5 and len({f['id'] for f in findings})==5
    assert [f['type'] for f in findings]==['command-injection','command-injection','xss','other','ssrf']
    assert [f['severity'] for f in findings]==['high','high','medium','low','medium']
    assert findings[2]['file']=='src/view.js' and findings[4]['file']==''
    assert findings==json.loads(Path(repeated['candidate']).read_text())['vulnerabilities']
    comparison=json.loads((artifact/'severity-comparison.json').read_text())
    first=comparison['candidates'][0]
    assert first['curated_severity']=='critical' and first['automatic_severity']=='high' and first['differs']
    assert comparison['candidates'][1]['original_id'] is None  # duplicate is not reused
    assert json.loads((artifact/'mapping.json').read_text())[0]['rule_id']=='javascript/CommandInjection'


@pytest.mark.parametrize('uri,relative',[
    ('app.js','app.js'), ('./app.js','app.js'), ('project/app.js','app.js'),
    ('fixtures/demo/project/app.js','app.js'), ('src%2Fview.js','src/view.js')])
def test_snyk_project_path_forms(root,uri,relative):
    project=root/'fixtures/demo/project'
    assert _project_relative_path(uri,root,project)==relative
    assert _project_relative_path((project/relative).as_uri(),root,project)==relative
    assert _project_relative_path(relative,root,project,project.as_uri()+'/')==relative


@pytest.mark.parametrize('uri',['../findings.json','fixtures/demo/project/../findings.json','https://example.com/app.js','file://remote/app.js'])
def test_candidate_path_escape_refused(root,uri):
    with pytest.raises(ValueError): _project_relative_path(uri,root,root/'fixtures/demo/project')


def test_sarif_original_uri_base_ids(root):
    sample=json.loads(SAMPLE.read_text())
    sample['runs'][0]['originalUriBaseIds']={'%SRCROOT%':{'uri':(root/'fixtures/demo/project').as_uri()+'/'}}
    sample['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uriBaseId']='%SRCROOT%'
    async def scanner(*args): return json.dumps(sample),'',1
    with patch('vulnbench.references.generate.execute',scanner): result=asyncio.run(generate(root,'demo'))
    assert json.loads(Path(result['candidate']).read_text())['vulnerabilities'][0]['file']=='app.js'


def test_scanner_failure_preserves_original_and_partial_output(root):
    target=root/'fixtures/demo/findings.json'; before=target.read_bytes()
    async def scanner(*args): raise ProcessTimeoutError('partial stdout','partial stderr',-9)
    with patch('vulnbench.references.generate.execute',scanner):
        with pytest.raises(RuntimeError,match='artifacts'): asyncio.run(generate(root,'demo',overwrite=True))
    artifact=next((root/'results/references').iterdir())
    assert (artifact/'stdout.txt').read_text()=='partial stdout'
    assert (artifact/'stderr.txt').read_text()=='partial stderr'
    assert json.loads((artifact/'execution.json').read_text())['exit_status']==-9
    assert target.read_bytes()==before


def test_malformed_sarif_preserves_raw_and_original(root):
    target=root/'fixtures/demo/findings.json'; before=target.read_bytes()
    async def scanner(*args): return '{broken','stderr',1
    with patch('vulnbench.references.generate.execute',scanner):
        with pytest.raises(ValueError): asyncio.run(generate(root,'demo',overwrite=True))
    artifact=next((root/'results/references').iterdir())
    assert (artifact/'scan.sarif.json').read_text()=='{broken'
    assert target.read_bytes()==before


def test_concurrent_reference_edit_does_not_get_overwritten(root):
    target=root/'fixtures/demo/findings.json'
    async def scanner(*args):
        target.write_text('changed by reviewer')
        return SAMPLE.read_text(),'',1
    with patch('vulnbench.references.generate.execute',scanner):
        with pytest.raises(RuntimeError,match='changed during scan'): asyncio.run(generate(root,'demo',overwrite=True))
    assert target.read_text()=='changed by reviewer'
    assert next((root/'results/references').glob('*/candidate-findings.json')).exists()


def test_real_subprocess_timeout_retains_emitted_output(root):
    argv=[sys.executable,'-c','import sys,time; print("partial",flush=True); print("warning",file=sys.stderr,flush=True); time.sleep(10)']
    with pytest.raises(ProcessTimeoutError) as error: asyncio.run(execute(argv,root,.2))
    assert error.value.stdout=='partial\n' and error.value.stderr=='warning\n'

@pytest.mark.parametrize('document',[
    {'runs':[None]},
    {'runs':[{'results':[None]}]},
    {'runs':[{'results':[],'invocations':[{'executionSuccessful':False}]}]},
])
def test_invalid_or_failed_sarif_never_installs_candidates(root,document):
    target=root/'fixtures/demo/findings.json'; before=target.read_bytes()
    async def scanner(*args): return json.dumps(document),'',0
    with patch('vulnbench.references.generate.execute',scanner):
        with pytest.raises(ValueError): asyncio.run(generate(root,'demo',overwrite=True))
    assert target.read_bytes()==before
