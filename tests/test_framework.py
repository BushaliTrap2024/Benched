import asyncio,json,sys,shutil
from pathlib import Path
from unittest.mock import patch
import pytest
from vulnbench.models import Finding,RunConfig,RunOutput
from vulnbench.config import ROOT,load_task,load_config
from vulnbench.parsers.snyk_sarif import parse_snyk,map_level,map_rule_id
from vulnbench.parsers.claude_findings import parse_findings,normalize_type
from vulnbench.scoring import score
from vulnbench.workspace import isolated_workspace
from vulnbench.references.generate import generate
from vulnbench.runners.snyk_code import SnykCodeRunner
from vulnbench.experiment import run
from vulnbench.repeatability import analyze
from vulnbench.aggregation import aggregate

SARIF=json.dumps({'runs':[{'results':[{'ruleId':'javascript/Sqli','level':'error','message':{'text':'SQL sink'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'app.js'},'region':{'startLine':42}}}]},{'ruleId':'javascript/XSS','level':'note'},{}]}]})
@pytest.mark.parametrize('rule,kind',[('Sqli','sql-injection'),('DOMXSS','xss'),('PT','path-traversal'),('CommandInjection','command-injection'),('CodeInjection','code-injection'),('OR','open-redirect'),('NoHardcodedPasswords','hardcoded-credentials'),('Ssrf','ssrf'),('PrototypePollution','prototype-pollution'),('TooPermissiveCorsHeader','origin-validation-error'),('Unrecognized','other')])
def test_rules(rule,kind): assert map_rule_id('javascript/'+rule)==kind
@pytest.mark.parametrize('level,expected',[('error','high'),('warning','medium'),('note','low'),('','medium'),('critical','medium')])
def test_levels(level,expected): assert map_level(level)==expected

def test_sarif():
    findings=parse_snyk(SARIF); assert len(findings)==2
    assert findings[0].model_dump()==dict(type='sql-injection',file='app.js',line=42,severity='high',description='SQL sink',id=None)
    assert findings[1].file==''
@pytest.mark.parametrize('text',['','oops','{}','[]','{"runs":[]}'])
def test_malformed_sarif(text):
    assert parse_snyk(text)==[]
    with pytest.raises((ValueError,TypeError)): parse_snyk(text,strict=True)
@pytest.mark.parametrize('text',['FINDINGS_JSON:\n```json\n[{"type":"SQLi"}]\n```','prefix [{"type":"SQLi"}] suffix'])
def test_claude(text): assert parse_findings(text)[0].type=='sql-injection'
def test_invalid_claude():
    for text in ('','garbage','FINDINGS_JSON: ```json broken ```','[null,42]'): assert parse_findings(text)==[]

def test_greedy_duplicates():
    known=[Finding(id='a',type='xss'),Finding(id='b',type='xss')]
    result=score([Finding(type='xss',file='wrong.js')]*3,known)
    assert [m['reference_id'] for m in result['matches']]==['a','b']
    assert (result['TP'],result['FP'],result['FN'])==(2,1,0)
    assert result['precision']==2/3 and result['recall']==1 and result['f1']==.8
    assert score([],[])['recall']==1
    assert score([],[])['precision']==0
    assert score([],known)['f1']==0
    assert score([Finding(type='other')],known)['TP']==0

def test_workspace(tmp_path):
    fixture=tmp_path/'fixture'; project=fixture/'project'; project.mkdir(parents=True)
    (fixture/'findings.json').write_text('secret'); (project/'app.js').write_text('original')
    paths=[]
    for _ in range(2):
        with isolated_workspace(project) as cwd:
            paths.append(cwd); assert not (cwd/'findings.json').exists()
            assert (cwd/'app.js').read_text()=='original'; (cwd/'app.js').write_text('mutated')
        assert not cwd.exists()
    assert paths[0]!=paths[1]
    with pytest.raises(RuntimeError):
        with isolated_workspace(project) as cwd: raise RuntimeError()
    assert not cwd.exists()

def test_links(tmp_path, make_symlink):
    make_symlink(tmp_path/'leak', tmp_path/'secret.txt')
    with pytest.raises(ValueError):
        with isolated_workspace(tmp_path): pass

@pytest.fixture
def root(tmp_path):
    (tmp_path/'fixtures/demo/project').mkdir(parents=True)
    (tmp_path/'fixtures/demo/project/app.js').write_text('source')
    return tmp_path

def test_references(root):
    async def fake(*args): return SARIF,'warning',1
    with patch('vulnbench.references.generate.execute',fake):
        result=asyncio.run(generate(root,'demo'))
        candidate=Path(result['candidate'])
        data=json.loads(candidate.read_text()); assert data['provenance']['review_status']=='unreviewed'
        assert len({v['id'] for v in data['vulnerabilities']})==2
        target=root/'fixtures/demo/findings.json'
        assert not target.exists()  # Generating candidates never installs by default.
        target.write_text('{"description":"curated","vulnerabilities":[]}')
        old=target.read_bytes()
        generated=asyncio.run(generate(root,'demo'))
        assert target.read_bytes()==old
        second=asyncio.run(generate(root,'demo',True))
        assert (Path(second['artifacts'])/'previous-findings.json').read_bytes()==old
        assert json.loads(target.read_text())['vulnerabilities']==data['vulnerabilities']
        assert Path(result['artifacts'],'scan.sarif.json').read_text()==SARIF

def test_reference_failure_preserves_existing(root):
    target=root/'fixtures/demo/findings.json'; target.write_text('{"description":"original","vulnerabilities":[]}')
    async def fake(*args): return '{"error":"authentication"}','bad auth',2
    with patch('vulnbench.references.generate.execute',fake):
        with pytest.raises(RuntimeError): asyncio.run(generate(root,'demo',True))
    assert json.loads(target.read_text())['description']=='original'

def test_baseline_process_and_no_overwrite(root):
    target=root/'fixtures/demo/findings.json'; target.write_text('original')
    script=root/'scanner.py'; script.write_text('import sys\nprint('+repr(SARIF)+')\nsys.exit(1)\n')
    config=RunConfig(id='fake',type='command',executable=sys.executable,args=[str(script)])
    with isolated_workspace(root/'fixtures/demo/project') as cwd:
        output=asyncio.run(SnykCodeRunner().run(None,config,cwd))
    assert not output.failure and len(output.findings)==2
    assert output.metrics['exit_status']==1 and output.metrics['sessionDurationMs']>0
    assert target.read_text()=='original'

def test_timeout(root):
    config=RunConfig(id='fake',type='command',executable=sys.executable,args=['-c','import time; time.sleep(10)'],timeoutMs=20)
    output=asyncio.run(SnykCodeRunner().run(None,config,root))
    assert output.failure=='timeout'

def test_repetitions(root):
    (root/'evals/tasks').mkdir(parents=True)
    (root/'evals/tasks/demo.json').write_text(json.dumps(dict(id='demo',name='Demo',fixture='demo',category='find-vulns')))
    (root/'evals/prompts.json').write_text(json.dumps(dict(systemPrompt='system',prompt='user')))
    (root/'evals/run-configs.json').write_text('[{"id":"fake","model":"fake"}]')
    (root/'fixtures/demo/findings.json').write_text('{"description":"reference","vulnerabilities":[{"id":"one","type":"xss"}]}')
    seen=[]
    class Fake:
        async def run(self,task,config,cwd):
            assert (cwd/'app.js').read_text()=='source'
            assert not (cwd/'findings.json').exists()
            seen.append(cwd); (cwd/'app.js').write_text('changed')
            return RunOutput(findings=[Finding(type='xss'),Finding(type='ssrf',file='./app.js',line=1)],metrics={'sessionDurationMs':1})
    records=asyncio.run(run(root,['demo'],['fake'],3,root/'runs.jsonl',lambda _:Fake()))
    assert len(set(seen))==3 and all(not p.exists() for p in seen)
    assert len((root/'runs.jsonl').read_text().splitlines())==3
    assert aggregate(records)[0]['f1']==pytest.approx(2/3)
    repeat=analyze(records)[0]
    assert repeat['reference_matched']['seen_all']==1 and repeat['unmatched']['seen_all']==1

def test_original_assets():
    task,fixture,refs=load_task(ROOT,'js-project-tigerteam-find-vulns')
    assert task.prompt.startswith('Audit all files') and len(refs.vulnerabilities)>0
    assert load_config(ROOT,'claude-opus-4-6-medium').effort=='medium'
    assert load_config(ROOT,'snyk-code').type=='command'

def test_claude_sdk_mock(root):
    import claude_agent_sdk as sdk
    observed={}
    async def fake(*,prompt,options):
        observed['options']=options
        yield sdk.ResultMessage(subtype='success',duration_ms=1,duration_api_ms=1,is_error=False,num_turns=2,session_id='mock',usage={'input_tokens':10,'output_tokens':5},total_cost_usd=.01,result='FINDINGS_JSON:\n```json\n[{"type":"XSS"}]\n```')
    from vulnbench.runners.claude_code import ClaudeCodeRunner
    from vulnbench.models import Task
    task=Task(id='demo',name='demo',fixture='demo',category='find-vulns',systemPrompt='system',prompt='prompt')
    async def sandbox_available(): pass
    with patch.object(sdk,'query',fake), patch('vulnbench.runners.claude_code.check_sandbox_available',sandbox_available):
        output=asyncio.run(ClaudeCodeRunner().run(task,RunConfig(id='demo',model='claude-opus-4-6'),root/'fixtures/demo/project'))
    assert not output.failure and output.findings[0].type=='xss'
    assert output.metrics['usage']['input_tokens']==10 and output.metrics['totalTurns']==2
    options=observed['options']; assert options.strict_mcp_config and options.setting_sources==[]
    assert options.sandbox is None
    sandbox=json.loads(options.settings)['sandbox']
    assert sandbox['enabled'] and not sandbox['allowUnsandboxedCommands']
    assert sandbox['filesystem']['denyRead']

def test_differential_original_typescript():
    import subprocess,random
    if not shutil.which('node'): pytest.skip('Node required only for upstream differential check')
    random.seed(41)
    types=['xss','sql-injection','other','command-injection']
    oracle=Path(__file__).with_name('upstream-v1-oracle.mts')
    for _ in range(20):
        known=[Finding(id=str(i),type=random.choice(types),severity=random.choice(['low','high'])) for i in range(random.randrange(6))]
        findings=[{'type':random.choice(types+['SQLi','unknown']),'file':'elsewhere.js','line':i} for i in range(random.randrange(7))]
        expected=json.loads(subprocess.check_output(['node',str(oracle)],input=json.dumps({'known':[v.model_dump() for v in known],'findings':findings}),text=True))
        actual=score(parse_findings(findings),known)
        for key in ('precision','recall','byType','bySeverity'):
            assert actual[key]==expected[key]
        for key in ('truePositives','falseNegatives'):
            assert [{k:v[k] for k in ('id','type','severity')} for v in actual[key]]==expected[key]
        assert actual['FP']==len(expected['falsePositives'])
