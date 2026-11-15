import json
from pathlib import Path
import subprocess
import sys

MAIN=Path(__file__).resolve().parents[1]/'main.py'


def test_analysis_cli_levels_and_signature_path(tmp_path):
    record=dict(task_id='demo',config_id='model',repetition=1,total_repetitions=1,
        score={'f1':1,'precision':1,'recall':1,'agentFindings':[{'type':'xss','file':'src/a.js','line':1}],
               'matches':[{'finding_index':0,'reference_id':'original'}]},metrics={'sessionDurationMs':1})
    path=tmp_path/'runs.jsonl'; path.write_text(json.dumps(record)+'\n')
    def command(*args): return json.loads(subprocess.check_output([sys.executable,str(MAIN),*args],text=True))
    assert command('aggregate',str(path))['configurations'][0]['f1']==1
    assert command('aggregate',str(path),'--level','task')[0]['task_id']=='demo'
    assert command('aggregate',str(path),'--level','config')[0]['config_id']=='model'
    result=command('repeatability',str(path),'--signature-path','relative-path')[0]
    assert result['reference_matched']['signatures'][0]['signature'][-2]=='src/a.js'


def test_reference_cli_subprocess_preserves_original(tmp_path):
    project=tmp_path/'fixtures/demo/project'; project.mkdir(parents=True)
    target=project.parent/'findings.json'
    target.write_text('{"description":"curated","vulnerabilities":[]}')
    before=target.read_bytes()
    sample=(MAIN.parent/'tests/data/snyk-code-representative.sarif.json').read_text()
    scanner=tmp_path/'snyk-mock'
    scanner.write_text('#!'+sys.executable+'\nimport sys,pathlib\nraw='+repr(sample)+'\nfor a in sys.argv:\n if a.startswith("--json-file-output="): pathlib.Path(a.split("=",1)[1]).write_text(raw)\nprint("human summary")\nsys.exit(1)\n')
    scanner.chmod(0o700)
    result=json.loads(subprocess.check_output([sys.executable,str(MAIN),'--root',str(tmp_path),
        'generate-references','--fixture','demo','--snyk',str(scanner)],text=True))
    assert result['count']==5 and not result['installed']
    assert target.read_bytes()==before
    assert json.loads(Path(result['candidate']).read_text())['provenance']['review_status']=='unreviewed'
