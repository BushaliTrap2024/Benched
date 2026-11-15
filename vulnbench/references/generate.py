import hashlib,json,shutil,uuid
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import unquote,urlparse
from ..config import fixture_path
from ..models import References
from ..parsers.snyk_sarif import parse_snyk,sarif_results
from ..runners.snyk_code import execute

async def generate(root,fixture_id,overwrite=False,executable='snyk',timeout=600,include_ignores=False):
    fixture=fixture_path(root,fixture_id); target=fixture/'findings.json'
    if target.exists() and not overwrite: raise FileExistsError(f'{target} exists; use --overwrite (backs up existing file)')
    artifact=root/'results'/'references'/f'{fixture_id}-{uuid.uuid4().hex}'
    artifact.mkdir(parents=True)
    raw=artifact/'scan.sarif.json'
    args=[executable,'code','test',str(fixture/'project'),'--json',f'--json-file-output={raw}']
    if include_ignores: args.append('--include-ignores')
    stdout,stderr,status=await execute(args,root,timeout)
    (artifact/'stdout.txt').write_text(stdout); (artifact/'stderr.txt').write_text(stderr)
    (artifact/'execution.json').write_text(json.dumps({'argv':args,'exit_status':status}))
    if not raw.exists(): raw.write_text(stdout)
    if status not in (0,1): raise RuntimeError(f'Snyk failed ({status}); artifacts: {artifact}')
    text=raw.read_text(); findings=parse_snyk(text,strict=True); results=[r for r in sarif_results(text) if r.get('ruleId')]
    counts={}
    for finding,result in zip(findings,results):
        path=unquote(finding.file).replace('\\','/')
        if path.startswith('file:'): path=urlparse(path).path
        location=Path(path)
        if location.is_absolute():
            path=location.resolve().relative_to((fixture/'project').resolve()).as_posix()
        prefix=f'fixtures/{fixture_id}/project/'
        if path.startswith(prefix): path=path[len(prefix):]
        if '..' in Path(path).parts: raise ValueError('SARIF path escapes project')
        finding.file=path
        signature=json.dumps([result['ruleId'],path,finding.line],ensure_ascii=False)
        counts[signature]=counts.get(signature,0)+1
        finding.id=f'{fixture_id}-{hashlib.sha256(signature.encode()).hexdigest()[:16]}-{counts[signature]}'
    refs=References(description='Automatically generated Snyk Code reference candidates; not manually reviewed.',vulnerabilities=findings).validate_ids()
    data=refs.model_dump() | {'_note':'Generated automation of upstream authoring Steps 2–4; requires review.',
        'provenance':{'generator':'snyk-code','review_status':'unreviewed','created_at':datetime.now(timezone.utc).isoformat(),'raw_artifact':str(raw.relative_to(root)),'sha256':hashlib.sha256(text.encode()).hexdigest()}}
    temporary=artifact/'findings.json'; temporary.write_text(json.dumps(data,indent=2)+'\n')
    References.model_validate_json(temporary.read_text()).validate_ids()
    if target.exists(): shutil.copy2(target,artifact/'previous-findings.json')
    if overwrite:
        replacement=target.with_suffix('.json.tmp'); shutil.copyfile(temporary,replacement); replacement.replace(target)
    else:
        with target.open('x') as handle: handle.write(temporary.read_text())
    return {'reference':str(target),'artifacts':str(artifact),'count':len(findings)}
