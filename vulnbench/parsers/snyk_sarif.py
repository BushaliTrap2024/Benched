import json,re
from pathlib import Path
from ..models import Finding
RULES=json.loads(Path(__file__).with_name('rules.json').read_text(encoding='utf-8'))
def map_rule_id(rule_id):
    return next((kind for pattern,kind in RULES if re.search(pattern.replace(r'\/','/'),rule_id.lower())), 'other')
def map_level(level): return {'error':'high','warning':'medium','note':'low'}.get(level,'medium')
def sarif_results(text):
    data=json.loads(text)
    if not isinstance(data,dict) or not isinstance(data.get('runs'),list) or not data['runs']:
        raise ValueError('Not a SARIF document with runs[0]')
    run=data['runs'][0]
    if not isinstance(run,dict): raise ValueError('Invalid SARIF run')
    if any(i.get('executionSuccessful') is False for i in run.get('invocations',[]) if isinstance(i,dict)):
        raise ValueError('SARIF invocation reports an unsuccessful scan')
    results=run.get('results',[])
    if not isinstance(results,list) or any(not isinstance(r,dict) for r in results): raise ValueError('Invalid SARIF results')
    return results

def parse_snyk(text, strict=False):
    try:
        findings=[]
        for result in sarif_results(text):
            if not result.get('ruleId'): continue
            locations=result.get('locations') or [{}]
            location=locations[0].get('physicalLocation',{})
            findings.append(Finding(type=map_rule_id(result['ruleId']),file=location.get('artifactLocation',{}).get('uri',''),
                line=location.get('region',{}).get('startLine'),severity=map_level(result.get('level','')),
                description=result.get('message',{}).get('text','')))
        return findings
    except (ValueError,TypeError,KeyError,AttributeError,IndexError):
        if strict: raise
        return []
