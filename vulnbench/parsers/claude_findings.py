import json, re
from pathlib import Path
from ..models import Finding
ALIASES = json.loads(Path(__file__).with_name('aliases.json').read_text(encoding='utf-8'))

def normalize_type(value): return ALIASES.get(str(value).lower().strip(), 'other')

def extract_findings_payload(value):
    """Extract the V1 marker/fallback payload, distinguishing [] from failure."""
    if not isinstance(value, str):
        return value
    match = re.search(r'FINDINGS_JSON:\s*```(?:json)?\s*([\s\S]*?)```',value,re.I)
    fallback = re.search(r'\[[\s\S]*?\]',value) if not match else None
    if not match and not fallback:
        raise ValueError('Missing FINDINGS_JSON or JSON array')
    return json.loads(match[1] if match else fallback[0])


def parse_findings(value):
    try:
        value = extract_findings_payload(value)
    except (ValueError, TypeError):
        return []
    if not isinstance(value,list): return []
    result=[]
    for item in value:
        if not isinstance(item,dict): continue
        severity=str(item.get('severity','medium')).lower()
        result.append(Finding(id=f'found-{len(result)}',type=normalize_type(item.get('type','other')),
            file=str(item.get('file','')),line=item.get('line') if type(item.get('line')) in (int,float) else None,
            severity=severity if severity in ('critical','high','low') else 'medium',description=str(item.get('description',''))))
    return result
