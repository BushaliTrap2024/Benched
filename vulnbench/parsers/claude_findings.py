import json, re
from pathlib import Path
from ..models import Finding
ALIASES = json.loads(Path(__file__).with_name('aliases.json').read_text())

def normalize_type(value): return ALIASES.get(str(value).lower().strip(), 'other')

def parse_findings(value):
    if isinstance(value, str):
        match = re.search(r'FINDINGS_JSON:\s*```(?:json)?\s*([\s\S]*?)```',value,re.I)
        fallback = re.search(r'\[[\s\S]*?\]',value) if not match else None
        if not match and not fallback: return []
        try: value = json.loads(match[1] if match else fallback[0])
        except (ValueError,TypeError): return []
    if not isinstance(value,list): return []
    result=[]
    for item in value:
        if not isinstance(item,dict): continue
        severity=str(item.get('severity','medium')).lower()
        result.append(Finding(id=f'found-{len(result)}',type=normalize_type(item.get('type','other')),
            file=str(item.get('file','')),line=item.get('line') if type(item.get('line')) in (int,float) else None,
            severity=severity if severity in ('critical','high','low') else 'medium',description=str(item.get('description',''))))
    return result
