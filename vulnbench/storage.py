import json
from pathlib import Path

def append_record(path,record):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a', encoding='utf-8', newline='\n') as handle: handle.write(json.dumps(record,ensure_ascii=False)+'\n')
def read_records(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]
