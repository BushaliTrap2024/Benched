from contextlib import contextmanager
import json
from pathlib import Path

def append_record(path,record):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a', encoding='utf-8', newline='\n') as handle: handle.write(json.dumps(record,ensure_ascii=False)+'\n')
def read_records(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]


def instance_key(record):
    return record['task_id'], record.get('variant_id'), record['config_id']


def execution_key(record):
    return (*instance_key(record), record['repetition'])


def source_identity(variant_id):
    return dict(variant_id=variant_id, source='original' if variant_id is None else 'transformed')


def reject_duplicates(records):
    seen = set()
    for record in records:
        key = execution_key(record)
        if key in seen:
            raise ValueError(f'Duplicate execution {key}; use one record per repetition')
        seen.add(key)
    return seen

@contextmanager
def output_lock(path):
    """Serialize Benched writers to a JSONL output across processes."""
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + '.lock')
    try:
        handle = lock.open('x')
    except FileExistsError:
        raise ValueError(f'Output is locked: {lock}') from None
    try:
        with handle:
            yield
    finally:
        lock.unlink()
