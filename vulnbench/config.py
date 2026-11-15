import json
from pathlib import Path
from .models import Task, RunConfig, References
ROOT = Path(__file__).resolve().parents[1]

def fixture_path(root: Path, identifier: str) -> Path:
    path = (root/'fixtures'/identifier).resolve()
    if path.parent != (root/'fixtures').resolve() or not (path/'project').is_dir():
        raise ValueError(f'Invalid fixture: {identifier}')
    return path

def load_task(root: Path, identifier: str):
    if Path(identifier).name != identifier: raise ValueError('Invalid task ID')
    data = json.loads((root/'evals/tasks'/f'{identifier}.json').read_text())
    task = Task.model_validate(json.loads((root/'evals/prompts.json').read_text()) | data)
    fixture = fixture_path(root, task.fixture)
    refs = References.model_validate_json((fixture/'findings.json').read_text()).validate_ids()
    return task, fixture, refs

def load_config(root: Path, identifier: str):
    for config in json.loads((root/'evals/run-configs.json').read_text()):
        if config['id'] == identifier: return RunConfig.model_validate(config)
    raise ValueError(f'Unknown configuration: {identifier}')
