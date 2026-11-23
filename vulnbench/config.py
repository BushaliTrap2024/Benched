import json
import re
from pathlib import Path
from .models import Task, RunConfig, References
from .workspace import _is_link_or_reparse_point

ROOT = Path(__file__).resolve().parents[1]

def fixture_path(root: Path, identifier: str) -> Path:
    path = (root/'fixtures'/identifier).resolve()
    if path.parent != (root/'fixtures').resolve() or not (path/'project').is_dir():
        raise ValueError(f'Invalid fixture: {identifier}')
    return path

def load_task(root: Path, identifier: str):
    if Path(identifier).name != identifier: raise ValueError('Invalid task ID')
    data = json.loads((root/'evals/tasks'/f'{identifier}.json').read_text(encoding='utf-8'))
    task = Task.model_validate(json.loads((root/'evals/prompts.json').read_text(encoding='utf-8')) | data)
    fixture = fixture_path(root, task.fixture)
    refs = References.model_validate_json((fixture/'findings.json').read_text(encoding='utf-8')).validate_ids()
    return task, fixture, refs

def load_config(root: Path, identifier: str):
    for config in json.loads((root/'evals/run-configs.json').read_text(encoding='utf-8')):
        if config['id'] == identifier: return RunConfig.model_validate(config)
    raise ValueError(f'Unknown configuration: {identifier}')

def _valid_identifier(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', value)


def variant_project(root: Path, fixture: str, variant: str) -> Path:
    if not _valid_identifier(variant):
        raise ValueError(f'Invalid variant ID: {variant!r}')
    if not _valid_identifier(fixture):
        raise ValueError(f'Invalid fixture ID: {fixture!r}')
    root = root.resolve()
    path = root
    for part in ('transformed-variants', fixture, variant, 'project'):
        path = path / part
        try:
            linked = _is_link_or_reparse_point(path)
        except FileNotFoundError:
            raise ValueError(f'Missing variant project: {fixture}/{variant}') from None
        if linked or not path.is_dir() or not path.resolve().is_relative_to(root):
            raise ValueError(f'Invalid variant project directory: {path}')
    return path


def select_tasks(root, tasks, variant=None, all_variants=False):
    if all_variants:
        if tasks or variant is not None:
            raise ValueError('--all-variants cannot be combined with --task or --variant')
        selected = []
        base = root / 'transformed-variants'
        if (base.exists() or base.is_symlink()) and _is_link_or_reparse_point(base):
            raise ValueError(f'Invalid variants directory: {base}')
        for file in sorted((root / 'evals' / 'tasks').glob('*.json')):
            data = json.loads(file.read_text(encoding='utf-8'))
            fixture = data['fixture']
            if not _valid_identifier(fixture):
                raise ValueError(f'Invalid fixture ID: {fixture!r}')
            directory = base / fixture
            if not directory.exists() and not directory.is_symlink():
                continue
            if _is_link_or_reparse_point(directory) or not directory.is_dir():
                raise ValueError(f'Invalid variants directory: {directory}')
            for candidate in sorted(directory.iterdir()):
                if candidate.is_dir() or _is_link_or_reparse_point(candidate):
                    selected.append((fixture, candidate.name, file.stem))
        if not selected:
            raise ValueError('No transformed variants found for benchmark tasks')
        return [(task, variant_id) for _, variant_id, task in sorted(selected)]
    if not tasks:
        raise ValueError('Specify --task or --all-variants')
    return [(task, variant) for task in tasks]


def execution_sources(root, tasks, variant=None, all_variants=False):
    for task_id, variant_id in select_tasks(root, tasks, variant, all_variants):
        task, fixture, refs = load_task(root, task_id)
        project = fixture / 'project' if variant_id is None else variant_project(root, task.fixture, variant_id)
        yield task, fixture, refs, project, variant_id
