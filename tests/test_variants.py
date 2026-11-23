import asyncio
import json
from pathlib import Path
import subprocess
import sys

import pytest

from vulnbench.aggregation import aggregate
from vulnbench.config import execution_sources, variant_project
from vulnbench.experiment import run
from vulnbench.models import Finding, RunOutput
from vulnbench.repeatability import analyze
from vulnbench.robustness import compare
from vulnbench.storage import output_lock, read_records


TASK = 'demo-task'
MAIN = Path(__file__).resolve().parents[1] / 'main.py'


@pytest.fixture
def benchmark(tmp_path):
    def put(name, data):
        file = tmp_path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps(data), encoding='utf-8')

    put('evals/prompts.json', {'systemPrompt': '', 'prompt': ''})
    put('evals/tasks/demo-task.json',
        {'id': TASK, 'name': 'Demo', 'fixture': 'demo', 'category': 'find-vulns'})
    put('evals/run-configs.json', [{'id': 'mock', 'type': 'command'}])
    references = {'description': 'curated', 'vulnerabilities': [
        {'id': 'curated-id', 'type': 'xss', 'file': 'app.js', 'line': 1},
    ]}
    put('fixtures/demo/findings.json', references)
    put('fixtures/demo/project/source.json', 'original')
    for variant in ('bbb', 'aaa'):
        path = f'transformed-variants/demo/{variant}'
        put(f'{path}/project/source.json', variant)
        put(f'{path}/findings.json', {'description': 'unused', 'vulnerabilities': []})
    put('transformed-variants/unknown/ignored/project/source.json', 'ignore me')
    return tmp_path


class Detector:
    def __init__(self, observed):
        self.observed = observed

    async def run(self, task, config, cwd):
        assert task.id == TASK
        assert not (cwd / 'findings.json').exists()
        marker = json.loads((cwd / 'source.json').read_text())
        self.observed.append(marker)
        findings = [] if marker == 'bbb' else [Finding(type='xss', file='app.js', line=99)]
        return RunOutput(findings=findings, metrics={'sessionDurationMs': 1})


def test_variant_runs_use_original_references_and_keep_results_separate(benchmark):
    observed = []
    factory = lambda _: Detector(observed)
    original_file = benchmark / 'original.jsonl'
    variant_file = benchmark / 'variants.jsonl'
    before = (benchmark / 'fixtures/demo/findings.json').read_bytes()
    originals = asyncio.run(run(benchmark, [TASK], ['mock'], 2, original_file, factory))
    variants = asyncio.run(run(benchmark, None, ['mock'], 2, variant_file, factory, all_variants=True))
    assert observed == ['original', 'original', 'aaa', 'aaa', 'bbb', 'bbb']
    assert originals[0]['variant_id'] is None
    assert originals[0]['source'] == 'original'
    first = read_records(variant_file)[0]
    assert (first['fixture_id'], first['variant_id'], first['source']) == ('demo', 'aaa', 'transformed')
    assert first['task']['variant_id'] == 'aaa'
    assert first['score']['matches'] == [{'finding_index': 0, 'reference_id': 'curated-id'}]
    assert first['reference_sha256'] == originals[0]['reference_sha256']
    assert (benchmark / 'fixtures/demo/findings.json').read_bytes() == before
    assert len(aggregate(originals + variants)) == 3
    recurrence = analyze(originals + variants)
    assert [result.get('variant_id') for result in recurrence] == [None, 'aaa', 'bbb']
    assert recurrence[1]['reference_coverage']['seen_all'] == 1
    assert recurrence[2]['reference_coverage']['unique'] == 0
    result = compare(originals + variants)
    assert [v['delta_f1'] for v in result['variants']] == [0, -1]
    assert result['variants'][1]['reference_frequencies']['curated-id'] == {
        'original': {'detected': 2, 'successful': 2, 'attempts': 2},
        'transformed': {'detected': 0, 'successful': 2, 'attempts': 2},
    }
    assert result['configurations'][0]['delta_f1'] == -.5
    with pytest.raises(ValueError, match='already contains'):
        asyncio.run(run(benchmark, [TASK], ['mock'], 2, variant_file, factory, variant='aaa'))
    with pytest.raises(ValueError, match='separate output'):
        asyncio.run(run(benchmark, [TASK], ['mock'], 2, original_file, factory, variant='aaa'))
    with pytest.raises(ValueError, match='Duplicate execution'):
        analyze(variants + variants)
    assert len(read_records(variant_file)) == 4


@pytest.mark.parametrize('variant', ['../aaa', r'..\aaa', '/aaa', '.', '', 'missing'])
def test_invalid_or_missing_variant(benchmark, variant):
    with pytest.raises(ValueError, match='variant'):
        variant_project(benchmark, 'demo', variant)


def test_missing_project_and_link(benchmark):
    base = benchmark / 'transformed-variants/demo'
    (base / 'empty').mkdir()
    with pytest.raises(ValueError, match='Missing variant project'):
        variant_project(benchmark, 'demo', 'empty')
    try:
        (base / 'linked').symlink_to(base / 'aaa', target_is_directory=True)
    except OSError:
        pytest.skip('Directory symlinks are unavailable')
    with pytest.raises(ValueError, match='Invalid variant project'):
        variant_project(benchmark, 'demo', 'linked')


def test_dry_run_selection(benchmark):
    def dry_run(*args):
        return subprocess.run([sys.executable, str(MAIN), '--root', str(benchmark), 'run',
                               '--dry-run', '--config', 'mock', *args],
                              check=False, capture_output=True, text=True)

    assert list(execution_sources(benchmark, [TASK]))[0][3] == benchmark / 'fixtures/demo/project'
    original = json.loads(dry_run('--task', TASK).stdout)
    assert original['tasks'][0]['fixture'] == 'demo'
    single = json.loads(dry_run('--task', TASK, '--variant', 'bbb').stdout)
    assert single['sources'][0]['project'].endswith('/demo/bbb/project') or Path(
        single['sources'][0]['project']).parts[-3:] == ('demo', 'bbb', 'project')
    all_sources = json.loads(dry_run('--all-variants').stdout)['sources']
    assert [item['variant_id'] for item in all_sources] == ['aaa', 'bbb']
    assert dry_run('--task', TASK, '--all-variants').returncode != 0


def test_output_lock(benchmark):
    path = benchmark / 'output.jsonl'
    with output_lock(path), pytest.raises(ValueError, match='locked'):
        with output_lock(path):
            pytest.fail('Acquired an already locked output')
    assert not path.with_name('output.jsonl.lock').exists()


def test_configuration_robustness_weights_fixtures_equally():
    def record(fixture, variant, f1):
        return dict(task_id=fixture + '-task', fixture_id=fixture,
                    variant_id=variant, config_id='mock', repetition=1,
                    total_repetitions=1, metrics={'sessionDurationMs': 1},
                    reference_sha256=fixture,
                    score=dict(f1=f1, precision=f1, recall=f1, matches=[]))

    result = compare([
        record('a', None, 1), record('a', 'v1', 0), record('a', 'v2', 0),
        record('b', None, 1), record('b', 'v1', 1),
    ])
    config = result['configurations'][0]
    assert config['fixture_count'] == config['comparable_fixtures'] == 2
    assert config['f1'] == .5
    assert config['delta_f1'] == -.5

    with pytest.raises(ValueError, match='Reference sets differ'):
        compare([record('a', None, 1),
                 {**record('a', 'v1', 1), 'reference_sha256': 'changed'}])
