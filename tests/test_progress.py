"""Progress is live on stderr; execution and persistence use offline fake runners."""
import asyncio
import io
import json
import sys

import pytest

import main as cli
from vulnbench.config import ROOT
from vulnbench.experiment import run
from vulnbench.models import Finding, RunOutput


class ProgressStream(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushes = 0

    def flush(self):
        self.flushes += 1
        super().flush()


def test_live_progress_flushes_and_persists_each_execution(tmp_path, monkeypatch, capsys):
    stream = ProgressStream()
    monkeypatch.setattr(sys, 'stderr', stream)
    path = tmp_path / 'runs.jsonl'
    outcomes = [(None, None), ('timeout', 'timed out'), (None, 'runner error'), (None, None)]
    calls = []

    class FakeRunner:
        async def run(self, task, config, cwd):
            index = len(calls)
            # Both the plan and current start have been flushed before executing.
            assert stream.flushes == 2 + 2 * index
            assert f'[{index+1}/4] Starting' in stream.getvalue()
            saved = path.read_text().splitlines() if path.exists() else []
            assert len(saved) == index
            calls.append((task.id, config.id, cwd))
            failure, error = outcomes[index]
            return RunOutput(findings=[Finding(type='xss')], failure=failure, error=error,
                             metrics={'sessionDurationMs': 100 + index})

    records = asyncio.run(run(ROOT, ['js-project-tigerteam-find-vulns'],
                              ['claude-opus-4-6-medium', 'snyk-code'], 2, path,
                              lambda _: FakeRunner()))
    lines = stream.getvalue().splitlines()
    assert lines[0] == 'Planned executions: 4'
    assert stream.flushes == 9
    assert capsys.readouterr().out == ''
    for index, record in enumerate(records):
        start, end = lines[1+index*2:3+index*2]
        assert f'[{index+1}/4] Starting' in start
        assert record['task']['name'] in start
        assert 'fixture=js-project-tigerteam' in start
        assert f"config={record['config_id']}" in start
        assert f"repetition={record['repetition']}/2" in start
        status = 'FAILED' if index in (1, 2) else 'SUCCEEDED'
        assert end == (f'[{index+1}/4] {status} duration={100+index} ms '
                       f'completed={index+1}/4 failed={min(index, 2)}')
    assert [json.loads(line) for line in path.read_text().splitlines()] == records
    assert all(not cwd.exists() for _, _, cwd in calls)
    assert len({cwd for _, _, cwd in calls}) == 4


@pytest.mark.parametrize('failure', [None, 'timeout'])
def test_cli_progress_keeps_stdout_json(tmp_path, monkeypatch, capsys, failure):
    class FakeRunner:
        async def run(self, task, config, cwd):
            return RunOutput(failure=failure, error='timed out' if failure else None,
                             metrics={'sessionDurationMs': 42})

    async def fake_run(*args):
        return await run(*args, runner_factory=lambda _: FakeRunner())

    monkeypatch.setattr(cli, 'run', fake_run)
    path = tmp_path / 'runs.jsonl'
    monkeypatch.setattr(sys, 'argv', ['main.py', 'run', '--task',
        'js-project-tigerteam-find-vulns', '--config', 'claude-opus-4-6-medium',
        '--output', str(path)])
    assert cli.main() == int(bool(failure))
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {'output': str(path), 'runs': 1, 'failed': int(bool(failure))}
    assert 'Planned executions: 1' in captured.err
    assert ('[1/1] FAILED' if failure else '[1/1] SUCCEEDED') in captured.err


def test_dry_run_has_no_execution_progress_or_output_file(tmp_path, monkeypatch, capsys):
    def unexpected_run(*args):
        pytest.fail('Dry-run must not execute the experiment')

    monkeypatch.setattr(cli, 'run', unexpected_run)
    path = tmp_path / 'runs.jsonl'
    monkeypatch.setattr(sys, 'argv', ['main.py', 'run', '--task',
        'js-project-tigerteam-find-vulns', '--config', 'claude-opus-4-6-medium',
        '--repetitions', '5', '--output', str(path), '--dry-run'])
    assert cli.main() == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)['repetitions'] == 5
    assert captured.err == ''
    assert not path.exists()
