import json
from pathlib import Path
import shutil
from statistics import stdev
import subprocess
import pytest
from vulnbench.aggregation import aggregate, aggregate_by_config


def row(task, rep, f1, total=2, config='model'):
    return dict(task_id=task, config_id=config, configuration={'model':'claude-model'},
                repetition=rep, total_repetitions=total, failure=None,
                score=dict(f1=f1, precision=f1, recall=f1),
                metrics=dict(sessionDurationMs=rep*100, usage={'input_tokens':10,'output_tokens':20,'cache_read_input_tokens':30,'cache_creation_input_tokens':40},totalCostUsd=.02))


def test_config_macro_average_not_pooled_and_repetition_stddev():
    records = [row('a',1,1), row('a',2,1), row('b',1,0)]
    result = aggregate_by_config(records)[0]
    assert result['f1'] == .5  # A pooled mean would incorrectly be 2/3.
    assert result['f1_stddev'] == pytest.approx(stdev([.5,1]))
    assert result['total_tokens'] == 100 and result['cost_usd'] == .02
    assert result['repetition_headlines'][1]['task_count'] == 1
    assert result['successful_task_count'] == 2 and result['expected_runs'] == 4
    assert not result['complete']


def test_failures_null_metrics_and_configuration_separation():
    good=row('a',1,.8,1); good['metrics']={'sessionDurationMs':1}
    failed=row('b',1,0,1); failed.update(failure='runner',score=None)
    other=row('a',1,.2,1,config='other')
    results=aggregate_by_config([good,failed,other])
    assert results[0]['f1'] == .4 and results[0]['failures'] == 1
    assert results[0]['total_tokens'] == 100 and results[0]['cost_usd'] == .02
    assert results[1]['f1'] == .2
    assert aggregate_by_config([failed])[0]['f1'] == 0


def test_config_stddev_zero_when_task_differences_are_repeatable():
    result=aggregate_by_config([row(task,rep,f1) for task,f1 in [('a',1),('b',0)] for rep in (1,2)])[0]
    assert result['f1']==.5 and result['f1_stddev']==0
    assert result['complete']


def test_duplicate_successful_task_repetition_rejected():
    with pytest.raises(ValueError,match='Duplicate successful task/repetition'):
        aggregate_by_config([row('a',1,1),row('a',1,1)])


def test_differential_upstream_aggregation():
    if not shutil.which('node'): pytest.skip('Node 22.18+ needed for TypeScript oracle')
    records=[row(task,rep,value) for task,values in [('a',[.2,.4,.8]),('b',[.9,.1,.7])] for rep,value in enumerate(values,1)]
    original=[]
    for r in records:
        original.append(dict(taskId=r['task_id'],taskName=r['task_id'],fixtureId=r['task_id'],fixtureMetadata={},fixtureMetadataHash='',
            runConfigId=r['config_id'],runConfigName='model',runConfigType='model',groundTruth='v1',primaryMetric='f1',
            requestedModel='claude-model',effort='medium',thinking=None,promptTemplateId='default',repetition=r['repetition'],score=r['score']['f1'],
            details={'precision':r['score']['precision'],'recall':r['score']['recall']},
            metrics={'sessionDurationMs':r['metrics']['sessionDurationMs'],'totalLogicalInputTokens':80,'totalOutputTokens':20,'totalCostUsd':.02}))
    expected=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('upstream-aggregation-oracle.mts'))],input=json.dumps(original),text=True))
    result=aggregate_by_config(records)[0]
    for python_key,ts_key in [('f1','score'),('f1_stddev','scoreStdDev'),('precision','precision'),('recall','recall'),('duration_ms','sessionDurationMs'),('duration_stddev_ms','sessionDurationStdDevMs'),('total_tokens','totalTokens'),('cost_usd','totalCostUsd')]:
        assert result[python_key] == pytest.approx(expected[0][ts_key])

def test_reproduces_published_model_headlines_and_variance():
    data=json.loads((Path(__file__).with_name('data')/'published-v1-signatures.json').read_text())
    actual={r['config_id']:r for r in aggregate_by_config(data['records'])}
    assert len(actual)==6
    for expected in data['config_expectations']:
        result=actual[expected['runConfigId']]
        assert result['complete'] and result['task_count']==10 and result['repetitions']==5
        for python_key,ts_key in [('f1','score'),('f1_stddev','scoreStdDev'),('precision','precision'),('recall','recall')]:
            assert result[python_key]==pytest.approx(expected[ts_key])


def failure_row(task, rep, *, error_only=False, null_score=True):
    record = row(task, rep, .99, 5)
    record.update(failure=None if error_only else 'timeout', error='execution timed out')
    if null_score:
        record['score'] = None
    record['metrics']['sessionDurationMs'] = 1500
    record['metrics']['usage'] = {'input_tokens': 8, 'output_tokens': 2}
    record['metrics']['totalCostUsd'] = None
    return record


@pytest.mark.parametrize('failed_reps', [[], [5], [1, 2, 3, 4, 5]])
def test_five_repetitions_include_failure_zeros(failed_reps):
    records = [failure_row('a', rep) if rep in failed_reps else row('a', rep, 1, 5)
               for rep in range(1, 6)]
    before = json.dumps(records, sort_keys=True)
    scores = [0 if rep in failed_reps else 1 for rep in range(1, 6)]
    task = aggregate(records)[0]
    config = aggregate_by_config(records)[0]
    for result in (task, config):
        assert result['f1'] == sum(scores) / 5
        assert result['f1_stddev'] == pytest.approx(stdev(scores))
        assert result['precision'] == (1 if len(failed_reps) < 5 else None)
        assert result['recall'] == (1 if len(failed_reps) < 5 else None)
        assert result['successful'] == 5 - len(failed_reps)
        assert result['failures'] == len(failed_reps)
    assert [r['f1'] for r in config['repetition_headlines']] == scores
    assert config['repetitions'] == 5
    assert json.dumps(records, sort_keys=True) == before


def test_missing_repetitions_are_not_failures():
    result = aggregate_by_config([row('a', rep, 1, 5) for rep in range(1, 5)])[0]
    assert result['f1'] == 1 and result['f1_stddev'] == 0
    assert result['failures'] == 0 and result['successful'] == 4
    assert result['repetitions'] == 4 and not result['complete']


@pytest.mark.parametrize('error_only,null_score', [(False, True), (True, True), (False, False)])
def test_failures_override_scores_and_have_no_observed_findings(error_only, null_score):
    from vulnbench.repeatability import analyze
    record = failure_row('a', 1, error_only=error_only, null_score=null_score)
    assert aggregate_by_config([record])[0]['f1'] == 0
    recurrence = analyze([record])[0]
    assert recurrence['successful_runs'] == 0
    for bucket in ('reference_matched', 'unmatched', 'all_findings', 'reference_coverage'):
        assert recurrence[bucket]['unique'] == 0


@pytest.mark.parametrize('scenario', ['successful', 'one_failure', 'all_failed', 'missing', 'cross_project'])
def test_failed_runs_against_pinned_typescript(scenario):
    if not shutil.which('node'):
        pytest.skip('Node 22.18+ needed for TypeScript oracle')
    records = [row('a', rep, 1, 5) for rep in range(1, 6)]
    if scenario == 'one_failure':
        records[-1] = failure_row('a', 5)
    elif scenario == 'all_failed':
        records = [failure_row('a', rep) for rep in range(1, 6)]
    elif scenario == 'missing':
        records.pop()
    elif scenario == 'cross_project':
        records[0] = failure_row('a', 1)
        records += [failure_row('b', rep) if rep == 2 else row('b', rep, .4, 5)
                    for rep in range(1, 6)]
        records += [failure_row('c', rep) for rep in range(1, 6)]
    original = []
    for r in records:
        failed = bool(r.get('failure') or r.get('error'))
        usage = r['metrics']['usage']
        original.append(dict(
            taskId=r['task_id'], runConfigId=r['config_id'], runConfigType='model',
            groundTruth='v1', primaryMetric='f1', repetition=r['repetition'],
            score=0 if failed else r['score']['f1'], error=r.get('error'),
            details={} if failed else r['score'],
            metrics=dict(sessionDurationMs=r['metrics']['sessionDurationMs'],
                         totalLogicalInputTokens=sum(usage.get(k, 0) for k in
                             ('input_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens')),
                         totalOutputTokens=usage.get('output_tokens', 0),
                         totalCostUsd=r['metrics']['totalCostUsd'])))
    expected = json.loads(subprocess.check_output(
        ['node', str(Path(__file__).with_name('upstream-aggregation-oracle.mts'))],
        input=json.dumps(original), text=True))[0]
    actual = aggregate_by_config(records)[0]
    for py, ts in [('f1', 'score'), ('f1_stddev', 'scoreStdDev'),
                   ('precision', 'precision'), ('recall', 'recall'),
                   ('duration_ms', 'sessionDurationMs'), ('duration_stddev_ms', 'sessionDurationStdDevMs'),
                   ('total_tokens', 'totalTokens'), ('cost_usd', 'totalCostUsd')]:
        if expected[ts] is None:
            assert actual[py] is None
        else:
            assert actual[py] == pytest.approx(expected[ts])
    if scenario == 'cross_project':
        assert actual['f1'] == pytest.approx((.8 + .32) / 3)
        assert [r['f1'] for r in actual['repetition_headlines']] == pytest.approx([.4/3, 1/3, 1.4/3, 1.4/3, 1.4/3])
