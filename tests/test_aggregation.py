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
    assert results[0]['f1'] == .8 and results[0]['failures'] == 1
    assert results[0]['total_tokens'] is None and results[0]['cost_usd'] is None
    assert results[1]['f1'] == .2
    assert aggregate_by_config([failed])[0]['f1'] is None


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
