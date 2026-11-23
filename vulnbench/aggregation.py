"""V1 macro aggregation: repetitions -> tasks -> detector configuration.

Headline standard deviation is computed on per-repetition task macro means,
not on all individual scans pooled together (src/aggregator.ts).
"""
from collections import defaultdict
from statistics import mean, stdev

from .storage import instance_key, reject_duplicates, source_identity


def _mean(values):
    values = [v for v in values if v is not None]
    return mean(values) if values else None


def _std(values):
    return stdev(values) if len(values) > 1 else 0


def _successful(record):
    return not record.get('failure') and not record.get('error') and record.get('score') is not None


def _f1(record):
    # Legacy failures retain score=None on disk; only recorded failures are zero.
    if record.get('failure') or record.get('error'):
        return 0
    return record['score']['f1'] if record.get('score') is not None else None


def _tokens(record):
    metrics = record['metrics']
    usage = metrics.get('usage')
    if usage is not None:
        keys = ('input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens')
        return sum(usage.get(k, 0) for k in keys) if any(k in usage for k in keys) else None
    if 'totalLogicalInputTokens' in metrics and 'totalOutputTokens' in metrics:
        return metrics['totalLogicalInputTokens'] + metrics['totalOutputTokens']
    return None


def aggregate(records):
    """Per-instance means including recorded failures as zero F1."""
    records = list(records)
    if any(r.get('variant_id') is not None for r in records):
        reject_duplicates(records)
    groups = defaultdict(list)
    for record in records:
        groups[instance_key(record)].append(record)
    result = []
    for (task, variant, config), rows in groups.items():
        good = [r for r in rows if _successful(r)]
        scores = [_f1(r) for r in rows if _f1(r) is not None]
        durations = [r['metrics']['sessionDurationMs'] for r in rows]
        identity = dict(fixture_id=rows[0].get('fixture_id'), **source_identity(variant)) if variant is not None else {}
        if variant is not None:
            identity.update(
                precision_stddev=_std([row['score']['precision'] for row in good]),
                recall_stddev=_std([row['score']['recall'] for row in good]),
            )
        result.append(dict(
            **identity, task_id=task, config_id=config, model=rows[0].get('configuration', {}).get('model'),
            attempts=len(rows), successful=len(good), failures=len(rows)-len(good),
            f1=_mean(scores), f1_stddev=_std(scores),
            precision=_mean(r['score']['precision'] for r in good),
            recall=_mean(r['score']['recall'] for r in good),
            duration_ms=_mean(durations), duration_stddev_ms=_std(durations),
            total_tokens=_mean(_tokens(r) for r in rows),
            cost_usd=_mean(r['metrics'].get('totalCostUsd') for r in rows),
        ))
    return result


def aggregate_by_config(records):
    """One equal-task-weight headline per configuration (model + effort/tools).

    Recorded failures contribute zero F1 and their observed resource metrics.
    Missing repetitions are not imputed. Precision/recall use successes only;
    completeness continues to describe successful execution coverage.
    """
    records = list(records)
    if any(r.get('variant_id') is not None for r in records):
        raise ValueError('Configuration headlines require original records; use robustness for variants')
    task_groups = defaultdict(list)
    raw_groups = defaultdict(list)
    for task in aggregate(records):
        task_groups[task['config_id']].append(task)
    for record in records:
        raw_groups[record['config_id']].append(record)
    result = []
    for config, tasks in task_groups.items():
        raw = raw_groups[config]
        good = [r for r in raw if _successful(r)]
        usable = [t for t in tasks if t['successful']]
        by_rep = defaultdict(list)
        seen = set()
        for row in good:
            key = (row['task_id'], row['repetition'])
            if key in seen:
                raise ValueError(f'Duplicate successful task/repetition for {config}; analyze one experiment at a time')
            seen.add(key)
        for row in raw:
            if _f1(row) is not None:
                by_rep[row['repetition']].append(row)
        headlines = [dict(
            repetition=rep, task_count=len(rows),
            f1=mean(_f1(r) for r in rows),
            duration_ms=mean(r['metrics']['sessionDurationMs'] for r in rows),
        ) for rep, rows in sorted(by_rep.items())]
        requested_by_task = {t['task_id']: max(r['total_repetitions'] for r in raw if r['task_id'] == t['task_id']) for t in tasks}
        result.append(dict(
            config_id=config, model=tasks[0]['model'], primary_metric='f1',
            task_count=len(tasks), successful_task_count=len(usable),
            attempts=len(raw), successful=len(good), failures=len(raw)-len(good),
            expected_runs=sum(requested_by_task.values()),
            complete=all((task, rep) in seen for task, count in requested_by_task.items() for rep in range(1, count+1)),
            repetitions=len(by_rep),
            f1=_mean(t['f1'] for t in tasks),
            precision=_mean(t['precision'] for t in usable),
            recall=_mean(t['recall'] for t in usable),
            f1_stddev=_std([r['f1'] for r in headlines]),
            duration_ms=_mean(t['duration_ms'] for t in tasks),
            duration_stddev_ms=_std([r['duration_ms'] for r in headlines]),
            total_tokens=_mean(t['total_tokens'] for t in tasks),
            cost_usd=_mean(t['cost_usd'] for t in tasks),
            repetition_headlines=headlines,
        ))
    return result
