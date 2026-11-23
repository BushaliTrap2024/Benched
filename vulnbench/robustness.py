"""Compare reported detections across sources using the frozen scoring references."""
from collections import Counter, defaultdict

from .aggregation import _mean, _successful, aggregate
from .storage import instance_key, reject_duplicates


def _frequencies(rows):
    reference_ids = {ref for row in rows for ref in row.get('reference_ids', [])}
    counts = Counter()
    for row in rows:
        if not _successful(row):
            continue
        score = row['score']
        reference_ids.update(ref['id'] for ref in score.get('falseNegatives', []))
        hits = {match['reference_id'] for match in score['matches']}
        reference_ids.update(hits)
        counts.update(hits)
    return reference_ids, counts


def compare(records):
    reject_duplicates(records)
    instances = defaultdict(list)
    for record in records:
        instances[instance_key(record)].append(record)
    stats = {instance_key(row): row for row in aggregate(records)}
    comparisons = []
    by_config = defaultdict(lambda: defaultdict(list))
    for key, rows in sorted(instances.items(), key=lambda item: (
        item[0][0], item[0][1] or '', item[0][2],
    )):
        task, variant, config = key
        if variant is None:
            continue
        original_key = (task, None, config)
        baseline = instances.get(original_key, [])
        variant_stat = stats[key]
        original_stat = stats.get(original_key)
        hashes = {row['reference_sha256'] for row in baseline + rows if row.get('reference_sha256')}
        if len(hashes) > 1:
            raise ValueError(f'Reference sets differ for {task}/{config}/{variant}')
        original_f1 = original_stat['f1'] if original_stat else None
        variant_f1 = variant_stat['f1']
        delta = variant_f1 - original_f1 if variant_f1 is not None and original_f1 is not None else None
        original_ids, original_hits = _frequencies(baseline)
        variant_ids, variant_hits = _frequencies(rows)
        frequencies = {}
        for ref in sorted(original_ids | variant_ids):
            frequencies[ref] = dict(
                original=None if not baseline else dict(
                    detected=original_hits[ref], successful=original_stat['successful'],
                    attempts=original_stat['attempts'],
                ),
                transformed=dict(detected=variant_hits[ref], successful=variant_stat['successful'],
                                 attempts=variant_stat['attempts']),
            )
        comparison = {**variant_stat, 'original_f1': original_f1, 'delta_f1': delta,
                      'reference_frequencies': frequencies}
        comparisons.append(comparison)
        by_config[config][variant_stat['fixture_id'] or task].append(comparison)

    configurations = []
    for config, fixtures in sorted(by_config.items()):
        summaries = [
            dict(fixture_id=fixture, variants=len(variants),
                 comparable_variants=sum(v['delta_f1'] is not None for v in variants),
                 **{metric: _mean(v[metric] for v in variants)
                    for metric in ('precision', 'recall', 'f1', 'delta_f1')})
            for fixture, variants in sorted(fixtures.items())
        ]
        configurations.append(dict(
            config_id=config, fixture_count=len(summaries),
            comparable_fixtures=sum(f['delta_f1'] is not None for f in summaries),
            fixtures=summaries,
            **{metric: _mean(f[metric] for f in summaries)
               for metric in ('precision', 'recall', 'f1', 'delta_f1')},
        ))
    return dict(variants=comparisons, configurations=configurations)
