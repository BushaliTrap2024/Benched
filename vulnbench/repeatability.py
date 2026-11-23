"""Finding recurrence is independent of V1's type-only scoring.

The paper handoff uses basename(file) for reported signatures and reference IDs
for a separate reference-coverage view. Keep both, plus the original locations.
"""
from collections import Counter, defaultdict
import posixpath
from typing import Any

from .storage import instance_key, reject_duplicates, source_identity


def finding_signature(finding: dict, path_mode: str = 'basename') -> tuple:
    path = posixpath.normpath(str(finding.get('file', '')).replace('\\', '/'))
    if path == '.':
        path = ''
    if path_mode == 'basename':
        path = posixpath.basename(path)
    elif path_mode != 'relative-path':
        raise ValueError('path_mode must be basename or relative-path')
    return finding['type'], path, finding.get('line')


def _summarize(signatures: dict, repetitions: int) -> dict:
    counts = [len(item['repetitions']) for item in signatures.values()]
    return {
        'unique': len(signatures),
        'frequency_histogram': dict(sorted(Counter(counts).items())),
        'seen_once': sum(count == 1 for count in counts),
        'seen_several': sum(1 < count < repetitions for count in counts),
        'seen_all': sum(count == repetitions for count in counts),
        'signatures': [dict(signature=signature, runs=len(item['repetitions']),
                            repetitions=sorted(item['repetitions']),
                            occurrences=item['occurrences'])
                       for signature, item in signatures.items()],
    }


def analyze(records: list[dict], path_mode: str = 'basename') -> list[dict]:
    if path_mode not in ('basename', 'relative-path'):
        raise ValueError('path_mode must be basename or relative-path')
    if any(r.get('variant_id') is not None for r in records):
        reject_duplicates(records)
    groups = defaultdict(list)
    for record in records:
        groups[instance_key(record)].append(record)
    output = []
    for (task, variant, config), attempts in groups.items():
        prefix = (task, config) if variant is None else (task, config, variant)
        identity = dict(fixture_id=attempts[0].get("fixture_id"), **source_identity(variant)) if variant is not None else {}
        rows = [r for r in attempts if not r.get('failure') and not r.get('error') and r.get('score') is not None]
        repetitions = [r['repetition'] for r in rows]
        if len(repetitions) != len(set(repetitions)):
            raise ValueError(f'Duplicate successful repetition for {task}/{config}; analyze one experiment at a time')
        requested = max(r['total_repetitions'] for r in attempts)
        buckets: dict[str, dict[Any, dict]] = {name: {} for name in ('reference_matched', 'unmatched', 'all_findings', 'reference_coverage')}

        def add(bucket, signature, repetition, occurrence):
            item = buckets[bucket].setdefault(signature, {'repetitions': set(), 'occurrences': []})
            item['repetitions'].add(repetition)
            item['occurrences'].append(occurrence)

        for row in rows:
            detail = row['score']
            matches = {m['finding_index']: m['reference_id'] for m in detail['matches']}
            for index, finding in enumerate(detail['agentFindings']):
                reference_id = matches.get(index)
                occurrence = dict(repetition=row['repetition'], finding_index=index,
                                  finding=finding, reference_id=reference_id)
                # Scope task/config in the exported signature, not just the group.
                signature = (*prefix, *finding_signature(finding, path_mode))
                add('all_findings', signature, row['repetition'], occurrence)
                add('reference_matched' if reference_id is not None else 'unmatched',
                    signature, row['repetition'], occurrence)
                if reference_id is not None:
                    add('reference_coverage', (*prefix, reference_id), row['repetition'], occurrence)
        output.append(dict(
            **identity, task_id=task, config_id=config, signature_path_mode=path_mode,
            successful_runs=len(rows), requested_repetitions=requested,
            failed_attempts=len(attempts)-len(rows),
            complete=set(repetitions) == set(range(1, requested + 1)),
            # Use requested repetitions: an incomplete experiment cannot claim
            # a finding appeared in every planned repetition.
            **{name: _summarize(bucket, requested) for name, bucket in buckets.items()},
        ))
    return output
