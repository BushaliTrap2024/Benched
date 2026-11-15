from copy import deepcopy
import pytest
from vulnbench.models import Finding
from vulnbench.scoring import score
from vulnbench.repeatability import analyze


def record(rep, findings, total=3, known=None):
    known = known if known is not None else [Finding(id='reference-one', type='xss')]
    return dict(task_id='task', config_id='model-medium', repetition=rep,
                total_repetitions=total, score=score(findings, known), failure=None)


def test_matched_findings_keep_locations_and_reference_metadata():
    rows = [record(1, [Finding(type='xss', file='src/a.js', line=5)]),
            record(2, [Finding(type='xss', file='src/a.js', line=6)]),
            record(3, [Finding(type='xss', file='src/b.js', line=5)])]
    result = analyze(rows)[0]
    assert result['reference_matched']['unique'] == 3
    assert result['reference_matched']['frequency_histogram'] == {1: 3}
    assert result['reference_coverage']['unique'] == 1
    assert result['reference_coverage']['seen_all'] == 1
    occurrences = [s['occurrences'][0] for s in result['reference_matched']['signatures']]
    assert [o['reference_id'] for o in occurrences] == ['reference-one'] * 3
    assert [o['finding']['file'] for o in occurrences] == ['src/a.js', 'src/a.js', 'src/b.js']
    assert all(r['score']['TP'] == 1 for r in rows)  # Still type-only scoring.


def test_duplicate_reports_count_once_per_repetition_and_keep_all_occurrences():
    rows = [record(rep, [Finding(type='ssrf', file='a.js', line=2)] * 2) for rep in range(1, 4)]
    result = analyze(rows)[0]
    sig = result['unmatched']['signatures'][0]
    assert sig['runs'] == 3 and len(sig['occurrences']) == 6
    assert result['unmatched']['seen_all'] == 1


def test_paper_basename_and_optional_full_path():
    rows = [record(1, [Finding(type='xss', file='a\\index.js', line=1)], 2),
            record(2, [Finding(type='xss', file='b/index.js', line=1)], 2)]
    assert analyze(rows)[0]['reference_matched']['unique'] == 1
    assert analyze(rows, 'relative-path')[0]['reference_matched']['unique'] == 2
    assert analyze(rows)[0]['reference_matched']['signatures'][0]['signature'] == ('task', 'model-medium', 'xss', 'index.js', 1)


def test_incomplete_runs_never_claim_all_requested_repetitions():
    rows = [record(1, [Finding(type='xss')]), record(2, [Finding(type='xss')])]
    failed = record(3, []); failed.update(score=None, failure='timeout')
    result = analyze(rows + [failed])[0]
    assert not result['complete']
    assert result['successful_runs'] == 2 and result['failed_attempts'] == 1
    assert result['reference_matched']['seen_all'] == 0
    assert result['reference_matched']['seen_several'] == 1
    failed_only = analyze([failed])[0]
    assert failed_only['reference_matched']['unique'] == 0


def test_duplicate_successful_rep_rejected():
    row = record(1, [])
    with pytest.raises(ValueError, match='Duplicate successful repetition'):
        analyze([row, deepcopy(row)])


def test_same_signature_can_be_matched_and_unmatched_without_losing_context():
    rows = [record(1, [Finding(type='xss',file='a.js',line=1)] * 2, total=1)]
    result = analyze(rows)[0]
    assert result['all_findings']['unique'] == 1
    assert result['reference_matched']['unique'] == result['unmatched']['unique'] == 1
    assert result['all_findings']['signatures'][0]['runs'] == 1
    assert len(result['all_findings']['signatures'][0]['occurrences']) == 2

def test_reproduces_published_signature_counts_and_separates_reported_locations():
    import json
    from pathlib import Path
    data=json.loads((Path(__file__).with_name('data')/'published-v1-signatures.json').read_text())
    models=[r for r in analyze(data['records']) if r['config_id']!='snyk-code']
    assert len([r for r in data['records'] if r['config_id']!='snyk-code'])==250
    def totals(view):
        return tuple(sum(r[view][key] for r in models) for key in ('unique','seen_once','seen_all'))
    assert totals('unmatched')==(161,80,22)
    assert totals('reference_coverage')==(158,9,134)
    assert totals('reference_matched')==(187,40,120)  # Requested location-sensitive extension.
