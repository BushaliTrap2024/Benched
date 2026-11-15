"""Automate Snyk reference authoring, preserving curated and raw artifacts."""
import hashlib
import json
import posixpath
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..config import fixture_path
from ..models import References
from ..parsers.snyk_sarif import parse_snyk, sarif_results
from ..runners.snyk_code import execute


def _project_relative_path(uri: str, root: Path, project: Path, base_uri: str = '') -> str:
    if not uri:
        return ''
    uri = unquote(uri).replace('\\', '/')
    parsed = urlparse(uri)
    if parsed.scheme and parsed.scheme != 'file':
        raise ValueError(f'Unsupported SARIF URI scheme: {parsed.scheme}')
    if parsed.netloc and parsed.netloc != 'localhost':
        raise ValueError('Remote file URIs are not project locations')
    path = Path(parsed.path if parsed.scheme else uri)
    if path.is_absolute():
        return path.resolve().relative_to(project.resolve()).as_posix()
    if base_uri:
        base = urlparse(unquote(base_uri))
        if base.scheme not in ('', 'file') or base.netloc not in ('', 'localhost'):
            raise ValueError('Unsupported SARIF URI base')
        return (Path(base.path) / path).resolve().relative_to(project.resolve()).as_posix()
    # Resolve the two documented Snyk CLI formats, preserving source order.
    normalized = str(path)
    prefix = project.relative_to(root).as_posix() + '/'
    if normalized.startswith(prefix):
        normalized = normalized[len(prefix):]
    elif normalized.startswith('project/'):
        normalized = normalized[len('project/'):]
    normalized = posixpath.normpath(normalized)
    if normalized == '..' or normalized.startswith('../'):
        raise ValueError('SARIF path escapes project')
    # Resolve links in source projects too; references must name project files.
    return (project / normalized).resolve().relative_to(project.resolve()).as_posix()


def _severity_comparison(findings, original):
    remaining = list(original.get('vulnerabilities', [])) if original else []
    rows = []
    for finding in findings:
        match = next((v for v in remaining if (v.get('type'), v.get('file'), v.get('line')) ==
                      (finding.type, finding.file, finding.line)), None)
        if match:
            remaining.remove(match)
        rows.append(dict(candidate_id=finding.id, type=finding.type, file=finding.file, line=finding.line,
                         automatic_severity=finding.severity,
                         original_id=match.get('id') if match else None,
                         curated_severity=match.get('severity') if match else None,
                         differs=bool(match and match.get('severity') != finding.severity)))
    return {'comparison_protocol': 'exact type/file/line for diagnostics only; does not change V1 scoring',
            'candidates': rows, 'original_without_candidate': remaining}


async def generate(root, fixture_id, overwrite=False, executable='snyk', timeout=600, include_ignores=False):
    root = Path(root).resolve()
    fixture = fixture_path(root, fixture_id)
    project, target = fixture / 'project', fixture / 'findings.json'
    artifact = root / 'results' / 'references' / f'{fixture_id}-{uuid.uuid4().hex}'
    artifact.mkdir(parents=True)
    original_bytes = target.read_bytes() if target.exists() else None
    original = json.loads(original_bytes) if original_bytes is not None else None
    if original_bytes is not None:
        (artifact / 'previous-findings.json').write_bytes(original_bytes)
    raw = artifact / 'scan.sarif.json'
    args = [executable, 'code', 'test', str(project), '--json', f'--json-file-output={raw}']
    if include_ignores:
        args.append('--include-ignores')
    execution = {'argv': args, 'started_at': datetime.now(timezone.utc).isoformat()}
    try:
        stdout, stderr, status = await execute(args, root, timeout)
    except Exception as error:
        stdout, stderr = getattr(error, 'stdout', ''), getattr(error, 'stderr', '')
        execution.update(error=str(error), exit_status=getattr(error, 'exit_status', None))
        (artifact / 'stdout.txt').write_text(stdout)
        (artifact / 'stderr.txt').write_text(stderr)
        (artifact / 'execution.json').write_text(json.dumps(execution, indent=2))
        raise RuntimeError(f'Snyk execution failed; artifacts: {artifact}: {error}') from error
    (artifact / 'stdout.txt').write_text(stdout)
    (artifact / 'stderr.txt').write_text(stderr)
    execution['exit_status'] = status
    (artifact / 'execution.json').write_text(json.dumps(execution, indent=2))
    if not raw.exists():
        raw.write_text(stdout)
    if status not in (0, 1):
        raise RuntimeError(f'Snyk failed ({status}); artifacts: {artifact}')
    text = raw.read_text()
    findings = parse_snyk(text, strict=True)
    results = [r for r in sarif_results(text) if r.get('ruleId')]
    bases = json.loads(text)['runs'][0].get('originalUriBaseIds', {})
    counts = {}
    rule_metadata = []
    for finding, result in zip(findings, results):
        location = ((result.get('locations') or [{}])[0].get('physicalLocation') or {}).get('artifactLocation', {})
        base_id = location.get('uriBaseId')
        if base_id and base_id not in bases:
            raise ValueError(f'Unknown SARIF URI base: {base_id}')
        finding.file = _project_relative_path(finding.file, root, project, bases.get(base_id, {}).get('uri', ''))
        signature = json.dumps([result['ruleId'], finding.file, finding.line], ensure_ascii=False)
        counts[signature] = counts.get(signature, 0) + 1
        finding.id = f'{fixture_id}-{hashlib.sha256(signature.encode()).hexdigest()[:16]}-{counts[signature]}'
        rule_metadata.append(dict(candidate_id=finding.id, rule_id=result['ruleId'], sarif_level=result.get('level'),
                                  mapped_type=finding.type, mapped_severity=finding.severity))
    refs = References(description='Automatically generated Snyk Code reference candidates; not manually reviewed.', vulnerabilities=findings).validate_ids()
    data = refs.model_dump() | {
        '_note': 'Unreviewed candidates; review independently before selecting benchmark references.',
        'provenance': {'generator': 'snyk-code', 'review_status': 'unreviewed',
                       'created_at': datetime.now(timezone.utc).isoformat(),
                       'raw_artifact': str(raw.relative_to(root)), 'sha256': hashlib.sha256(raw.read_bytes()).hexdigest()},
    }
    candidate = artifact / 'candidate-findings.json'
    candidate.write_text(json.dumps(data, indent=2) + '\n')
    References.model_validate_json(candidate.read_text()).validate_ids()
    (artifact / 'mapping.json').write_text(json.dumps(rule_metadata, indent=2))
    (artifact / 'severity-comparison.json').write_text(json.dumps(_severity_comparison(findings, original), indent=2))
    if overwrite:
        # Explicit opt-in only, with a byte-exact backup and a concurrent-edit check.
        if (target.read_bytes() if target.exists() else None) != original_bytes:
            raise RuntimeError('Reference changed during scan; candidate retained, refusing overwrite')
        replacement = target.with_name(f'.findings-{uuid.uuid4().hex}.tmp')
        try:
            shutil.copyfile(candidate, replacement)
            replacement.replace(target)
        finally:
            replacement.unlink(missing_ok=True)
    return {'reference': str(target) if target.exists() else None,
            'candidate': str(candidate), 'artifacts': str(artifact),
            'installed': overwrite, 'count': len(findings)}
