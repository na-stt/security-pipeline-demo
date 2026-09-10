"""Deterministic gate over validated scanner observations; no model makes this decision."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
import reports
from render_report import render

POLICY_VERSION = '1'


def aggregate(directory, context=None):
    scanners = []
    findings = []
    for engine in reports.ENGINES:
        try:
            result = reports.load(directory / f'{engine}.json', engine)
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            result = reports.report(engine, 'error', reason='Missing or invalid scanner report')
        observations = result.pop('findings')
        result['finding_count'] = len(observations)
        result['blocking_count'] = sum(reports.blocking(f) for f in observations)
        result['conclusion'] = ('success' if result['status'] == 'complete'
                                and not result['blocking_count'] else 'failure')
        scanners.append(result)
        for f in observations:
            # An observation ID, not a claim that two different scanners found the same issue.
            identity = [f[k] for k in ('engine', 'category', 'rule', 'path', 'line', 'detail')]
            f['id'] = 'SEC-' + hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:16]
            f['decision'] = 'blocking' if reports.blocking(f) else 'advisory'
            f['baseline_status'] = 'unknown'
            findings.append(f)
    findings.sort(key=lambda f: (f['decision'] != 'blocking', reports.SEVERITIES.index(f['severity']),
                                  f['engine'], f['path'], f['line'], f['id']))
    counts = Counter(reports.bucket(f) for f in findings)
    missing = [r['engine'] for r in scanners if r['status'] != 'complete']
    blockers = sum(f['decision'] == 'blocking' for f in findings)
    reasons = []
    if context and context.get('scan_conclusion') != 'success':
        reasons.append('Source scan workflow did not complete successfully')
    if missing:
        reasons.append('Required scanners incomplete: ' + ', '.join(missing))
    if blockers:
        reasons.append(f'{blockers} blocking scanner observations')
    conclusion = 'failure' if reasons else 'success'
    summary = ['## Security review — ' + ('BLOCKED' if reasons else 'PASS'), '',
               f'{blockers} blocking observations · {len(findings) - blockers} advisory observations', '',
               '| Scanner | Coverage | Findings | Blocking |', '|---|---|---:|---:|']
    for r in scanners:
        summary.append(f"| {r['engine']} | {r['status']} | {r['finding_count']} | {r['blocking_count']} |")
    summary += ['', '| Finding group | Count |', '|---|---:|']
    for group in ('high-confidence vulnerability', 'other vulnerability (review confidence)',
                  'dependency', 'secret', 'misconfiguration', 'informational'):
        summary.append(f'| {group} | {counts[group]} |')
    summary += ['', *['- ' + reason for reason in reasons], '',
        'Policy: all three scanners must complete. Potential secrets and HIGH/CRITICAL code',
        'vulnerabilities with high scanner confidence block. Other findings are advisory.',
        'Confidence is not independent verification. Counts are observations, not unique vulnerabilities.',
        'Baseline status is unknown: Semgrep/Trivy scan the tracked snapshot; DeepSec reviews changed files.']
    return dict(schema_version=2, policy_version=POLICY_VERSION, context=context or {'scope': 'local'},
                conclusion=conclusion, reasons=reasons, blocking_count=blockers,
                finding_count=len(findings), summary='\n'.join(summary), scanners=scanners, findings=findings)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--context', type=Path)
    parser.add_argument('--markdown', type=Path)
    args = parser.parse_args()
    context = json.loads(args.context.read_text()) if args.context else None
    data = aggregate(args.reports, context)
    reports.save(args.out, data)
    markdown = args.markdown or args.out.with_suffix('.md')
    markdown.write_text(render(data))
    # A bounded summary is appropriate for Actions, while the artifact holds the full report.
    print(data['summary'])
