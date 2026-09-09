"""Validate untrusted reports and generate fixed-format presentation data."""
import argparse
from collections import Counter
from pathlib import Path
import reports


def aggregate(directory):
    result = []
    for engine in reports.ENGINES:
        try:
            result.append(reports.load(directory / f'{engine}.json', engine))
        except (OSError, ValueError, TypeError, KeyError):
            result.append(reports.report(engine, 'error', reason='Missing or invalid scanner report'))
    findings = [f for r in result for f in r['findings']]
    counts = Counter(reports.bucket(f) for f in findings)
    incomplete = any(r['status'] in ('error', 'partial') for r in result)
    blocking = any(reports.blocking(f) for f in findings)
    summary = ['## Security scan', '', '| Scanner | Coverage status | Findings |', '|---|---|---:|']
    for r in result:
        summary.append(f"| {r['engine']} | {r['status']} | {len(r['findings'])} |")
    summary += ['', '| Finding group | Count |', '|---|---:|']
    for group in ('high-confidence vulnerability', 'other vulnerability (review confidence)',
                  'dependency', 'secret', 'misconfiguration', 'informational'):
        summary.append(f'| {group} | {counts[group]} |')
    summary += ['', 'High confidence is a scanner/model estimate, not independent verification.',
                'Counts are scanner findings; overlapping reports may describe the same vulnerability.',
                'Baseline: Semgrep and Trivy scan the full tracked snapshot. DeepSec reviews changed files.',
                'DeepSec skips forks and runs only when enabled, with a model and credential configured.',
                'Dependency/CVE and misconfiguration findings are advisory in this initial policy.',
                'Full normalized findings and coverage details are in the linked run artifacts.']
    conclusion = 'failure' if incomplete or blocking else 'neutral' if any(r['status'] == 'skipped' for r in result) else 'success'
    return {'summary': '\n'.join(summary), 'conclusion': conclusion,
            'findings': findings, 'scanners': result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = aggregate(args.reports)
    reports.save(args.out, data)
    print(data['summary'])
