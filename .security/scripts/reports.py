"""Small, bounded report contract shared by scanners and the trusted publisher."""
import json
from pathlib import Path

MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 5000
ENGINES = ('semgrep', 'trivy', 'deepsec')
STATUSES = ('complete', 'error', 'skipped', 'partial')
CATEGORIES = ('vulnerability', 'dependency', 'secret', 'misconfiguration', 'informational')
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN')


def clean(value, limit=240):
    return ''.join(c for c in str(value) if c.isprintable())[:limit]


def safe_path(value):
    value = str(value).removeprefix('/src/').removeprefix('./')
    if (not value or len(value) > 1024 or value.startswith('/') or '\\' in value
            or any(p in ('', '.', '..') for p in value.split('/'))
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('invalid finding path')
    return value


def finding(engine, category, rule, path, severity, confidence='unknown', line=1,
            title='', detail='', recommendation=''):
    severity = str(severity).upper()
    severity = {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'HIGH_BUG': 'INFO', 'BUG': 'INFO'}.get(severity, severity)
    if severity not in SEVERITIES:
        severity = 'UNKNOWN'
    confidence = str(confidence).lower()
    if confidence not in ('high', 'medium', 'low', 'unknown'):
        confidence = 'unknown'
    return dict(engine=engine, category=category, rule=clean(rule, 160), path=safe_path(path),
                severity=severity, confidence=confidence,
                line=max(1, min(int(line or 1), 1000000)), title=clean(title),
                detail=clean(detail, 1500), recommendation=clean(recommendation, 800))


def report(engine, status='complete', findings=None, reason='', coverage=None):
    return dict(schema=1, engine=engine, status=status, reason=clean(reason),
                findings=findings or [], coverage=coverage or {})


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, indent=2)
    if len(data.encode()) > MAX_REPORT_BYTES:
        raise ValueError('report exceeds size limit')
    path.write_text(data + '\n')


def load(path, engine):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError('unsafe or oversized report')
    data = json.loads(path.read_text())
    if (not isinstance(data, dict) or data.get('schema') != 1 or data.get('engine') != engine
            or data.get('status') not in STATUSES
            or not isinstance(data.get('findings'), list)
            or len(data['findings']) > MAX_FINDINGS):
        raise ValueError('invalid report schema')
    findings = []
    for f in data['findings']:
        if not isinstance(f, dict) or f.get('engine') != engine or f.get('category') not in CATEGORIES:
            raise ValueError('invalid finding')
        findings.append(finding(**{k: f[k] for k in (
            'engine', 'category', 'rule', 'path', 'severity', 'confidence', 'line',
            'title', 'detail', 'recommendation')}))
    return report(engine, data['status'], findings, data.get('reason', ''))


def semgrep(data):
    findings = []
    for item in data['results']:
        extra = item['extra']
        category = 'informational' if extra['severity'] == 'INFO' else 'vulnerability'
        findings.append(finding('semgrep', category, item['check_id'], item['path'],
                                extra['severity'], extra.get('metadata', {}).get('confidence'),
                                item['start']['line'], extra.get('message', '')))
    # Parse/timeout errors mean coverage is incomplete, even if the process exits zero.
    return report('semgrep', 'partial' if data.get('errors') else 'complete', findings,
                  'Some files could not be analyzed' if data.get('errors') else '')


def trivy(data):
    findings = []
    for result in data.get('Results', []):
        path = result['Target']
        for v in result.get('Vulnerabilities') or []:
            findings.append(finding('trivy', 'dependency', v['VulnerabilityID'], path,
                v['Severity'], title=v.get('Title', v['VulnerabilityID']),
                detail=f"{v.get('PkgName', '')} installed={v.get('InstalledVersion', '')}",
                recommendation=f"Fixed versions: {v.get('FixedVersion') or 'not supplied'}"))
        for s in result.get('Secrets') or []:
            # Never preserve Match, Code, or source excerpts from secret results.
            findings.append(finding('trivy', 'secret', s['RuleID'], path,
                s['Severity'], line=s.get('StartLine', 1), title='Potential exposed secret',
                recommendation='Verify without posting the value; revoke/rotate if confirmed.'))
        for m in result.get('Misconfigurations') or []:
            if m.get('Status') == 'FAIL':
                findings.append(finding('trivy', 'misconfiguration', m['ID'], path,
                    m['Severity'], line=(m.get('CauseMetadata') or {}).get('StartLine', 1),
                    title=m.get('Title', ''), recommendation=m.get('Resolution', '')))
    return report('trivy', findings=findings)


def deepsec(data_dir, expected, exit_code):
    records = [json.loads(p.read_text()) for p in Path(data_dir).glob('pr/files/**/*.json')]
    by_path = {r['filePath']: r for r in records}
    complete = exit_code in (0, 1) and all(
        p in by_path and by_path[p].get('status') == 'analyzed'
        and by_path[p].get('analysisHistory')
        and not (by_path[p]['analysisHistory'][-1].get('refusal') or {}).get('refused')
        for p in expected)
    findings = []
    for r in records:
        for f in r.get('findings', []):
            category = 'informational' if f['severity'] in ('BUG', 'HIGH_BUG') else 'vulnerability'
            findings.append(finding('deepsec', category, f['vulnSlug'], r['filePath'],
                f['severity'], f.get('confidence'), (f.get('lineNumbers') or [1])[0],
                f.get('title', ''), f.get('description', ''), f.get('recommendation', '')))
    complete = complete and (exit_code == 0 or bool(findings))
    return report('deepsec', 'complete' if complete else 'error', findings,
                  '' if complete else 'AI review failed, refused, or left files unreviewed')


def bucket(f):
    if f['category'] != 'vulnerability':
        return f['category']
    if f['severity'] in ('CRITICAL', 'HIGH') and f['confidence'] == 'high':
        return 'high-confidence vulnerability'
    return 'other vulnerability (review confidence)'


def blocking(f):
    return f['category'] == 'secret' or bucket(f) == 'high-confidence vulnerability'
