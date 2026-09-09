"""Run an OSS scanner in a disposable, credential-free Docker container."""
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
import reports
from snapshot import snapshot

POLICY = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--engine', required=True, choices=['semgrep', 'trivy'])
    args = parser.parse_args()
    result = reports.report(args.engine, 'error', reason='Scanner did not finish')
    try:
        with tempfile.TemporaryDirectory(prefix='security-scan-') as tmp:
            root = Path(tmp)
            coverage = snapshot(args.source, root / 'source')
            (root / 'output').mkdir(mode=0o777)
            (root / 'output').chmod(0o777)
            image = json.loads((POLICY / 'versions.json').read_text())[args.engine]
            subprocess.run(['docker', 'pull', image], check=True, stdout=subprocess.DEVNULL)
            # Match a non-root host user so private scanner cache directories can
            # be cleaned up afterward. Root callers retain the nobody identity.
            uid, gid = (os.getuid(), os.getgid()) if os.getuid() else (65534, 65534)
            cmd = ['docker', 'run', '--rm', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                   '--pids-limit=256', '--memory=4g', '--cpus=2', '--read-only',
                   '--tmpfs=/tmp:rw,noexec,nosuid,size=1g', f'--user={uid}:{gid}',
                   '-e', 'HOME=/tmp', '-v', f'{root / "source"}:/src:ro',
                   '-v', f'{POLICY}:/policy:ro', '-v', f'{root / "output"}:/out:rw', '-w', '/tmp']
            if args.engine == 'semgrep':
                cmd += ['--network=none', '--entrypoint=semgrep', image, 'scan',
                        '--config=/policy/semgrep/rules.yml', '--metrics=off',
                        '--disable-version-check', '--disable-nosem', '--no-git-ignore',
                        '--no-rewrite-rule-ids', '--jobs=2', '--timeout=10', '--max-memory=2000',
                        '--json-output=/out/raw.json', '/src']
            else:
                # Trivy's database exceeds 1 GB. Keep its disposable cache on runner
                # disk, not the memory-backed /tmp mount. Never share it across runs.
                (root / 'cache').mkdir()
                (root / 'cache').chmod(0o777)
                cmd += ['-v', f'{root / "cache"}:/cache:rw']
                # Trivy needs outbound access for public vulnerability/IaC databases.
                cmd += [image, 'filesystem', '--config=/policy/trivy/config.yaml',
                        '--ignorefile=/policy/trivy/empty.ignore',
                        '--secret-config=/policy/trivy/secret.yaml', '--cache-dir=/cache',
                        '--scanners=vuln,secret,misconfig', '--skip-dirs=/src/.git',
                        '--disable-telemetry', '--skip-version-check', '--offline-scan',
                        '--timeout=10m', '--format=json', '--output=/out/raw.json', '/src']
            # Scanner logs and raw results can include source or secret values: never publish them.
            completed = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=900)
            if completed.returncode != 0:
                raise ValueError('scanner process failed')
            raw = root / 'output/raw.json'
            if raw.stat().st_size > 64 * 1024 * 1024:
                raise ValueError('raw scanner output exceeds limit')
            result = getattr(reports, args.engine)(json.loads(raw.read_text()))
            result['coverage'] = coverage
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result = reports.report(args.engine, 'error', reason='Scanner failed; reproduce locally for diagnostics')
    reports.save(args.out / f'{args.engine}.json', result)
    print(f"{args.engine}: {result['status']}; {len(result['findings'])} findings")
    return 0 if result['status'] == 'complete' else 2


if __name__ == '__main__':
    raise SystemExit(main())
