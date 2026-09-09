"""Trusted, read-only DeepSec adapter. Never call from a PR-owned workflow with secrets."""
import argparse
import os
import subprocess
import tempfile
from pathlib import Path
import reports
from snapshot import snapshot, changed_files

POLICY = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--base', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--model', required=True)
    args = parser.parse_args()
    result = reports.report('deepsec', 'error', reason='AI review did not finish')
    try:
        if not os.environ.get('OPENROUTER_API_KEY'):
            result = reports.report('deepsec', 'skipped', reason='OPENROUTER_API_KEY is not configured')
        else:
            with tempfile.TemporaryDirectory(prefix='security-ai-') as tmp:
                root = Path(tmp)
                coverage = snapshot(args.source, root / 'source')
                files = changed_files(args.source, args.base, root / 'source')
                if len(files) > 20 or sum((root / 'source' / f).stat().st_size for f in files) > 500000:
                    result = reports.report('deepsec', 'partial', reason='Diff exceeds 20-file/500KB AI budget; manual review required')
                elif not files:
                    result = reports.report('deepsec', reason='No changed regular files to review')
                else:
                    (root / 'files.txt').write_text('\n'.join(files) + '\n')
                    (root / 'home').mkdir()
                    # Load only our reviewed model catalog, never the PR or user's Pi config.
                    (root / 'agent').mkdir()
                    (root / 'agent/models.json').write_bytes(
                        (POLICY / 'deepsec/models.json').read_bytes())
                    # Allowlist the environment: no GitHub credentials, Actions command files,
                    # production credentials, user subscriptions, or inherited agent configuration.
                    env = {'PATH': os.environ['PATH'], 'HOME': str(root / 'home'),
                           'TMPDIR': str(root), 'CI': 'true',
                           'OPENROUTER_API_KEY': os.environ['OPENROUTER_API_KEY'],
                           'SECURITY_SOURCE': str(root / 'source'),
                           'DEEPSEC_DATA_ROOT': str(root / 'data'),
                           'PI_CODING_AGENT_DIR': str(root / 'agent')}
                    cli = POLICY / 'deepsec/node_modules/deepsec/dist/cli.mjs'
                    cmd = ['node', str(cli), 'process', '--project-id', 'pr',
                           '--root', str(root / 'source'), '--files-from', str(root / 'files.txt'),
                           # Pi needs its provider prefix before OpenRouter's vendor/model ID.
                           '--no-ignore', '--agent', 'pi', '--model', f'openrouter/{args.model}',
                           # DeepSec 2.3.9's credential preflight needs the explicit key-env
                           # flag even with ai.apiKeyEnv configured. Repeat the trusted route.
                           '--ai-provider', 'openrouter',
                           '--ai-base-url', 'https://openrouter.ai/api/v1',
                           '--ai-api-key-env', 'OPENROUTER_API_KEY',
                           '--thinking-level', 'low', '--concurrency', '1',
                           '--batch-size', '5', '--max-turns', '12']
                    completed = subprocess.run(cmd, cwd=POLICY / 'deepsec', env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
                    result = reports.deepsec(root / 'data', files, completed.returncode)
                result['coverage'] = coverage | {'changed_files': len(files), 'max_files': 20}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result = reports.report('deepsec', 'error', reason='AI review failed; reproduce locally for diagnostics')
    reports.save(args.out / 'deepsec.json', result)
    print(f"deepsec: {result['status']}; {len(result['findings'])} findings")
    return 0 if result['status'] in ('complete', 'skipped') else 2


if __name__ == '__main__':
    raise SystemExit(main())
