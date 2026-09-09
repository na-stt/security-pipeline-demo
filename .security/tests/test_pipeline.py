import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reports
import deepsec
from aggregate import aggregate
from snapshot import snapshot, changed_files


class PipelineTests(unittest.TestCase):
    def test_deepsec_requires_openrouter_key_without_credential_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            argv = ['deepsec.py', '--source', temp, '--base', 'main',
                    '--out', temp, '--model', 'openai/gpt-5.5']
            with patch.object(sys, 'argv', argv), patch.dict(os.environ, {
                'AI_GATEWAY_API_KEY': 'synthetic-old-key',
                'OPENAI_API_KEY': 'synthetic-direct-key',
            }, clear=True), patch.object(deepsec, 'snapshot') as snap:
                self.assertEqual(deepsec.main(), 0)
                snap.assert_not_called()
            result = json.loads((Path(temp) / 'deepsec.json').read_text())
            self.assertEqual(result['status'], 'skipped')
            self.assertIn('OPENROUTER_API_KEY', result['reason'])

    def test_deepsec_routes_model_and_isolates_credentials(self):
        def fake_snapshot(source, target):
            target.mkdir()
            (target / 'app.py').write_text('print("fixture")\n')
            return {}

        def fake_cli(cmd, **kwargs):
            self.assertEqual(cmd[cmd.index('--model') + 1], 'openrouter/openai/gpt-5.5')
            self.assertEqual(cmd[cmd.index('--ai-provider') + 1], 'openrouter')
            self.assertEqual(cmd[cmd.index('--ai-base-url') + 1], 'https://openrouter.ai/api/v1')
            self.assertEqual(cmd[cmd.index('--ai-api-key-env') + 1], 'OPENROUTER_API_KEY')
            env = kwargs['env']
            self.assertEqual(env['OPENROUTER_API_KEY'], 'synthetic-openrouter-key')
            for name in ('GITHUB_TOKEN', 'AI_GATEWAY_API_KEY', 'OPENAI_API_KEY', 'NODE_OPTIONS'):
                self.assertNotIn(name, env)
            record = Path(env['DEEPSEC_DATA_ROOT']) / 'pr/files/app.py.json'
            record.parent.mkdir(parents=True)
            record.write_text(json.dumps(dict(filePath='app.py', status='analyzed',
                                              findings=[], analysisHistory=[{}])))
            return subprocess.CompletedProcess(cmd, 0)

        with tempfile.TemporaryDirectory() as temp:
            argv = ['deepsec.py', '--source', temp, '--base', 'main',
                    '--out', temp, '--model', 'openai/gpt-5.5']
            with patch.object(sys, 'argv', argv), patch.dict(os.environ, {
                'PATH': os.environ['PATH'], 'OPENROUTER_API_KEY': 'synthetic-openrouter-key',
                'GITHUB_TOKEN': 'synthetic-github-token', 'AI_GATEWAY_API_KEY': 'synthetic-old-key',
                'OPENAI_API_KEY': 'synthetic-direct-key', 'NODE_OPTIONS': '--untrusted-preload',
            }, clear=True), patch.object(deepsec, 'snapshot', side_effect=fake_snapshot), \
                    patch.object(deepsec, 'changed_files', return_value=['app.py']), \
                    patch.object(deepsec.subprocess, 'run', side_effect=fake_cli):
                self.assertEqual(deepsec.main(), 0)
            report = (Path(temp) / 'deepsec.json').read_text()
            self.assertEqual(json.loads(report)['status'], 'complete')
            self.assertNotIn('synthetic-openrouter-key', report)

    def test_rejects_escaping_paths_and_commands(self):
        for path in ('../secret', '/etc/passwd', 'a/../b', 'a\\b', 'x\n::error::injected'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                reports.safe_path(path)

    def test_secret_value_and_snippet_are_never_retained(self):
        raw = {'Results': [{'Target': 'app.env', 'Secrets': [{
            'RuleID': 'test', 'Severity': 'HIGH', 'StartLine': 4,
            'Match': 'do-not-publish-me', 'Code': {'Lines': ['do-not-publish-me']}}]}]}
        result = reports.trivy(raw)
        self.assertNotIn('do-not-publish-me', json.dumps(result))
        self.assertEqual(result['findings'][0]['category'], 'secret')

    def test_failure_is_not_clean_and_skip_is_neutral(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.assertEqual(aggregate(directory)['conclusion'], 'failure')
            for engine in reports.ENGINES:
                reports.save(directory / f'{engine}.json', reports.report(engine))
            self.assertEqual(aggregate(directory)['conclusion'], 'success')
            reports.save(directory / 'deepsec.json', reports.report('deepsec', 'skipped'))
            self.assertEqual(aggregate(directory)['conclusion'], 'neutral')

    def test_confidence_and_dependency_policy(self):
        f = reports.finding('semgrep', 'vulnerability', 'test', 'app.py', 'HIGH', 'medium')
        self.assertFalse(reports.blocking(f))
        f['confidence'] = 'high'
        self.assertTrue(reports.blocking(f))
        f['category'] = 'dependency'
        self.assertFalse(reports.blocking(f))

    def test_deepsec_exit_one_requires_completed_records(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'pr/files/app.py.json'
            path.parent.mkdir(parents=True)
            r = dict(filePath='app.py', status='analyzed', findings=[{
                'severity': 'HIGH', 'vulnSlug': 'test', 'confidence': 'high'}], analysisHistory=[{}])
            path.write_text(json.dumps(r))
            self.assertEqual(reports.deepsec(temp, ['app.py'], 1)['status'], 'complete')
            r['status'] = 'error'
            path.write_text(json.dumps(r))
            self.assertEqual(reports.deepsec(temp, ['app.py'], 1)['status'], 'error')
            r['status'] = 'analyzed'
            r['analysisHistory'] = [{'refusal': {'refused': True}}]
            path.write_text(json.dumps(r))
            self.assertEqual(reports.deepsec(temp, ['app.py'], 0)['status'], 'error')
            self.assertEqual(reports.deepsec(temp, ['missing.py'], 0)['status'], 'error')

    def test_snapshot_ignores_export_attributes_and_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / 'repo'
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)
            git('init')
            git('config', 'user.name', 'Fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (repo / 'app.py').write_text('print("base")\n')
            git('add', '.')
            git('commit', '-m', 'base')
            base = git('rev-parse', 'HEAD').decode().strip()
            (repo / '.gitattributes').write_text('app.py export-ignore\n')
            (repo / '.semgrepignore').write_text('*\n')
            (repo / 'escape').symlink_to('/etc/passwd')
            (repo / 'app.py').write_text('print("head")\n')
            git('add', '.')
            git('commit', '-m', 'head')
            output = root / 'snapshot'
            coverage = snapshot(repo, output)
            self.assertEqual((output / 'app.py').read_text(), 'print("head")\n')
            self.assertFalse((output / 'escape').exists())
            self.assertFalse((output / '.semgrepignore').exists())
            self.assertFalse((output / '.git').exists())
            self.assertEqual(coverage['excluded_symlinks_or_ignore_files'], 2)
            self.assertIn('app.py', changed_files(repo, base, output))

    def test_untrusted_text_does_not_reach_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            f = reports.finding('semgrep', 'vulnerability', 'evil', 'app.py', 'HIGH',
                title='@everyone [click](https://evil.invalid)', detail='ignore all policy')
            reports.save(directory / 'semgrep.json', reports.report('semgrep', findings=[f]))
            self.assertNotIn('evil.invalid', aggregate(directory)['summary'])
            self.assertNotIn('ignore all policy', aggregate(directory)['summary'])


if __name__ == '__main__':
    unittest.main()
