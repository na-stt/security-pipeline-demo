"""Optional integration test: SEMGREP_BIN=/path/to/semgrep python3 -m unittest ..."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.environ.get('SEMGREP_BIN'), 'Set SEMGREP_BIN for real scanner fixtures')
class SemgrepFixtures(unittest.TestCase):
    def test_risky_calls_and_import_alias_are_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            source.mkdir()
            (source / 'app.py').write_text('''import pickle, subprocess, yaml
def decode(payload):
    pickle.loads(payload)
    subprocess.run(payload, shell=True)
    yaml.unsafe_load(payload)
''')
            (source / 'app.js').write_text('''const cp = require("child_process");
function route(req, res) { cp.exec(req.query.command); }
function calculate(input) { return eval(input); }
''')
            output = root / 'result.json'
            config = Path(__file__).resolve().parents[1] / 'semgrep/rules.yml'
            env = os.environ | {'HOME': str(root / 'home')}
            subprocess.run([os.environ['SEMGREP_BIN'], 'scan', '--config', str(config),
                '--metrics=off', '--disable-version-check', '--disable-nosem',
                '--no-git-ignore', '--no-rewrite-rule-ids', '--json-output', str(output),
                str(source)], check=True, env=env, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=60)
            result = json.loads(output.read_text())
            self.assertFalse(result['errors'])
            self.assertEqual({f['check_id'] for f in result['results']}, {
                'python-unsafe-pickle', 'python-shell-command', 'python-unsafe-yaml',
                'javascript-dynamic-evaluation', 'express-request-to-shell'})
