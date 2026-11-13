"""Pure setup tests: no package, service, firewall or system configuration changes."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
import yaml

spec = importlib.util.spec_from_file_location('setup', pathlib.Path(__file__).resolve().parents[1] / 'src-tauri/src/protection/configure.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        setup.ROOT = pathlib.Path(self.temp.name) / 'private'
        setup.CONFIG_ROOT = pathlib.Path(self.temp.name) / 'engine'
        setup.ROOT.mkdir()
        setup.CONFIG_ROOT.mkdir()
        self.owner(True)
        (setup.CONFIG_ROOT / 'credentials.yaml').write_text('url: http://127.0.0.1:8080/\n')
        (setup.CONFIG_ROOT / 'acquis.yaml').write_text('filenames: [/var/log/auth.log]\nlabels: {type: syslog}\n')
        (setup.CONFIG_ROOT / 'config.yaml').write_text(yaml.safe_dump({'api': {'client': {'credentials_path': str(setup.CONFIG_ROOT / 'credentials.yaml')}}, 'crowdsec_service': {'acquisition_path': str(setup.CONFIG_ROOT / 'acquis.yaml'), 'acquisition_dir': ''}}))

    def owner(self, managed):
        (setup.ROOT / 'setup-owner.json').write_text(json.dumps({'managedEngine': managed, 'packageBouncers': ['vendor-generated']}))

    def test_new_engine_private_defaults_and_repeatable_report(self):
        setup.configure()
        setup.configure()
        report = setup.read_json(setup.ROOT / 'sources.json')
        self.assertEqual(report['inputs'][0]['kind'], 'syslog')
        self.assertEqual(report['packageBouncers'], ['vendor-generated'])
        privacy = yaml.safe_load((setup.CONFIG_ROOT / 'config.yaml.local').read_text())
        self.assertFalse(privacy['api']['server']['online_client']['sharing'])

    def test_preserves_existing_overrides(self):
        self.owner(False)
        local = setup.CONFIG_ROOT / 'config.yaml.local'
        text = 'api: {server: {online_client: {sharing: true}}}\n'
        local.write_text(text)
        setup.configure()
        self.assertEqual(local.read_text(), text)

    def test_no_inputs_does_not_claim_configured(self):
        (setup.CONFIG_ROOT / 'acquis.yaml').write_text('# no inputs\n')
        with self.assertRaisesRegex(ValueError, 'No supported log'):
            setup.configure()
        self.assertFalse((setup.ROOT / 'sources.json').exists())

    def test_remote_engine_rejected_without_rewriting_credentials(self):
        credentials = setup.CONFIG_ROOT / 'credentials.yaml'
        credentials.write_text('url: https://existing.example:8443\n')
        with self.assertRaisesRegex(ValueError, 'local CrowdSec API'):
            setup.configure()
        self.assertIn('existing.example', credentials.read_text())

if __name__ == '__main__':
    unittest.main()
