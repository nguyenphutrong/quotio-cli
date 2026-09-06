#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('notices', Path(__file__).with_name('third-party-notices.py'))
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class NoticesTests(unittest.TestCase):
    def test_selects_build_and_normal_dependencies_and_requires_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'LICENSE').write_text('Required copyright notice')
            data = {'resolve': {'root': 'app', 'nodes': [
                {'id': 'app', 'deps': [
                    {'pkg': 'normal', 'dep_kinds': [{'kind': None}]},
                    {'pkg': 'build', 'dep_kinds': [{'kind': 'build'}]},
                    {'pkg': 'test', 'dep_kinds': [{'kind': 'dev'}]}]},
                *[{'id': name, 'deps': []} for name in ['normal', 'build', 'test']]]},
                'packages': [{'id': name, 'name': name, 'version': '1.0',
                              'source': 'registry', 'license': 'MIT',
                              'manifest_path': str(root / 'Cargo.toml')}
                             for name in ['normal', 'build', 'test']]}
            result = notices.render(data)
            self.assertIn('## normal', result)
            self.assertIn('## build', result)
            self.assertNotIn('## test', result)
            self.assertIn('Required copyright notice', result)
            (root / 'LICENSE').unlink()
            with self.assertRaises(ValueError):
                notices.render(data)


if __name__ == '__main__':
    unittest.main()
