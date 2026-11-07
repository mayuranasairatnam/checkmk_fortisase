"""
Verify version selection, repeat releases and versioned package metadata.
"""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    """
    Load a Python module, including extensionless special agents.

    Input:
        Arguments supplied by the test fixtures or the check under test.

    Output:
        Imported module after executing the supplied source file.

    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load('release_version', ROOT / '.github/scripts/release_version.py')
builder = load('release_builder', ROOT / 'build_mkp.py')


class ReleaseTests(unittest.TestCase):
    """
    Release version selection and reproducible MKP tests.

    Input:
        Constructor arguments supported by the test double or test runner.

    Output:
        ReleaseTests instance.

    """
    def test_version_selection(self):
        """
        Verify version selection.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        cases = [
            ('', '', '1.0.0'),
            ('', 'unrelated\nv1.0.0-rc1\n', '1.0.0'),
            ('', 'v1.0.9\nv1.0.10\nv1.0.2\n', '1.0.11'),
            ('', 'v1.9.99\nv2.0.0\n', '2.0.1'),
            ('v1.0.0\n', '', '1.0.0'),
            ('v1.0.1\n', 'v1.0.2\n', '1.0.1'),
        ]
        for current, existing, expected in cases:
            with self.subTest(current=current, existing=existing):
                with patch.object(release.subprocess, 'check_output',
                                  side_effect=[current, existing]):
                    self.assertEqual(release.release_version(), expected)

    def test_release_version_matches_filename_and_metadata(self):
        """
        Verify release version matches filename and metadata.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'LICENSE').write_bytes((ROOT / 'LICENSE').read_bytes())
            (root / 'cmk_addons_plugins').symlink_to(ROOT / 'cmk_addons_plugins',
                                                    target_is_directory=True)
            with patch.object(builder, 'ROOT', root):
                path = builder.build('1.2.3')
                self.assertEqual(path.name, 'check_fortisase-1.2.3.mkp')
                with tarfile.open(path) as archive:
                    metadata = json.load(archive.extractfile('info.json'))
                    with tarfile.open(fileobj=io.BytesIO(
                            archive.extractfile('cmk_addons_plugins.tar').read())) as inner:
                        self.assertEqual(inner.getnames(), metadata['files']['cmk_addons_plugins'])
                        self.assertEqual(metadata['num_files'], len(inner.getnames()))
                        self.assertEqual(inner.extractfile('fortisase/LICENSE').read(),
                                         (ROOT / 'LICENSE').read_bytes())
                    self.assertIn("'version': '1.2.3'", archive.extractfile('info').read().decode())
                self.assertEqual(metadata['version'], '1.2.3')
                first = path.read_bytes()
                builder.build('1.2.3')
                self.assertEqual(first, path.read_bytes())

    def test_invalid_versions_are_rejected(self):
        """
        Verify invalid versions are rejected.

        Input:
            Test fixtures and mocks defined by this test case.

        Output:
            None; assertions fail if the expected behavior is not met.

        """
        for version in ('v1.0.0', '01.0.0', '1.0', '../other', '1.0.0-rc1'):
            with self.subTest(version=version):
                with self.assertRaises(argparse.ArgumentTypeError):
                    builder.build(version)
