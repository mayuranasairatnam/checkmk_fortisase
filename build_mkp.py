#!/usr/bin/env python3
"""
Build a deterministic native MKP for Checkmk 2.4 and 2.5 using the Python stdlib.
"""
import argparse
import gzip
import io
import json
from pathlib import Path
import pprint
import re
import tarfile

ROOT = Path(__file__).resolve().parent
NAME = 'check_fortisase'
VERSION = '1.0.0'


def package_version(value):
    """
    Validate the numeric release version used in metadata and filenames.
    """
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise argparse.ArgumentTypeError('version must be MAJOR.MINOR.PATCH, for example 1.0.0')
    return value


def entry(archive, name, data, executable=False):
    """
    Add a deterministic file member to the MKP archive.

    Input:
        archive: Open tar archive receiving the new member.
        name: Name assigned to the object being created.
        data: File contents as bytes.
        executable: Whether to store executable permissions on the archive member.

    Output:
        None; writes the data to the archive with fixed metadata.

    """
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755 if executable else 0o644
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def build(version=VERSION):
    """
    Build a reproducible native Checkmk package.

    Input:
        Plugin sources, package constants and an optional release version.

    Output:
        Path to the generated MKP; also writes the package and prints its path.

    """
    version = package_version(version)
    family = ROOT / 'cmk_addons_plugins'
    files = {str(p.relative_to(family)): p for p in family.rglob('*')
             if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    files['fortisase/LICENSE'] = ROOT / 'LICENSE'
    files = dict(sorted(files.items()))
    metadata = {
        'name': NAME, 'title': 'FortiSASE', 'version': version,
        'author': 'Mayuran Asairatnam', 'description': 'FortiSASE HTTPS API monitoring: PoP bandwidth, SWG/VPN sessions, remote certificates, license seats and API health.',
        'download_url': 'https://github.com/mayuranasairatnam/checkmk_fortisase/releases/latest', 'version.min_required': '2.4.0', 'version.packaged': '2.4.0',
        'version.usable_until': '2.5.99', 'num_files': len(files),
        'files': {'cmk_addons_plugins': list(files)},
    }
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, path in files.items():
            entry(archive, name, path.read_bytes(), path.parent.name == 'libexec')
    output = ROOT / f'{NAME}-{version}.mkp'
    with output.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            entry(archive, 'info', (pprint.pformat(metadata, sort_dicts=True) + '\n').encode())
            entry(archive, 'info.json', (json.dumps(metadata, indent=2, sort_keys=True) + '\n').encode())
            entry(archive, 'cmk_addons_plugins.tar', inner.getvalue())
    print(output)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', type=package_version, default=VERSION)
    build(parser.parse_args().version)
