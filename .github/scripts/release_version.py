"""
Select an idempotent release version from stable vMAJOR.MINOR.PATCH tags.
"""
import re
import subprocess


def versions(tags):
    return [tuple(map(int, tag[1:].split('.'))) for tag in tags.splitlines()
            if re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag)]


def release_version():
    current = versions(subprocess.check_output(
        ['git', 'tag', '--points-at', 'HEAD'], text=True))
    if current:
        version = max(current)
    else:
        existing = versions(subprocess.check_output(['git', 'tag', '--list'], text=True))
        if existing:
            major, minor, patch = max(existing)
            version = (major, minor, patch + 1)
        else:
            version = (1, 0, 0)
    return '.'.join(map(str, version))


if __name__ == '__main__':
    print(release_version())
