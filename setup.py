import os
import subprocess
from setuptools import setup, find_packages

basedir = os.path.abspath(os.path.dirname(__file__))

def get_git_hash():
    """
    Get version from asv/__init__.py and generate asv/_version.py
    """
    # Obtain git revision
    githash = ""
    if os.path.isdir(os.path.join(basedir, '.git')):
        try:
            proc = subprocess.Popen(
                ['git', '-C', basedir, 'rev-parse', 'HEAD'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            rev, err = proc.communicate()
            if proc.returncode == 0:
                githash = rev.strip().decode('ascii')
        except OSError:
            pass
    return githash


def get_git_revision():
    """
    Get the number of revisions since the last tag.
    """
    revision = "0"
    if os.path.isdir(os.path.join(basedir, '.git')):
        try:
            proc = subprocess.Popen(
                ['git', '-C', basedir, 'rev-list', '--count', 'HEAD'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            rev, err = proc.communicate()
            if proc.returncode == 0:
                revision = int(rev.strip().decode('ascii'))
        except (OSError, ValueError):
            pass
    return revision


def write_version_file(filename, version, revision):
    # Write revision file (only if it needs to be changed)
    content = '''
__version__ = "{0}"
__githash__ = "{1}"
__release__ = {2}
    '''.format(version, revision, 'dev' not in version)

    old_content = None
    if os.path.isfile(filename):
        with open(filename, 'r') as f:
            old_content = f.read()
    if content != old_content:
        with open(filename, 'w') as f:
            f.write(content)


version = "0.1.dev"

git_hash = get_git_hash()
release = 'dev' not in version
if not release:
    version += '%s+%s' % (get_git_revision(), git_hash[:6])
write_version_file(
    os.path.join(basedir, 'tahoestaticfs', 'version.py'), version, git_hash)

setup(
    name="tahoestaticfs",
    version=version,
    packages=find_packages(),
    install_requires=['fuse-python>=0.2', 'cryptography>=0.5', 'nose>=1.0'],
    test_suite='nose.collector',
    entry_points={
        'console_scripts': [
            'tahoestaticfs = tahoestaticfs.cli:main',
        ]
    }
)
