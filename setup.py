from setuptools import setup, find_packages
setup(
    name = "tahoestaticfs",
    version = "0.1.dev",
    packages = find_packages(),
    install_requires = ['fuse-python>=0.2', 'M2Crypto>=0.21', 'pycrypto>=2.6', 'nose>=1.0'],
    entry_points = {
        'console_scripts': [
            'tahoestaticfs = tahoestaticfs.cli:main',
        ]
    }
)
