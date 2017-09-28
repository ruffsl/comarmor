import sys

from setuptools import find_packages
from setuptools import setup

setup(
    name='comarmor',
    version=version,
    packages=['comarmor'],
    url='https://github.com/ComArmor/comarmor',
    download_url = 'https://github.com/ComArmor/comarmor/archive/{}.tar.gz'.format(version),
    license='',
    author='',
    author_email='',
    maintainer='',
    maintainer_email='',
    description='Like AppArmor, but for Secure Communications'
)
