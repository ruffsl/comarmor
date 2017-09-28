import sys

from setuptools import find_packages
from setuptools import setup

version='0.0.0'

install_requires = [
    'setuptools',
]
tests_require = [
    'nose',
]

package_excludes = ['tests*', 'docs*']
packages = find_packages(exclude=package_excludes)

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
    description='Like AppArmor, but for Secure Communications',
    install_requires=install_requires,
    test_suite='tests',
    tests_require=tests_require,
)
