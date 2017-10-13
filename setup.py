import sys

from setuptools import find_packages
from setuptools import setup

if sys.version_info < (3, 5):
    print('comarmor requires Python 3.5 or higher.', file=sys.stderr)
    sys.exit(1)

version = '0.0.0'

install_requires = [
    # 'apparmor',
    'setuptools',
]
tests_require = [
    'nose',
]

package_excludes = ['tests', 'docs']
packages = find_packages(exclude=package_excludes)

setup(
    name='comarmor',
    version=version,
    packages=packages,
    url='https://github.com/ComArmor/comarmor',
    download_url='https://github.com/ComArmor/comarmor/releases',
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
