'''A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
'''

from codecs import open as copen
from os import path

import kibra
from setuptools import setup

# Get the long description from the README file
HERE = path.abspath(path.dirname(__file__))
with copen(path.join(HERE, 'README.rst'), encoding='utf-8') as _file:
    LONG_DESC = _file.read()

setup(
    name='kibra',
    # https://packaging.python.org/en/latest/single_source_version.html
    version=kibra.__version__,
    description='Kirale Border Router Administration',
    long_description=LONG_DESC,
    # The project's main homepage.
    url='https://github.com/KiraleTechnologies/kibra',
    # Author details
    author='Kirale Technologies',
    author_email='emontoya@kirale.com',
    license='MIT',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Environment :: Console', 'Environment :: Web Environment',
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Intended Audience :: Manufacturing',
        'Intended Audience :: Telecommunications Industry',
        'Topic :: Internet',
        'Topic :: Internet :: WWW/HTTP :: Site Management',
        'Topic :: Software Development :: Embedded Systems',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Hardware',
        'Topic :: System :: Networking :: Firewalls', 'Topic :: Utilities',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Operating System :: POSIX :: Linux'
    ],
    keywords='kirale kinos thread border router',
    packages=['kibra', 'kibra.ncp_fw'],
    include_package_data=True,
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=[
        'aiocoap==kirale-1.0',
        'bash==0.6',
        'daemonize==2.5.0',
        'importlib_resources==1.0.2',  # Not needed in Python 3.7
        'kitools==1.3.2',
        'pyroute2==0.5.3',
    ],
    entry_points={'console_scripts': ['kibra = kibra.__main__:main']},
)
