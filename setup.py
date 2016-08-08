from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='mobbage',

    version='0.1',

    description='A HTTP stress test and benchmark tool',
    long_description=long_description,
    url='https://github.com/redfin/mobbage',

    author='Eric Schwimmer',
    author_email='git@nerdvana.org',

    license='Apache 2.0',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Benchmark',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='http http/2 benchmark stress load test',

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=['requests'],

    entry_points={
        'console_scripts': [
            'mobbage = mobbage:main'
        ],
    },
)
