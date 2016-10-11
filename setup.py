import os
import codecs
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    # intentionally *not* adding an encoding option to open
    return codecs.open(os.path.join(here, *parts), 'r').read()


setup(
    name='ghost',
    version="0.4.1",
    url='https://github.com/nir0s/ghost',
    author='nir0s',
    author_email='nir36g@gmail.com',
    license='LICENSE',
    platforms='All',
    description='Ghost stores your secrets where no one can see',
    long_description=read('README.rst'),
    py_modules=['ghost'],
    entry_points={'console_scripts': ['ghost = ghost:main']},
    install_requires=[
        "click==6.6",
        "tinydb==3.2.1",
        "appdirs==1.4.0",
        "cryptography>=1.5"
    ],
    extras_require={
        'vault': ['hvac>=0.2.16'],
        'consul': ['requests>=2.11.1'],
        'sqlalchemy': ['sqlalchemy>=1.0.15'],
        'elasticsearch': ['elasticsearch>=2.4.0']
    },
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Natural Language :: English',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
