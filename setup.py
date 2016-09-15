import os
import codecs
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    # intentionally *not* adding an encoding option to open
    return codecs.open(os.path.join(here, *parts), 'r').read()


setup(
    name='ghost',
    version="0.1.2",
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
        "simple-crypt==4.1.7"
    ],
    classifiers=[
        'Programming Language :: Python',
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
