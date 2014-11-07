from codecs import open
from setuptools import setup

with open('README.rst', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='verifi',
    version='0.1.0',
    description="SSL/TLS certificate chain verification",
    long_description=long_description,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    author='Jeremy Carbaugh',
    author_email='jeremy@jcarbaugh.com',
    url='https://github.com/jcarbaugh/python-verifi',
    license='BSD',
    py_modules=['verifi'],
    install_requires=['certifi', 'pyOpenSSL==0.14', 'python-dateutil==2.2'],
    entry_points={
        'console_scripts': ['verifi = verifi:main']
    },
)
