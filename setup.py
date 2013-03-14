#!/usr/bin/env python

from distribute_setup import use_setuptools
use_setuptools()
from setuptools import setup

# from distutils.core import setup


setup(name='cvrfparse',
      version='0.9',
      packages=["cvrfparse"],
      package_data={'cvrfparse': ['schemata/*/*/*.xsd', 'schemata/*/*.xsd', 
                                  'schemata/*.xml',
                                  'sample-xml/*']},
      install_requires=['lxml'],
      description='CVRF parsing/validation utility',
      author='Mike Schiffman',
      author_email='mschiffm@cisco.com',
      url='http://pypi.python.org/pypi/cvrfparse',
      entry_points= {
      	'console_scripts': [
	   'cvrfparse = cvrfparse.cvrfparse:main',
	]
      }
)
