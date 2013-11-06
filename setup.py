from distutils.core import setup
#from setuptools import setup

setup(name='cvrfparse',
      version='1.0',
      packages=["cvrfparse"],
      package_data={'cvrfparse': ['schemata/*/*/*.xsd', 'schemata/*/*.xsd', 
                                  'schemata/*.xml',
                                  'sample-xml/*']},
      install_requires=['lxml'],
      description='CVRF parsing/validation utility',
      author='Mike Schiffman',
      author_email='mschiffm@cisco.com',
      url='http://pypi.python.org/pypi/cvrfparse',
      entry_points = 
      {
        'console_scripts': ['cvrfparse = cvrfparse.cvrfparse:main']
      }
)
