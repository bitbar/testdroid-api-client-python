# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
import sys, os

version = '0.1.3'

setup(name='testdroid',
      version=version,
      description="Testdroid API client for Python",
      long_description="""\
Testdroid API client for Python""",
      classifiers=['Operating System :: OS Independent',
        'Topic :: Software Development', 
        'Intended Audience :: Developers'], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='testdroid rest api client',
      author='Henri Kivelä <henri.kivela@bitbar.com>, Sakari Rautiainen <sakari.rautiainen@bitbar.com>',
      author_email='info@bitbar.com',
      url='http://www.testdroid.com',
      license='Apache License v2.0',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=[
         'requests'
      ],

      entry_points = {
              'console_scripts': [
                  'testdroid = testdroid:main',                  
              ],              
          },
      )
