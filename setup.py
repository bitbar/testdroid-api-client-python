# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

version = '3.1'

setup(name='testdroid',
      version=version,
      description="Testdroid API client for Python",
      long_description="""\nTestdroid API client for Python""",
      # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=['Operating System :: OS Independent',
                   'Topic :: Software Development',
                   'Intended Audience :: Developers'],
      keywords='testdroid rest api client',
      author='Henri Kivelä <henri.kivela@bitbar.com>, Sakari Rautiainen <sakari.rautiainen@bitbar.com>, '
             'Teppo Malinen <teppo.malinen@bitbar.com>, Jarno Tuovinen <jarno.tuovinen@bitbar.com>, '
             'Atte Keltanen <atte.keltanen@bitbar.com>',
      author_email='info@bitbar.com',
      url='http://www.bitbar.com',
      license='Apache License v2.0',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=[
          'requests',
      ],
      entry_points={
          'console_scripts': [
              'testdroid = testdroid:main',
          ],
      },
      test_suite='testdroid.tests.test_all',
      tests_require=[
          'responses',
      ],
      )
