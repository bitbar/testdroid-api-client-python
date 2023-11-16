[![PyPI version](https://badge.fury.io/py/testdroid.svg)](https://badge.fury.io/py/testdroid)


Python client for Testdroid Cloud APIv2
=======================================

Dependencies
-----

For Linux installation you need Python dev package.

Ubuntu
`sudo apt-get install python-dev`

Command line
-----

Install it with:
`sudo pip install testdroid`

Upgrade it with:
`sudo pip install testdroid --upgrade`

Usage
-----

`testdroid --help`

Note that you can set `TESTDROID_APIKEY` and `TESTDROID_URL` environment variables.


Module
-----

You can use this class as a command line utility or import it to your own code.

The example below is using api key as the authentication method.

Example:

```python
>>> from testdroid import Testdroid
>>> testdroid = Testdroid(apikey="<your api key>")
>>> testdroid.get_test_run(1233, 12345)
{u'displayName': u'Test Run 1', u'logZipState': u'BLANK', u'screenshotZipState': u'BLANK', u'projectId': 12340, u'number': 1, u'successRatio': 0.814815, u'createTime': 1393595647000, u'executionRatio': 1.0, u'state': u'FINISHED', u'startedByDisplayName': u'John Doe', u'id': 10} 
```

Developing and testing
----------------------

Set up sandbox

`virtualenv myenv && source myenv/bin/activate`

Build example

`python setup.py clean && python setup.py sdist && pip install -U dist/testdroid-<latest version>.tar.gz`

Usage

`testdroid`


Troubleshooting
-----

If you see Pillow error messages on Linux you are most likely missing python-dev, see dependencies.

Contributing
------------

1. **Fork** the repository and clone it locally. 
2. **Create a branch** from Bitbar devel branch for your edits.
3. **Commit and push** to your own branch in Github
4. **Open pull request** for your changes for Bitbar devel branch. 

