Python client for Testdroid Cloud APIv2
=======================================

Command line
-----

Install it with:
`sudo pip install testdroid`

Usage
-----

`testdroid --help`

Note that you can set `TESTDROID_USERNAME`, `TESTDROID_PASSWORD` and `TESTDROID_URL` environment variables.


Module
-----

You can use this class as a command line utility or import it to your own code.

Example:

```python
>>> from testdroid import Testdroid
>>> testdroid = Testdroid(username="admin@localhost", password="admin", url="http://localhost:9080/testdroid-cloud")
>>> testdroid.get_test_run(1233, 12345)
{u'displayName': u'Test Run 1', u'logZipState': u'BLANK', u'screenshotZipState': u'BLANK', u'projectId': 12340, u'number': 1, u'successRatio': 0.814815, u'createTime': 1393595647000, u'executionRatio': 1.0, u'state': u'FINISHED', u'startedByDisplayName': u'John Doe', u'id': 10} 
```

Developing and testing
----------------------

Set up sandbox

`virtualenv myenv && source myenv/bin/activate`

Build example

`python setup.py clean && python setup.py sdist && pip install -U dist/testdroid-0.1.2dev.tar.gz && bin/testdroid-api-client me`

