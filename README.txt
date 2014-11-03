"""
Testdroid Cloud API V2 client

You can use this class as a command line utility or import it to your own code.
There is auto detection for command line execution mode.

Note:
On linux use pip to install requests. Ubuntu 12.04 python-requests package
will not work.

Example:

>>> from testdroid import Testdroid
>>> testdroid = Testdroid(username="admin@localhost", password="admin", url="http://localhost:9080/testdroid-cloud")
>>> testdroid.get_test_run(1233, 12345)
{u'displayName': u'Test Run 1', u'logZipState': u'BLANK', u'screenshotZipState': u'BLANK', u'projectId': 12340, u'number': 1, u'successRatio': 0.814815, u'createTime': 1393595647000, u'executionRatio': 1.0, u'state': u'FINISHED', u'startedByDisplayName': u'John Doe', u'id': 10}

"""