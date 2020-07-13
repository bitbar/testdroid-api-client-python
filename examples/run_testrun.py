import argparse
import sys
import time
import json

from testdroid import Testdroid
from testdroid import RequestResponseError

parser = argparse.ArgumentParser(description='Run some tests.')
parser.add_argument('--api-key, -a', dest='api_key', required=True, help='Bitbar API key')
parser.add_argument('--dg-id, -d', dest='dg_id', required=True, help='Device group ID')
parser.add_argument('--framework-id, -f', dest='framework_id', required=True, help='Framework ID')
parser.add_argument('--project-name, -p', dest='project_name', required=True, help='Project name')
parser.add_argument('--app-file', dest='app_file', help='App file path')
parser.add_argument('--cloud-url, -c', dest='cloud_url', help='Cloud endpoint')
parser.add_argument('--os-type, -o', dest='os_type', help='OS type')
parser.add_argument('--test-file', dest='test_file', help='Test file path')

args = parser.parse_args()
print("Cloud endpoint: {}".format(args.cloud_url))
print("OS type: {}".format(args.os_type))
print("Framework ID: {}".format(args.framework_id))
print("Project name: {}".format(args.project_name))
print("Device group ID: {}".format(args.dg_id))
print("App file path: {}".format(args.app_file))
print("Test file path: {}".format(args.test_file))

testdroid = Testdroid(apikey=args.api_key, url=args.cloud_url)

###############################
# Login test
###############################
print(testdroid.get_me()['id'])

###############################
# Create, delete and recreate project
###############################
project = testdroid.create_project(args.project_name)
testdroid.delete_project(project['id'])
try:
    delete_project = testdroid.get_project(project['id'])
except RequestResponseError:
    pass
else:
    print("Project delete failed")
    sys.exit(1)

project = testdroid.create_project(args.project_name)
print(project)

###############################
# Upload app and test
###############################
app_file_id = testdroid.upload_file(filename=args.app_file)['id']
test_file_id = testdroid.upload_file(filename=args.test_file)['id']

###############################
# Launch a test run
###############################
run_config = {'osType': args.os_type if args.os_type else "ANDROID",
              'frameworkId': args.framework_id,
              'projectId': project['id'],
              'files': [{'id': app_file_id}, {'id': test_file_id}],
              'deviceGroupId': args.dg_id}
testrun = testdroid.start_test_run_using_config(json.dumps(run_config))
print(testrun)

###############################
# Wait until test run is FINISHED
###############################
while True:
    run_state = testdroid.get_test_run(project['id'], testrun['id'])['state']
    if run_state == "FINISHED":
        break
    print("Test run state: {}".format(run_state))
    time.sleep(5)

###############################
# Download results and delete a project
###############################
testdroid.download_test_run(project['id'], testrun['id'])
testdroid.delete_project(project['id'])
