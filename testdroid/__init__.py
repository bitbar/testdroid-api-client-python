# -*- coding: utf-8 -*-

import os, sys, requests, json, logging, time, base64, imghdr

if sys.version_info[0] > 2:
    import http.client
else:
    import httplib
    assert httplib

from optparse import OptionParser
from datetime import datetime

__version__ = '2.43.0'

FORMAT = "%(message)s"
logging.basicConfig(format=FORMAT)

logger = logging.getLogger('testdroid')
logger.setLevel(logging.INFO)


class RequestTimeout(Exception):

    def __init__(self, msg):
        super(Exception, self).__init__(msg)

class ConnectionError(Exception):

    def __init__(self, msg):
        super(Exception, self).__init__(msg)

class RequestResponseError(Exception):

    def __init__(self, msg, status_code):
        super(Exception, self).__init__("Request Error: code %s: %s" % 
                                         (status_code, msg) )
        self.status_code = status_code
    

""" Format unix timestamp to human readable. Automatically detects timestamps with seconds or milliseconds.
"""
def ts_format(timestamp):
    if len(str(timestamp)) > 11:
        return datetime.fromtimestamp(timestamp/1000).strftime('%x %X %z')
    else:
        return datetime.fromtimestamp(timestamp).strftime('%x %X %z')


#
# Inspiration from https://code.google.com/p/corey-projects/source/browse/trunk/python2/progress_bar.py
#
class DownloadProgressBar:
    def __init__(self):
        self.percent_done = 0
        self.started = time.time()
        self.prog_bar = '  []'
        self.fill_char = '#'
        self.width = 40
        self.pos = 0
        self.total = 0
        self.eta = 'N/A'

    def update(self, pos, total):
        self.pos = pos
        self.total = total
        percent_done = int(round(100.0 * pos / total)) if total > 0 else 0

        all_full = self.width - 2
        num_hashes = int(round((percent_done / 100.0) * all_full))
        self.prog_bar = '  [' + self.fill_char * num_hashes + ' ' * (all_full - num_hashes) + ']'
        pct_place = (len(self.prog_bar) // 2) - len(str(percent_done))
        pct_string = '%d%%' % percent_done
        self.duration = int(round(time.time()-self.started))
        self.eta = int(round( self.duration / (percent_done / 100.0)))-self.duration if percent_done > 5 else 'N/A'
        self.prog_bar = self.prog_bar[0:pct_place] + \
                        (pct_string + self.prog_bar[pct_place + len(pct_string):])
        self.prog_bar += '  %s/%s bytes, %ss' % (self.pos, self.total, self.duration)
        if pos < total:
            self.prog_bar += '  (E.T.A.: %ss)' % self.eta
        else:
            self.prog_bar += '                   '
        if sys.platform.lower().startswith('win'):
            print(str(self) + '\r')
        else:
            print(str(self) + chr(27) + '[A')

    def __str__(self):
        return str(self.prog_bar)



class Testdroid:
    # Cloud URL (not including API path)
    url = None
    # Api Key for authentication
    api_key = None
    # Oauth access token
    access_token = None
    # Oauth refresh token
    refresh_token = None
    # Unix timestamp (seconds) when token expires
    token_expiration_time = None
    # Buffer size used for downloads
    download_buffer_size = 65536
    # polling interval when awaiting for test run completion
    polling_interval_mins = 10

    """ Constructor, defaults against cloud.bitbar.com
    """
    def __init__(self, **kwargs):
        self.api_key = kwargs.get('apikey')
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.cloud_url = kwargs.get('url') or "https://cloud.bitbar.com"
        self.download_buffer_size = kwargs.get('download_buffer_size') or 65536

    def set_apikey(self, apikey):
        self.api_key = apikey

    def set_username(self, username):
        self.username = username

    def set_password(self, password):
        self.password = password

    def set_url(self, url):
        self.cloud_url = url

    def set_download_buffer_size(self, download_buffer_size):
        self.download_buffer_size = download_buffer_size

    def set_polling_interval_mins(self, polling_interval_mins):
        self.polling_interval_mins = polling_interval_mins

    """ Get Oauth2 token
    """
    def get_token(self):
        if not self.access_token:
            # TODO: refresh
            url = "%s/oauth/token" % self.cloud_url
            payload = {
                "client_id": "testdroid-cloud-api",
                "grant_type": "password",
                "username": self.username,
                "password": self.password
            }
            res = requests.post(
                url,
                data = payload,
                headers = { "Accept": "application/json" }
                )
            if res.status_code not in list(range(200, 300)):
                raise RequestResponseError(res.text, res.status_code)

            reply = res.json()

            self.access_token = reply['access_token']
            self.refresh_token = reply['refresh_token']
            self.token_expiration_time = time.time() + reply['expires_in']
        elif self.token_expiration_time < time.time():
            url = "%s/oauth/token" % self.cloud_url
            payload = {
                "client_id": "testdroid-cloud-api",
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token
            }
            res = requests.post(
                url,
                data = payload,
                headers = { "Accept": "application/json" }
                )
            if res.status_code not in list(range(200, 300)):
                print("FAILED: Unable to get a new access token using refresh token")
                self.access_token = None
                return self.get_token()

            reply = res.json()

            self.access_token = reply['access_token']
            self.refresh_token = reply['refresh_token']
            self.token_expiration_time = time.time() + reply['expires_in']

        return self.access_token

    """ Helper method for getting necessary headers to use for API calls, including authentication
    """
    def _build_headers(self):
        if self.api_key:
            apikey = {'Authorization' : 'Basic %s' % base64.b64encode((self.api_key+":").encode(encoding='utf_8')).decode(), 'Accept' : 'application/json' }
            return apikey
        else:
            return { 'Authorization': 'Bearer %s' % self.get_token(), 'Accept': 'application/json' }

    """ Download file from API resource
    """
    def download(self, path=None, filename=None, payload={}, callback=None):
        url = "%s/api/v2/%s" % (self.cloud_url, path)
        try:
            res = requests.get(url, params=payload, headers=self._build_headers(), stream=True, timeout=(60.0))

            if res.status_code in range(200, 300):
                logger.info("Downloading %s (%s bytes)" % (filename, res.headers["Content-Length"]))
                pos = 0
                total = res.headers['content-length']

                # Check if the system is Windows or not.
                if os.name == 'nt':
                    fd = os.open(filename, os.O_RDWR|os.O_CREAT|os.O_BINARY)
                else:
                    fd = os.open(filename, os.O_RDWR|os.O_CREAT)

                for chunk in res.iter_content(self.download_buffer_size):
                    os.write(fd, chunk)
                    if callback:
                        pos += len(chunk)
                        callback(pos, total)
                        time.sleep(0.1)
                os.close(fd)
            else:
                raise RequestResponseError(res.text, res.status_code)

            res.close()
        except requests.exceptions.Timeout:
            logger.info("")
            logger.info("Download has failed. Please try to restart your download")
            raise RequestTimeout("Download has failed. Please try to restart your download")
        except requests.exceptions.ConnectionError:
            logger.info("")
            logger.info("Download has failed. Please try to restart your download")
            raise ConnectionError("Download has failed. Please try to restart your download")


    """ Upload file to API resource
    """
    def upload(self, path=None, filename=None):
        # TOOD: where's the error handling?
        with open(filename, 'rb') as f:
            url = "%s/api/v2/%s" % (self.cloud_url, path)
            files = {'file': f}
            res = requests.post(url, files=files, headers=self._build_headers())
            if res.status_code not in list(range(200, 300)):
                raise RequestResponseError(res.text, res.status_code)
            return res

    """ GET from API resource
    """
    def get(self, path=None, payload={}, headers={}):
        if path.find('v2/') >= 0:
            cut_path = path.split('v2/')
            path = cut_path[1]

        url = "%s/api/v2/%s" % (self.cloud_url, path)
        headers = dict(list(self._build_headers().items()) + list(headers.items()))
        res =  requests.get(url, params=payload, headers=headers)
        if res.status_code not in list(range(200, 300)):
            raise RequestResponseError(res.text, res.status_code)
        logger.debug(res.text)
        if headers['Accept'] == 'application/json':
            return res.json()
        else:
            return res.text

    """ POST against API resources
    """
    def post(self, path=None, payload=None, headers={}):
        headers = dict(list(self._build_headers().items()) + list(headers.items()))
        url = "%s/api/v2/%s" % (self.cloud_url, path)
        res = requests.post(url, payload, headers=headers)
        if res.status_code not in list(range(200, 300)):
            raise RequestResponseError(res.text, res.status_code)
        return res.json()

    """ DELETE API resource
    """
    def delete(self, path=None, payload=None, headers={}):
        headers = dict(list(self._build_headers().items()) + list(headers.items()))
        url = "%s/api/v2/%s" % (self.cloud_url, path)
        res = requests.delete(url, headers=headers)
        if res.status_code not in list(range(200, 300)):
            raise RequestResponseError(res.text, res.status_code)
        return res

    """ Returns user details
    """
    def get_me(self):
        return self.get("me")

    """ Returns list of device groups
    """
    def get_device_groups(self, limit=0):
        return self.get("me/device-groups", payload = {'limit': limit})

    """ Returns list of frameworks
    """
    def get_frameworks(self, limit=0):
        return self.get("me/available-frameworks", payload = {'limit': limit})

    """ Returns list of devices
    """
    def get_devices(self, limit=0):
        return self.get(path = "devices", payload = {'limit': limit})


    """ Print input files
    """
    def print_input_files(self, limit=0):
        for input_file in self.get_input_files(limit)['data']:
            print("id:{} name:{} size:{} type:{}".format(input_file['id'],input_file['name'],input_file['size'],input_file['inputType']))

    """ Print device groups
    """
    def print_device_groups(self, limit=0):
        for device_group in self.get_device_groups(limit)['data']:
            print("%s %s %s %s devices" % (str(device_group['id']).ljust(12), device_group['displayName'].ljust(30), device_group['osType'].ljust(10), device_group['deviceCount']))

    """ Print available free Android devices
    """
    def print_available_free_android_devices(self, limit=0):
        print("")
        print("Available Free Android Devices")
        print("------------------------------")

        for device in self.get_devices(limit)['data']:
            if device['creditsPrice'] == 0 and device['locked'] == False and device['osType'] == "ANDROID":
                    print(device['displayName'])
        print("")
    
    """ Print available frameworks
    """
    def print_available_frameworks(self, os_type=None, limit=0):
        print("")
        print("Available frameworks")
        print("------------------------------")
        for framework in self.get_frameworks(limit)['data']:
            print("id: {}\tosType:{}\tname:{}".format(framework['id'], framework['osType'], framework['name']))
        print("")


    """ Print available free iOS devices
    """
    def print_available_free_ios_devices(self, limit=0):
        print("")
        print("Available Free iOS Devices")
        print("--------------------------")

        for device in self.get_devices(limit)['data']:
            if device['creditsPrice'] == 0 and device['locked'] == False and device['osType'] == "IOS":
                print(device['displayName'])

        print("")

    """ Print available free devices
    """
    def print_available_free_devices(self, limit=0):
        self.print_available_free_android_devices(limit)
        self.print_available_free_ios_devices(limit)


    """ Create a project
    """
    def create_project(self, project_name, project_type):
        project = self.post(path="me/projects", payload={"name": project_name, "type": project_type})
        print(project)

        logger.info("Project %s: %s (%s) created" % (project['id'], project['name'], project['type'] ))
        return project

    """ Delete a project
    """
    def delete_project(self, project_id):
        project = self.get_project(project_id)
        if project:
            self.delete("me/projects/%s" % project_id)

    """ Returns projects for user
    """
    def get_projects(self, limit=0):
        return self.get(path="me/projects", payload = {'limit': limit})

    """ Returns a single project
    """
    def get_project(self, project_id):
        return self.get("me/projects/%s" % project_id)

    """ Print projects
    """
    def print_projects(self, limit=0):
        me = self.get_me()
        print("Projects for %s <%s>:" % (me['name'], me['email']))
        
        for project in self.get_projects(limit)['data']:
            print("%s %s \"%s\"" % (str(project['id']).ljust(10), project['type'].ljust(15), project['name']))

    """ Upload application file to project
    """
    def upload_application_file(self, project_id, filename):
        me = self.get_me()
        path = "users/%s/projects/%s/files/application" % (me['id'], project_id)
        self.upload(path=path, filename=filename)

    """ Upload test file to project
    """
    def upload_test_file(self, project_id, filename):
        me = self.get_me()
        path = "users/%s/projects/%s/files/test" % (me['id'], project_id)
        self.upload(path=path, filename=filename)

    """ Delete project parameter
    """
    def delete_project_parameters(self, project_id, parameter_id):
        me = self.get_me()
        path = "/users/%s/projects/%s/config/parameters/%s" % ( me['id'], project_id, parameter_id )
        return self.delete(path=path)

    """ Get project parameters
    """
    def get_project_parameters(self, project_id):
        path = "me/projects/%s/config/parameters" % ( project_id )
        return self.get(path=path)

    """ Upload additional data file to project
    """
    def upload_data_file(self, project_id, filename):
        me = self.get_me()
        path = "users/%s/projects/%s/files/data" % (me['id'], project_id)
        self.upload(path=path, filename=filename)

    """ Set project parameters
    """
    def set_project_parameters(self, project_id, parameters):
        #set key value pair for project. e.g. : {'key' : 'my_key', 'value':'my_value'}
        me = self.get_me()
        path = "/users/%s/projects/%s/config/parameters" % ( me['id'], project_id )
        return self.post(path=path, payload=parameters)

    """ Get project config
    """
    def get_project_config(self, project_id):
        path = "me/projects/%s/config" % ( project_id )
        return self.get(path=path)

    """ Set project config according to http://docs.testdroid.com/_pages/client.html#project-config
    """
    def set_project_config(self, project_id, payload):
        #set the project config to reflect the given json payload
        #e.g.: {'usedDeviceGroupId': 1234}
        if isinstance(payload, str):
            payload=json.loads(payload)
        me = self.get_me()
        path = "/users/%s/projects/%s/config" % ( me['id'], project_id )
        return self.post(path=path, payload=payload)

    """Set project framework based on a framework integer id
    """
    def set_project_framework(self, project_id, frameworkId):
        path = "projects/%(project_id)s/frameworks" % {
            'project_id': project_id
        }
        self.post(path, payload={"frameworkId": frameworkId})


    """ Start a test run using test run config
        e.g '{"frameworkId":12252, 
        "osType": "ANDROID", 
        "projectId":1234, 
        "files":[{"id":9876}, {"id":5432}]
        "testRunParameters":[{"key":"xyz", "value":"abc"}],
        "deviceGroupId":6854
        }'
        client.start_test_run_using_config(json.dumps({"frameworkId":123213}))
    """
    def start_test_run_using_config(self, test_run_config={}):

        me = self.get_me()
        path = "users/%s/runs" % (me['id'])
        test_run = self.post(path=path, payload=test_run_config, headers={'Content-type': 'application/json', 'Accept': 'application/json'})
        return test_run

    """ Start a test run on a device group
    """
    def start_test_run(self, project_id, device_group_id=None, device_model_ids=None, name=None, additional_params={}):
        # check project validity
        project = self.get_project(project_id)
        if not 'id' in project:
            print("Project %s not found" % project_id)
            sys.exit(1)

        # start populating parameters for the request payload...
        payload={}

        if name is not None:
            payload['name'] = name

        if device_group_id is not None:
            payload['usedDeviceGroupId'] = device_group_id
            print("Starting test run on project %s \"%s\" using device group %s" % (project['id'], project['name'], device_group_id))
        elif device_model_ids is not None:
            payload['usedDeviceIds[]'] = device_model_ids
            print("Starting test run on project %s \"%s\" using device models ids %s" % (project['id'], project['name'], device_model_ids))
        else:
            print("Either device group or device models must be defined")
            sys.exit(1)

        # add optional request params that the user might have specified
        payload.update(additional_params)

        # actually start the test run
        me = self.get_me()
        path = "/users/%s/projects/%s/runs" % (me['id'], project_id)
        test_run = self.post(path=path, payload=payload)
        print("Test run id: %s" % test_run['id'])
        print("Name: %s" % test_run['displayName'])
        return test_run['id']


    """ Start a test run on a device group and wait for completion
    """
    def start_wait_test_run(self, project_id, device_group_id=None, device_model_ids=None):
        test_run_id = self.start_test_run(project_id, device_group_id, device_model_ids)
        self.wait_test_run(project_id, test_run_id)
        return test_run_id


    """ Start a test run on a device group, wait for completion and download results
    """
    def start_wait_download_test_run(self, project_id, device_group_id=None, device_model_ids=None):
        test_run_id = self.start_wait_test_run(project_id, device_group_id, device_model_ids)
        self.download_test_run(project_id, test_run_id)

    """ Awaits completion of the given test run
    """
    def wait_test_run(self, project_id, test_run_id):
        if test_run_id:
            print("Awaiting completion of test run with id {}. Will wait forever polling every {}.".format(
                test_run_id,
                '{} minutes'.format(self.polling_interval_mins) if self.polling_interval_mins != 1 else 'minute'))

            while True:
                time.sleep(self.polling_interval_mins * 60)
                if not self.api_key:
                    self.access_token = None    #WORKAROUND: access token thinks it's still valid,
                                                # > token valid for another 633.357925177
                                                #whilst this happens:
                                                # > Couldn't establish the state of the test run with id: 72593732. Aborting
                                                # > {u'error_description': u'Invalid access token: b3e62604-9d2a-49dc-88f5-89786ff5a6b6', u'error': u'invalid_token'}

                    self.get_token()            #in case it expired
                testRunStatus = self.get_test_run(project_id, test_run_id)
                if testRunStatus and 'state' in testRunStatus:
                    if testRunStatus['state'] == "FINISHED":
                        print("The test run with id: %s has FINISHED" % test_run_id)
                        break
                    elif testRunStatus['state'] == "WAITING":
                        print("[%s] The test run with id: %s is awaiting to be scheduled" % (time.strftime("%H:%M:%S"), test_run_id))
                        continue
                    elif testRunStatus['state'] == "RUNNING":
                        print("[%s] The test run with id: %s is running" % (time.strftime("%H:%M:%S"), test_run_id))
                        continue

                print("Couldn't establish the state of the test run with id: %s. Aborting" % test_run_id)
                print(testRunStatus)
                sys.exit(1)


    """ Start device sessions
    """
    def start_device_session(self, device_model_id):
        payload={'deviceModelId':device_model_id}
        return self.post("me/device-sessions", payload)

    """ Stop device session
    """
    def stop_device_session(self, device_session_id):
        return self.post("me/device-sessions/%s/release" % (device_session_id))

    """ Get all test runs for a project
    """
    def get_project_test_runs(self, project_id, limit=0):
        return self.get(path = "me/projects/%s/runs" % (project_id), payload = {'limit': limit})

    """ Print test runs of a project to console
    """
    def print_project_test_runs(self, project_id, limit=0):
        test_runs = self.get_project_test_runs(project_id, limit)['data']
        for test_run in test_runs:
            print("%s %s  %s %s" % (str(test_run['id']).ljust(10), ts_format(test_run['createTime']), test_run['displayName'].ljust(30), test_run['state']))

    """ Get a single test run
    """
    def get_test_run(self, project_id, test_run_id):
        return self.get("me/projects/%s/runs/%s" % (project_id, test_run_id))

    """ Re-run an already-existing test run. Specify individual device run IDs to only re-run those devices.
    """
    def retry_test_run(self, project_id, test_run_id, device_run_ids=[]):
        endpoint = "me/projects/%s/runs/%s/retry" % (project_id, test_run_id)
        if device_run_ids:
            endpoint += "?deviceRunIds[]=" + "&deviceRunIds[]=".join(str(device_id) for device_id in device_run_ids)
        return self.post(endpoint)

    """Abort a test run
    """
    def abort_test_run(self, project_id, test_run_id):
        return self.post("me/projects/%s/runs/%s/abort" % (project_id, test_run_id))

    """ Return device runs for a project
    """
    def get_device_runs(self, project_id, test_run_id, limit=0):
        return self.get(path = "me/projects/%s/runs/%s/device-runs" % (project_id, test_run_id), payload = {'limit': limit})

    """ Downloads screenshots list for a device run
    """
    def get_device_run_screenshots_list(self, project_id, test_run_id, device_run_id, limit=0):
        return self.get("me/projects/%s/runs/%s/device-runs/%s/screenshots" % (project_id, test_run_id, device_run_id), payload = {'limit': limit})

    """ Get list of files for device run
    """
    def get_device_run_files(self, project_id, test_run_id, device_session_id, tags=None):
        if tags is None:
            return self.get("me/projects/%s/runs/%s/device-sessions/%s/output-file-set/files" % (project_id, test_run_id, device_session_id))
        else:
            return self.get("me/projects/%s/runs/%s/device-sessions/%s/output-file-set/files?tag[]=%s" % (project_id, test_run_id, device_session_id, tags))

    """ Get list of input files 
    """
    def get_input_files(self, limit=0):
        return self.get("me/files?limit={}&filter=s_direction_eq_INPUT".format(limit))

    """ Downloads test run files to a directory hierarchy
    """
    def download_test_run(self, project_id, test_run_id):
        test_run = self.get_test_run(project_id, test_run_id)
        device_runs = self.get_device_runs(project_id, test_run_id)

        logger.info("")
        logger.info("Test run %s: \"%s\" has %s device runs:" % (test_run['id'], test_run['displayName'], len(device_runs['data'])))

        for device_run in device_runs['data']:
            state = device_run['state']
            logger.info("")
            logger.info("%s \"%s\" %s" % (device_run['id'], device_run['device']['displayName'], state))

            if state in ("ABORTED", "TIMEOUT", "WARNING", "SUCCEEDED", "FAILED", "EXCLUDED"):
                directory = "%s-%s/%d-%s" % (test_run_id, test_run['displayName'], device_run['id'], device_run['device']['displayName'])
                session_id = device_run['id']
                files = self.get_device_run_files(project_id, test_run_id, session_id)
                for file in files['data']:
                    if file['state'] == "READY":
                        full_path = "%s/%s" % (directory, file['name'])
                        if not os.path.exists(directory):
                            os.makedirs(directory)

                        url = "me/files/%s/file" % (file['id'])
                        prog = DownloadProgressBar()
                        self.download(url, full_path, callback=lambda pos, total: prog.update(int(pos), int(total)))
                        print("")
                    else:
                        logger.info("File %s is not ready" % file['name'])
                if( len(files['data']) == 0 ):
                    logger.info("No files to download")
                    logger.info("")
            else:
                logger.info("Device run is not ended - Skipping file downloads")
                logger.info("")

    """ Downloads test run screenshots
    """
    def download_test_screenshots(self, project_id, test_run_id):
        test_run = self.get_test_run(project_id, test_run_id)
        device_runs = self.get_device_runs(project_id, test_run_id)
        logger.info("Test run %s: \"%s\" has %s device runs:" % (test_run['id'], test_run['displayName'], len(device_runs['data'])))
        for device_run in device_runs['data']:
            logger.info("%s \"%s\" %s" % (device_run['id'], device_run['device']['displayName'], device_run['state']))

        logger.info("");
        for device_run in device_runs['data']:
            if device_run['state'] in ["SUCCEEDED", "FAILED", "ABORTED", "WARNING", "TIMEOUT"]:
                directory = "%s-%s/%d-%s/screenshots" % (test_run['id'], test_run['displayName'], device_run['id'], device_run['device']['displayName'])
                screenshots = self.get_device_run_screenshots_list(project_id, test_run_id, device_run['id'])
                no_screenshots = True

                for screenshot in screenshots['data']:
                    no_screenshots = False
                    full_path = "%s/%s" % (directory, screenshot['originalName'])
                    if not os.path.exists(directory):
                        os.makedirs(directory)

                    if not os.path.exists(full_path):
                        url = "me/projects/%s/runs/%s/device-runs/%s/screenshots/%s" % (project_id, test_run['id'], device_run['id'], screenshot['id'])
                        prog = DownloadProgressBar()
                        self.download(url, full_path, callback=lambda pos, total: prog.update(int(pos), int(total)))
                        print("")
                    else:
                        ''' Earlier downloaded images are checked, and if needed re-downloaded.
                        '''
                        try:
                            if imghdr.what(full_path) in ['jpeg', 'png']:
                                logger.info("Screenshot %s already exists - skipping download" % full_path)
                            else:
                                raise
                        except:
                            url = "me/projects/%s/runs/%s/device-runs/%s/screenshots/%s" % (project_id, test_run['id'], device_run['id'], screenshot['id'])
                            prog = DownloadProgressBar()
                            self.download(url, full_path, callback=lambda pos, total: prog.update(int(pos), int(total)))
                            print("")

                if no_screenshots:
                    logger.info("Device %s has no screenshots - skipping" % device_run['device']['displayName'])
            else:
                logger.info("Device %s has errored or has not finished - skipping" % device_run['device']['displayName'])

    def get_parser(self):
        class MyParser(OptionParser):
            def format_epilog(self, formatter):
                return self.epilog
        usage = "usage: %prog [options] <command> [arguments...]"
        description = "Client for Testdroid Cloud API v2"
        epilog = """
Commands:

    me                                          Get user details
    available-free-devices                      Print list of currently available free devices
    device-groups                               Get list of your device groups
    create-project <name> <type>                Create a project
                                                Type is one of:
                                                        ANDROID
                                                        IOS
                                                        UIAUTOMATOR
                                                        APPIUM_ANDROID
                                                        APPIUM_IOS
                                                        CALABASH
                                                        CALABASH_IOS
    delete-project <id>                         Delete a project
    projects                                    Get projects
    upload-application <project-id> <filename>  Upload application to project
    upload-test <project-id> <filename>         Upload test file to project
    upload-data <project-id> <filename>         Upload additional data file to project
    set-project-config <project-id> <config-json>
                                                Change the project config parameters as facilitated by the API:
                                                http://docs.testdroid.com/_pages/client.html#project-config
                                                e.g.:
                                                ./testdroid-api-client set-project-config 1234 '{"limitationType":"CLASS", "limitationValue":"com.foo.test.VerifyFoo"}'
    start-test-run <project-id> <device-group-id> Start a test run
    start-wait-download-test-run <project-id> <device-group-id>
                                                Start a test run, await completion (polling) and
                                                download results
    wait-test-run <project-id> <test-run-id>    Await completion (polling) of the test run
    test-runs <project-id>                      Get test runs for a project
    test-run <project-id> <test-run-id>         Get test run details
    device-runs <project-id> <test-run-id>      Get device runs for a test run
    download-test-run <project-id> <test-run-id>
                                                Download test run data. Data will be downloaded to
                                                current directory in a structure:
                                                [test-run-id]/[device-run-id]-[device-name]/files...
    download-test-screenshots <project-id> <test-run-id>
                                                Download test run screenshots. Screenshots will be downloaded to
                                                current directory in a structure:
                                                [test-run-id]/[device-run-id]-[device-name]/screenshots/...

"""
        parser = MyParser(usage=usage, description=description, epilog=epilog,  version="%s %s" % ("%prog", __version__))
        parser.add_option("-k", "--apikey", dest="apikey",
                          help="API key - the API key for Testdroid Cloud. Optional. You can use environment variable TESTDROID_APIKEY as well.")
        parser.add_option("-u", "--username", dest="username",
                          help="Username - the email address. Optional. You can use environment variable TESTDROID_USERNAME as well.")
        parser.add_option("-p", "--password", dest="password",
                          help="Password. Required if username is used. You can use environment variable TESTDROID_PASSWORD as well.")
        parser.add_option("-c", "--url", dest="url", default="https://cloud.bitbar.com",
                          help="Cloud endpoint. Default is https://cloud.bitbar.com. You can use environment variable TESTDROID_URL as well.")
        parser.add_option("-i", "--interval", dest="interval",
                          help="How frequently the status of a test run should be checked (in minutes). Can be used with the command wait-test-run.")
        parser.add_option("-q", "--quiet", action="store_true", dest="quiet",
                          help="Quiet mode")
        parser.add_option("-d", "--debug", action="store_true", dest="debug",
                          help="Turn on debug level logging")
        return parser

    def get_commands(self):
        commands = {
            "me": self.get_me,
            "device-groups": self.print_device_groups,
            "available-free-devices": self.print_available_free_devices,
            "available-frameworks": self.print_available_frameworks,
            "projects": self.print_projects,
            "create-project": self.create_project,
            "delete-project": self.delete_project,
            "upload-application": self.upload_application_file,
            "upload-test": self.upload_test_file,
            "upload-data": self.upload_data_file,
            "set-project-config": self.set_project_config,
            "start-test-run": self.start_test_run,
            "start-test-run-using-config": self.start_test_run_using_config,
            "start-wait-download-test-run":self.start_wait_download_test_run,
            "wait-test-run":self.wait_test_run,
            "test-run": self.get_test_run,
            "test-runs": self.print_project_test_runs,
            "device-runs": self.get_device_runs,
            "device-run-files": self.get_device_run_files,
            "list-input-files": self.print_input_files,
            "download-test-run": self.download_test_run,
            "download-test-screenshots": self.download_test_screenshots
        }
        return commands

    def cli(self, parser, commands):
        (options, args) = parser.parse_args()

        if len(args) < 1:
            parser.print_help()
            sys.exit(1)

        if options.debug:
            logger.setLevel(logging.DEBUG)
            if sys.version_info[0] > 2:
                http.client.HTTPConnection.debuglevel = 1
            else:
                httplib.HTTPConnection.debuglevel = 1   
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

        if options.quiet:
            logger.setLevel(logging.WARNING)

        username = options.username or os.environ.get('TESTDROID_USERNAME')
        password = options.password or os.environ.get('TESTDROID_PASSWORD')
        apikey = options.apikey or os.environ.get('TESTDROID_APIKEY')
        url = os.environ.get('TESTDROID_URL') or options.url
        polling_interval_mins = 10

        try:
            polling_interval_mins = max(int(options.interval), 1)
        except:
            polling_interval_mins = 10

        self.set_username(username)
        self.set_password(password)
        self.set_apikey(apikey)
        self.set_url(url)
        self.set_polling_interval_mins(polling_interval_mins)

        command = commands[args[0]]
        if not command:
            parser.print_help()
            sys.exit(1)

        print(command(*args[1:]) or "")
        #print json.dumps(result, default=lambda o: o.__dict__, sort_keys=True, indent=4)


def main():
    testdroid = Testdroid()
    parser = testdroid.get_parser()
    commands = testdroid.get_commands()
    testdroid.cli(parser, commands)

if __name__ == '__main__':
    main()

