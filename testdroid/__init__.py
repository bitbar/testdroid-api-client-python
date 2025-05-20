# -*- coding: utf-8 -*-

import os
import sys
import requests
import logging
import time
import base64
import imghdr

if sys.version_info[0] > 2:
    import http.client
else:
    import httplib

    assert httplib

from optparse import OptionParser
from datetime import datetime

__version__ = '3.1'

FORMAT = "%(message)s"
logging.basicConfig(format=FORMAT)

logger = logging.getLogger('testdroid')
logger.setLevel(logging.INFO)


class RequestTimeout(Exception):

    def __init__(self, msg):
        super(Exception, self).__init__(msg)


class CloudConnectionError(Exception):

    def __init__(self, msg):
        super(Exception, self).__init__(msg)


class RequestResponseError(Exception):

    def __init__(self, msg, status_code):
        super(Exception, self).__init__("Request Error: code %s: %s" % (status_code, msg))
        self.status_code = status_code


class APIException(Exception):

    def __init__(self, msg, status_code):
        super(Exception, self).__init__("APIException: code %s: %s" % (status_code, msg))
        self.status_code = status_code


def ts_format(timestamp):
    """ Format unix timestamp to human readable. Automatically detects timestamps with seconds or milliseconds. """

    if len(str(timestamp)) > 11:
        return datetime.fromtimestamp(timestamp / 1000).strftime('%x %X %z')
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
        self.duration = None

    def update(self, pos, total):
        self.pos = pos
        self.total = total
        percent_done = int(round(100.0 * pos / total)) if total > 0 else 0

        all_full = self.width - 2
        num_hashes = int(round((percent_done / 100.0) * all_full))
        self.prog_bar = '  [' + self.fill_char * num_hashes + ' ' * (all_full - num_hashes) + ']'
        pct_place = (len(self.prog_bar) // 2) - len(str(percent_done))
        pct_string = '%d%%' % percent_done
        self.duration = int(round(time.time() - self.started))
        self.eta = int(round(self.duration / (percent_done / 100.0))) - self.duration if percent_done > 5 else 'N/A'
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
    # Buffer size used for downloads
    download_buffer_size = 65536
    # polling interval when awaiting for test run completion
    polling_interval_mins = 10
    # Set of statuses allowing use of file
    __accepted_virus_scan_statuses = {'safe', 'disabled', None}

    def __init__(self, **kwargs):
        """ Constructor, defaults against cloud.bitbar.com """

        self.api_key = kwargs.get('apikey')
        self.cloud_url = kwargs.get('url') or "https://cloud.bitbar.com"
        self.download_buffer_size = kwargs.get('download_buffer_size') or 65536

    def set_apikey(self, apikey):
        self.api_key = apikey

    def set_url(self, url):
        self.cloud_url = url

    def set_download_buffer_size(self, download_buffer_size):
        self.download_buffer_size = download_buffer_size

    def set_polling_interval_mins(self, polling_interval_mins):
        self.polling_interval_mins = polling_interval_mins

    def __build_headers(self):
        """ Helper method for getting necessary headers to use for API calls, including authentication """

        if self.api_key:
            apikey = {'Authorization': 'Basic %s' % base64.b64encode((self.api_key + ":")
                                                                     .encode(encoding='utf_8')).decode(),
                      'Accept': 'application/json',
                      'User-Agent': 'Bitbar Cloud API Client for Python v%s' % __version__}
            return apikey
        else:
            return {'Accept': 'application/json'}

    def download(self, path=None, filename=None, payload=None, callback=None):
        """ Download file from API resource """

        if payload is None:
            payload = {}
        url = "%s/api/v2/%s" % (self.cloud_url, path)
        try:
            res = requests.get(url, params=payload, headers=self.__build_headers(), stream=True, timeout=60.0)

            if res.status_code in range(200, 300):
                try:
                    total = res.headers['Content-length']
                    logger.info("Downloading %s (%s bytes)" % (filename, total))
                except KeyError as e:
                    callback = None

                pos = 0

                # Check if the system is Windows or not.
                if os.name == 'nt':
                    fd = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_BINARY)
                else:
                    fd = os.open(filename, os.O_RDWR | os.O_CREAT)

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
            raise CloudConnectionError("Download has failed. Please try to restart your download")

    def upload(self, path=None, filename=None):
        """ Upload file to API resource """

        # TODO: where's the error handling?
        with open(filename, 'rb') as f:
            url = "%s/api/v2/%s" % (self.cloud_url, path)
            files = {'file': f}
            res = requests.post(url, files=files, headers=self.__build_headers())
            if res.status_code not in list(range(200, 300)):
                raise RequestResponseError(res.text, res.status_code)
            return res.json()

    def get(self, path, payload=None, headers=None):
        """ GET from API resource """

        if payload is None:
            payload = {}
        if path.find('v2/') >= 0:
            cut_path = path.split('v2/')
            path = cut_path[1]

        (url, headers) = self.__get_request_params(path, headers)
        res = requests.get(url, params=payload, headers=headers, timeout=60.0)
        if res.status_code not in list(range(200, 300)):
            raise RequestResponseError(res.text, res.status_code)
        logger.debug(res.text)
        if headers.get('Accept') == 'application/json':
            return res.json()
        else:
            return res.text

    def post(self, path=None, payload=None, headers=None):
        """ POST against API resources """

        (url, headers) = self.__get_request_params(path, headers)
        res = requests.post(url, payload, headers=headers)
        if res.status_code not in list(range(200, 300)):
            raise RequestResponseError(res.text, res.status_code)
        return res.json()

    def delete(self, path=None, headers=None):
        """ DELETE API resource """

        (url, headers) = self.__get_request_params(path, headers)
        res = requests.delete(url, headers=headers)
        if res.status_code not in list(range(200, 300)):
            raise RequestResponseError(res.text, res.status_code)
        return res

    def __get_request_params(self, path, headers):
        if headers is None:
            headers = {}
        return ("%s/api/v2/%s" % (self.cloud_url, path),
                dict(list(self.__build_headers().items()) + list(headers.items())))

    def get_me(self):
        """ Returns user details """

        return self.get("me")

    def get_device_groups(self, limit=0):
        """ Returns list of device groups """

        return self.get("me/device-groups", payload={'limit': limit})

    def get_devices_from_group(self, device_group_id, limit=0):
        """ Returns list of devices from device group """

        me = self.get_me()
        path = "users/%s/device-groups/%s/devices" % (me['id'], device_group_id)
        return self.get(path, payload={'limit': limit})

    def get_frameworks(self, limit=0):
        """ Returns list of frameworks """

        return self.get("me/available-frameworks", payload={'limit': limit})

    def get_devices(self, limit=0):
        """ Returns list of devices """

        return self.get(path="devices", payload={'limit': limit})

    def print_input_files(self, limit=0):
        """ Print input files """

        for input_file in self.get_input_files(limit)['data']:
            print("id:{} name:{} size:{} type:{}".format(
                input_file['id'], input_file['name'], input_file['size'], input_file['inputType']))

    def print_device_groups(self, limit=0):
        """ Print device groups """

        for device_group in self.get_device_groups(limit)['data']:
            print("%s %s %s %s devices" %
                  (str(device_group['id']).ljust(12), device_group['displayName'].ljust(30),
                   device_group['osType'].ljust(10), device_group['deviceCount']))

    def print_available_free_android_devices(self, limit=0):
        """ Print available free Android devices """

        print("")
        print("Available Free Android Devices")
        print("------------------------------")

        for device in self.get_devices(limit)['data']:
            if device['creditsPrice'] == 0 and not device['locked'] and device['osType'] == "ANDROID":
                print(device['displayName'])
        print("")

    def print_available_frameworks(self, limit=0):
        """ Print available frameworks """

        print("")
        print("Available frameworks")
        print("------------------------------")
        for framework in self.get_frameworks(limit)['data']:
            print("id: {}\tosType:{}\tname:{}".format(framework['id'], framework['osType'], framework['name']))
        print("")

    def print_available_free_ios_devices(self, limit=0):
        """ Print available free iOS devices """

        print("")
        print("Available Free iOS Devices")
        print("--------------------------")

        for device in self.get_devices(limit)['data']:
            if device['creditsPrice'] == 0 and not device['locked'] and device['osType'] == "IOS":
                print(device['displayName'])

        print("")

    def print_available_free_devices(self, limit=0):
        """ Print available free devices """

        self.print_available_free_android_devices(limit)
        self.print_available_free_ios_devices(limit)

    def create_project(self, project_name, project_type=None):
        """ Create a project """
        if project_type:
            print("Project type is deprecated and not used anymore")
        project = self.post(path="me/projects", payload={"name": project_name})

        logger.info("Project %s: %s created" % (project['id'], project['name']))
        return project

    def delete_project(self, project_id):
        """ Delete a project """

        project = self.get_project(project_id)
        if project:
            self.delete("me/projects/%s" % project_id)

    def get_projects(self, limit=0):
        """ Returns projects for user """

        return self.get(path="me/projects", payload={'limit': limit})

    def get_project(self, project_id):
        """ Returns a single project """

        return self.get("me/projects/%s" % project_id)

    def print_projects(self, limit=0):
        """ Print projects """

        me = self.get_me()
        print("Projects for %s %s <%s>:" % (me['firstName'], me['lastName'], me['email']))

        for project in self.get_projects(limit)['data']:
            print("%s \"%s\"" % (str(project['id']).ljust(10), project['name']))

    def get_file(self, file_id):
        """ Get file """

        return self.get("me/files/%s" % file_id)

    def upload_file(self, filename, timeout=300, skip_scan_wait=False):
        """ Upload application file to project """

        me = self.get_me()
        path = "users/%s/files" % (me['id'])
        file = self.upload(path=path, filename=filename)
        if not skip_scan_wait:
            self.wait_for_virus_scan([file], timeout)
        return file

    def wait_for_virus_scan(self, api_files, timeout=300):
        """ Wait for virus scan of all files in a collection """

        loop_end = time.time() + timeout
        while time.time() < loop_end:
            statuses = set()
            for file in api_files:
                current_status = self.__get_virus_scan_status(file)
                if current_status in self.__accepted_virus_scan_statuses:
                    statuses.add(current_status)
                else:  # get status after refreshing
                    statuses.add(self.__get_virus_scan_status(self.get_file(file['id'])))
            if 'infected' in statuses:
                raise APIException(400, 'File rejected by virus scan')
            if self.__accepted_virus_scan_statuses.issuperset(statuses):
                return
            time.sleep(1)
        raise APIException(408, 'Waiting for virus scan timed out')

    @staticmethod
    def __get_virus_scan_status(api_file):
        return next((p['value'] for p in api_file['fileProperties'] if p['key'] == 'virus_scan_status'), None)

    def validate_test_run_config(self, test_run_config):
        """ Get test run config """

        path = "me/runs/config"
        return self.post(path=path, payload=test_run_config, headers={'Content-type': 'application/json',
                                                                      'Accept': 'application/json'})

    def start_test_run_using_config(self, test_run_config):
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

        me = self.get_me()
        path = "users/%s/runs" % (me['id'])
        test_run = self.post(path=path, payload=test_run_config, headers={'Content-type': 'application/json',
                                                                          'Accept': 'application/json'})
        return test_run

    def start_wait_test_run(self, test_run_config):
        """ Start a test run on a device group and wait for completion """

        test_run = self.start_test_run_using_config(test_run_config)
        self.wait_test_run(test_run['projectId'], test_run['id'])
        return test_run

    def start_wait_download_test_run(self, test_run_config):
        """ Start a test run on a device group, wait for completion and download results """

        test_run = self.start_wait_test_run(test_run_config)
        self.download_test_run(test_run['projectId'], test_run['id'])

    def wait_test_run(self, project_id, test_run_id):
        """ Awaits completion of the given test run """

        if test_run_id:
            print("Awaiting completion of test run with id {}. Will wait forever polling every {}.".format(
                test_run_id,
                '{} minutes'.format(self.polling_interval_mins) if self.polling_interval_mins != 1 else 'minute'))

            while True:
                time.sleep(self.polling_interval_mins * 60)
                test_run_status = self.get_test_run(project_id, test_run_id)
                if test_run_status and 'state' in test_run_status:
                    if test_run_status['state'] == "FINISHED":
                        print("The test run with id: %s has FINISHED" % test_run_id)
                        break
                    elif test_run_status['state'] == "WAITING":
                        print("[%s] The test run with id: %s is awaiting to be scheduled" %
                              (time.strftime("%H:%M:%S"), test_run_id))
                        continue
                    elif test_run_status['state'] == "RUNNING":
                        print("[%s] The test run with id: %s is running" % (time.strftime("%H:%M:%S"), test_run_id))
                        continue

                print("Couldn't establish the state of the test run with id: %s. Aborting" % test_run_id)
                print(test_run_status)
                sys.exit(1)

    def start_device_session(self, device_model_id):
        """ Start device sessions """

        payload = {'deviceModelId': device_model_id}
        return self.post("me/device-sessions", payload)

    def stop_device_session(self, device_session_id):
        """ Stop device session """

        return self.post("me/device-sessions/%s/release" % device_session_id)

    def get_project_test_runs(self, project_id, limit=0):
        """ Get all test runs for a project """

        return self.get(path="me/projects/%s/runs" % project_id, payload={'limit': limit})

    def print_project_test_runs(self, project_id, limit=0):
        """ Print test runs of a project to console """

        test_runs = self.get_project_test_runs(project_id, limit)['data']
        for test_run in test_runs:
            print("%s %s  %s %s" % (str(test_run['id']).ljust(10), ts_format(test_run['createTime']),
                                    test_run['displayName'].ljust(30), test_run['state']))

    def get_test_run(self, project_id, test_run_id):
        """ Get a single test run """

        return self.get("me/projects/%s/runs/%s" % (project_id, test_run_id))

    def retry_test_run(self, project_id, test_run_id, device_session_ids=None):
        """ Re-run an already-existing test run. Specify individual device session IDs to only re-run those devices. """

        endpoint = "me/projects/%s/runs/%s/retry" % (project_id, test_run_id)
        if device_session_ids:
            endpoint += "?deviceRunIds[]=" + "&deviceRunIds[]=".join(str(device_id) for device_id in device_session_ids)
        return self.post(endpoint)

    def abort_test_run(self, project_id, test_run_id):
        """ Abort a test run """

        return self.post("me/projects/%s/runs/%s/abort" % (project_id, test_run_id))

    def get_device_sessions(self, project_id, test_run_id, limit=0):
        """ Return device sessions for a project """

        return self.get(path="me/projects/%s/runs/%s/device-sessions" %
                             (project_id, test_run_id), payload={'limit': limit})

    def get_device_runs(self, project_id, test_run_id, limit=0):
        """ ***DEPRECATED***

            Return device sessions for a project
            use get_device_sessions() instead
        """

        return self.get_device_sessions(project_id, test_run_id, limit)

    def get_device_session_screenshots_list(self, project_id, test_run_id, device_session_id, limit=0):
        """ Downloads screenshots list for a device session """

        return self.get("me/projects/%s/runs/%s/device-sessions/%s/screenshots" %
                        (project_id, test_run_id, device_session_id), payload={'limit': limit})

    def get_device_run_screenshots_list(self, project_id, test_run_id, device_run_id, limit=0):
        """ ***DEPRECATED***

            Downloads screenshots list for a device run
            use get_device_run_screenshots_list() instead
        """

        return self.get_device_session_screenshots_list(project_id, test_run_id, device_run_id, limit)

    def get_device_session_files(self, project_id, test_run_id, device_session_id, tags=None):
        """ Get list of files for device session """

        if tags is None:
            return self.get("me/projects/%s/runs/%s/device-sessions/%s/output-file-set/files?limit=0" %
                            (project_id, test_run_id, device_session_id))
        else:
            return self.get("me/projects/%s/runs/%s/device-sessions/%s/output-file-set/files?limit=0&tag[]=%s" %
                            (project_id, test_run_id, device_session_id, tags))

    def get_device_run_files(self, project_id, test_run_id, device_session_id, tags=None):
        """ ***DEPRECATED***

            Get list of files for device run
            use get_device_session_files() instead
        """

        return self.get_device_session_files(project_id, test_run_id, device_session_id, tags)

    def get_input_files(self, limit=0):
        """ Get list of input files """

        return self.get("me/files?limit={}&filter=s_direction_eq_INPUT".format(limit))

    def download_test_run(self, project_id, test_run_id):
        """ Downloads test run files to a directory hierarchy """

        test_run = self.get_test_run(project_id, test_run_id)
        device_sessions = self.get_device_sessions(project_id, test_run_id)

        logger.info("")
        logger.info("Test run %s: \"%s\" has %s device sessions:" %
                    (test_run['id'], test_run['displayName'], len(device_sessions['data'])))

        for device_session in device_sessions['data']:
            state = device_session['state']
            logger.info("")
            logger.info("%s \"%s\" %s" % (device_session['id'], device_session['device']['displayName'], state))

            if state in ("ABORTED", "TIMEOUT", "WARNING", "SUCCEEDED", "FAILED", "EXCLUDED"):
                directory = "%s-%s/%d-%s" % (test_run_id, test_run['displayName'], device_session['id'],
                                             device_session['device']['displayName'])
                session_id = device_session['id']
                files = self.get_device_session_files(project_id, test_run_id, session_id)
                self.__download_files(files, directory)
            else:
                logger.info("Device session hasn't ended - Skipping file downloads")
                logger.info("")

    def __download_files(self, files, directory):
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
        if len(files) == 0:
            logger.info("No files to download")
            logger.info("")

    def download_test_screenshots(self, project_id, test_run_id):
        """ Downloads test run screenshots """

        test_run = self.get_test_run(project_id, test_run_id)
        device_sessions = self.get_device_sessions(project_id, test_run_id)
        logger.info("Test run %s: \"%s\" has %s device sessions:" %
                    (test_run['id'], test_run['displayName'], len(device_sessions['data'])))
        for device_session in device_sessions['data']:
            logger.info("%s \"%s\" %s" %
                        (device_session['id'], device_session['device']['displayName'], device_session['state']))

        logger.info("")
        for device_session in device_sessions['data']:
            if device_session['state'] in ["SUCCEEDED", "FAILED", "ABORTED", "WARNING", "TIMEOUT"]:
                directory = "%s-%s/%d-%s/screenshots" % (test_run['id'], test_run['displayName'],
                                                         device_session['id'], device_session['device']['displayName'])
                screenshots = self.get_device_session_screenshots_list(project_id, test_run_id, device_session['id'])
                no_screenshots = True

                for screenshot in screenshots['data']:
                    no_screenshots = False
                    full_path = "%s/%s" % (directory, screenshot['originalName'])
                    if not os.path.exists(directory):
                        os.makedirs(directory)

                    if not os.path.exists(full_path):
                        self.__download_screenshot(project_id, test_run['id'], device_session['id'], screenshot['id'],
                                                   full_path)
                    else:
                        ''' Earlier downloaded images are checked, and if needed re-downloaded.
                        '''
                        try:
                            if imghdr.what(full_path) in ['jpeg', 'png']:
                                logger.info("Screenshot %s already exists - skipping download" % full_path)
                            else:
                                raise
                        except:
                            self.__download_screenshot(project_id, test_run['id'], device_session['id'],
                                                       screenshot['id'], full_path)

                if no_screenshots:
                    logger.info("Device %s has no screenshots - skipping" % device_session['device']['displayName'])
            else:
                logger.info("Device %s has errored or has not finished - skipping" %
                            device_session['device']['displayName'])

    def __download_screenshot(self, project_id, test_run_id, device_session_id, screenshot_id, full_path):
        url = "me/projects/%s/runs/%s/device-sessions/%s/screenshots/%s" % \
              (project_id, test_run_id, device_session_id, screenshot_id)
        prog = DownloadProgressBar()
        self.download(url, full_path, callback=lambda pos, total: prog.update(int(pos), int(total)))
        print("")

    def get_access_groups(self):
        """ Get access groups """

        return self.get("me/access-groups")

    def get_access_group(self, access_group_id):
        """ Get access group by id """

        return self.get("me/access-groups/{}".format(access_group_id))

    def create_access_group(self, access_group_name, access_group_scope="USER"):
        """ Create access group """

        group = self.post(path="me/access-groups", payload={"name": access_group_name, "scope": access_group_scope})
        return group

    def update_access_group(self, access_group_id, access_group_name, access_group_scope):
        """ Update access group """

        # TODO: what if group_name or group_scope aren't provided??
        group = self.post(path="me/access-groups/{}".format(access_group_id),
                          payload={"name": access_group_name, "scope": access_group_scope})
        return group

    def delete_access_group(self, access_group_id):
        """ Delete access group """

        # TODO: what if group_name or group_scope aren't provided??
        return self.delete(path="me/access-groups/{}".format(access_group_id))

    def get_access_group_resources(self, access_group_id):
        """ Get access group resources by id """

        return self.get("me/access-groups/{}/resources".format(access_group_id))

    def get_access_group_resource(self, access_group_id, resource_id):
        """ Get resource from access group """

        return self.get("me/access-groups/{}/resources/{}".format(access_group_id, resource_id))

    def delete_access_group_resource(self, access_group_id, resource_id):
        """ Delete resource from access group """

        return self.delete("me/access-groups/{}/resources/{}".format(access_group_id, resource_id))

    def get_access_group_users(self, access_group_id):
        """ Get access group users """

        return self.get("me/access-groups/{}/users".format(access_group_id))

    def add_access_group_user(self, access_group_id, email):
        """ Add user to access group """

        return self.post("me/access-groups/{}/users".format(access_group_id), payload={"email": email})

    def get_access_group_user(self, access_group_id, user_id):
        """ Get user from access group """

        return self.get("me/access-groups/{}/users/{}".format(access_group_id, user_id))

    def delete_access_group_user(self, access_group_id, user_id):
        """ Delete user from access group """

        return self.delete("me/access-groups/{}/users/{}".format(access_group_id, user_id))

    def share_device_group(self, device_group_id, access_group_id):
        """ Share device group with access group """

        return self.post("me/device-groups/{}/share".format(device_group_id),
                         payload={"accessGroupId": access_group_id})

    def share_file_set(self, file_set_id, access_group_id):
        """ Share file set with access group """

        return self.post("me/file-sets/{}/share".format(file_set_id), payload={"accessGroupId": access_group_id})

    def share_file(self, file_id, access_group_id):
        """ Share file with access group """

        return self.post("me/files/{}/share".format(file_id), payload={"accessGroupId": access_group_id})

    def share_project(self, project_id, access_group_id):
        """ Share project with access group """

        return self.post("me/projects/{}/share".format(project_id), payload={"accessGroupId": access_group_id})

    def get_parser(self):
        class MyParser(OptionParser):
            def format_epilog(self, formatter):
                return self.epilog

        usage = "usage: %prog [options] <command> [arguments...]"
        description = "Client for Bitbar Cloud API v2"
        epilog = """
Commands:

    me                                          Get user details
    available-free-devices                      Print list of currently available free devices
    device-groups                               Get list of your device groups
    create-project <name>
    delete-project <id>                         Delete a project
    projects                                    Get projects
    get-file <file-id>                          Get file details
    upload-file <filename> <timeout> <skip-scan-wait>
                                                Upload file
                                                waits for virus scan unless skip-scan-wait is True (default: False)
                                                up to given timeout (default: 300s)
    wait-for-virus-scan <files> <timeout>       Wait for virus scan of list of files to finish 
                                                up to given timeout (default: 300s)
    start-wait-download-test-run <test_run_config>
                                                Start a test run, await completion (polling) and download results
    wait-test-run <project-id> <test-run-id>    Await completion (polling) of the test run
    test-runs <project-id>                      Get test runs for a project
    test-run <project-id> <test-run-id>         Get test run details
    get_device_sessions <project-id> <test-run-id>      
                                                Get device sessions for a test run
    device-runs <project-id> <test-run-id>      ***DEPRECATED*** Get device runs for a test run
    download-test-run <project-id> <test-run-id>
                                                Download test run data. Data will be downloaded to
                                                current directory in a structure:
                                                [test-run-id]/[device-session-id]-[device-name]/files...
    download-test-screenshots <project-id> <test-run-id>
                                                Download test run screenshots. Screenshots will be downloaded to
                                                current directory in a structure:
                                                [test-run-id]/[device-session-id]-[device-name]/screenshots/...

    access-groups                               Get access groups
    access-group <access-group-id>              Get an access group by id
    access-group-create <name> <scope>          Create a new access group
    access-group-update <access-group-id> <name> <scope>
                                                Update an access group
    access-group-delete <access-group-id>       Delete an access group
    access-group-resources <access-group-id>    Get resources in an access group
    access-group-resource <access-group-id> <resource-id>
                                                Get a resource in an access group by id
    access-group-resource-remove <access-group-id> <resource-id>
                                                Remove a resource from an access group
    access-group-users <access-group-id>        Get users in an access group
    access-group-users-get <access-group-id> <user-id>
                                                Get a user in an access group
    access-group-users-add <access-group-id> <user-email>
                                                Add a user to an access group
    access-group-users-remove <access-group-id> <user-email>
                                                Remove a user from an access group

    share-device-group <device-group-id> <access-group-id>
                                                Share a device group with an access group
    share-file-set <file-set-id> <access-group-id>
                                                Share a file set with an access group
    share-file <file-id> <access-group-id>      Share a file with an access group
    share-project <project-id> <access-group-id>
                                                Share a project with an access group
"""
        parser = MyParser(usage=usage, description=description, epilog=epilog, version="%s %s" % ("%prog", __version__))
        parser.add_option("-k", "--apikey", dest="apikey",
                          help="API key - the API key for Bitbar Cloud. Optional. "
                               "You can use environment variable TESTDROID_APIKEY as well.")
        parser.add_option("-c", "--url", dest="url", default="https://cloud.bitbar.com",
                          help="Cloud endpoint. Default is https://cloud.bitbar.com. "
                               "You can use environment variable TESTDROID_URL as well.")
        parser.add_option("-i", "--interval", dest="interval",
                          help="How frequently the status of a test run should be checked (in minutes). "
                               "Can be used with the command wait-test-run.")
        parser.add_option("-q", "--quiet", action="store_true", dest="quiet",
                          help="Quiet mode")
        parser.add_option("-d", "--debug", action="store_true", dest="debug",
                          help="Turn on debug level logging")
        return parser

    def get_commands(self):
        return {
            "me": self.get_me,
            "device-groups": self.print_device_groups,
            "available-free-devices": self.print_available_free_devices,
            "available-frameworks": self.print_available_frameworks,
            "projects": self.print_projects,
            "create-project": self.create_project,
            "delete-project": self.delete_project,
            "get-file": self.get_file,
            "upload-file": self.upload_file,
            "wait-for-virus-scan": self.wait_for_virus_scan,
            "validate-test-run-config": self.validate_test_run_config,
            "start-test-run-using-config": self.start_test_run_using_config,
            "start-wait-download-test-run": self.start_wait_download_test_run,
            "wait-test-run": self.wait_test_run,
            "test-run": self.get_test_run,
            "test-runs": self.print_project_test_runs,
            "device-sessions": self.get_device_sessions,
            "device-session-files": self.get_device_session_files,
            "device-runs": self.get_device_runs,
            "device-run-files": self.get_device_run_files,
            "list-input-files": self.print_input_files,
            "download-test-run": self.download_test_run,
            "access-groups": self.get_access_groups,
            "access-group": self.get_access_group,
            "access-group-create": self.create_access_group,
            "access-group-update": self.update_access_group,
            "access-group-delete": self.delete_access_group,
            "access-group-resources": self.get_access_group_resources,
            "access-group-resource": self.get_access_group_resource,
            "access-group-resource-remove": self.delete_access_group_resource,
            "access-group-users": self.get_access_group_users,
            "access-group-users-add": self.add_access_group_user,
            "access-group-users-get": self.get_access_group_user,
            "access-group-users-remove": self.delete_access_group_user,
            "share-device-group": self.share_device_group,
            "share-file-set": self.share_file_set,
            "share-file": self.share_file,
            "share-project": self.share_project,
        }

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

        apikey = options.apikey or os.environ.get('TESTDROID_APIKEY')
        url = os.environ.get('TESTDROID_URL') or options.url

        try:
            polling_interval_mins = max(int(options.interval), 1)
        except:
            polling_interval_mins = 10

        self.set_apikey(apikey)
        self.set_url(url)
        self.set_polling_interval_mins(polling_interval_mins)

        command = commands[args[0]]
        if not command:
            parser.print_help()
            sys.exit(1)

        print(command(*args[1:]) or "")


def main():
    testdroid = Testdroid()
    parser = testdroid.get_parser()
    commands = testdroid.get_commands()
    testdroid.cli(parser, commands)


if __name__ == '__main__':
    main()
