# -*- coding: utf-8 -*-

from unittest import TestCase
import os

import testdroid
import responses

JSON = {'k': 'v'}
PROJECT_ID = 2
TEST_RUN_ID = 3
DEVICE_SESSION_ID = 5
DEVICE_GROUP_ID = 6
USER_ID = 7
PARAM_ID = 8
TAGS = 'tags'
LIMIT = 0


URL_BASE = 'https://cloud.bitbar.com'
URL_API = '{}/api/v2'.format(URL_BASE)
URL_API_ME = '{}/me'.format(URL_API)
URL_USERS = '{}/users/{}'.format(URL_API, USER_ID)

t = testdroid.Testdroid()


# check that API calls go where they should go
class TestNetworking(TestCase):

    @responses.activate
    def test_get(self):
        path = 'get'
        url = '{}/{}'.format(URL_API, path)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get('get')
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_post(self):
        path = 'post'
        url = '{}/{}'.format(URL_API, path)
        responses.add(responses.POST, url, json=JSON, status=200)
        response = t.post(path)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_delete(self):
        path = 'delete'
        url = '{}/{}'.format(URL_API, path)
        responses.add(responses.DELETE, url, json=JSON, status=200)
        response = t.delete(path)
        self.assertEqual(response.status_code, 200)

    @responses.activate
    def test_upload(self):
        path = 'upload'
        file_path = '{}/testdroid/tests/upload.txt'.format(os.getcwd())
        url = '{}/{}'.format(URL_API, path)
        responses.add(responses.POST, url, json=JSON, status=200)
        response = t.upload(path, file_path)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_me(self):
        url = URL_API_ME
        responses.add(responses.GET, url, json=JSON, status=200)
        self.assertEqual(t.get_me(), JSON)

    @responses.activate
    def test_get_device_groups(self):
        url = '{}/device-groups'.format(URL_API_ME)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_device_groups()
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_frameworks(self):
        url = '{}/available-frameworks'.format(URL_API_ME)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_frameworks()
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_devices(self):
        url = '{}/devices'.format(URL_API)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_devices()
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_projects(self):
        url = '{}/projects'.format(URL_API_ME)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_projects()
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_project(self):
        url = '{}/projects/{}'.format(URL_API_ME, PROJECT_ID)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_project(PROJECT_ID)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_project_test_runs(self):
        url = '{}/projects/{}/runs'.format(URL_API_ME, PROJECT_ID)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_project_test_runs(PROJECT_ID)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_test_run(self):
        url = '{}/projects/{}/runs/{}'.format(URL_API_ME, PROJECT_ID, TEST_RUN_ID)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_test_run(PROJECT_ID, TEST_RUN_ID)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_device_session(self):
        url = '{}/projects/{}/runs/{}/device-sessions'.format(URL_API_ME, PROJECT_ID, TEST_RUN_ID)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_device_sessions(PROJECT_ID, TEST_RUN_ID)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_device_session_screenshots_list(self):
        url = '{}/projects/{}/runs/{}/device-sessions/{}/screenshots'.format(
            URL_API_ME, PROJECT_ID, TEST_RUN_ID, DEVICE_SESSION_ID)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_device_session_screenshots_list(PROJECT_ID, TEST_RUN_ID, DEVICE_SESSION_ID)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_device_sessions_files_without_tags(self):
        url = '{}/projects/{}/runs/{}/device-sessions/{}/output-file-set/files'.format(
            URL_API_ME, PROJECT_ID, TEST_RUN_ID, DEVICE_SESSION_ID)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_device_session_files(PROJECT_ID, TEST_RUN_ID, DEVICE_SESSION_ID)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_device_session_files_with_tags(self):
        url = '{}/projects/{}/runs/{}/device-sessions/{}/output-file-set/files?limit=0&tag[]={}'.format(
            URL_API_ME, PROJECT_ID, TEST_RUN_ID, DEVICE_SESSION_ID, TAGS)
        responses.add(responses.GET, url, json=JSON, status=200)
        response = t.get_device_session_files(PROJECT_ID, TEST_RUN_ID, DEVICE_SESSION_ID, TAGS)
        self.assertEqual(response, JSON)

    @responses.activate
    def test_get_input_files(self):
        url = '{}/files?limit={}&filter=s_direction_eq_INPUT'.format(URL_API_ME, LIMIT)
        responses.add(responses.GET, url, json=JSON, status=200)
        self.assertEqual(t.get_input_files(LIMIT), JSON)
