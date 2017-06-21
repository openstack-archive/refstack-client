# Copyright 2015 IBM Corp.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import logging
import os
import requests
import subprocess
import tempfile

import httmock
import mock
import unittest

import refstack_client.list_parser as parser


class TestTestListParser(unittest.TestCase):

    test_path = os.path.dirname(os.path.realpath(__file__))
    tempest_dir = "some_dir/.tempest"

    def setUp(self):
        """Test case setup"""
        logging.disable(logging.CRITICAL)
        self.parser = parser.TestListParser(self.tempest_dir)

    def test_get_tempest_test_ids(self):
        """Test that the tempest test-list is correctly parsed."""
        test_list = ("tempest.test.one[gate]\n"
                     "tempest.test.two[gate,smoke]\n"
                     "tempest.test.three(scenario)\n"
                     "tempest.test.four[gate](another_scenario)\n"
                     "tempest.test.five")
        process_mock = mock.Mock(returncode=0)
        attrs = {'communicate.return_value': (test_list, None)}
        process_mock.configure_mock(**attrs)
        subprocess.Popen = mock.Mock(return_value=process_mock)
        output = self.parser._get_tempest_test_ids()

        subprocess.Popen.assert_called_with(
            ("%s/tools/with_venv.sh" % self.tempest_dir, "testr",
             "list-tests"),
            stdout=subprocess.PIPE,
            cwd=self.tempest_dir)
        expected_output = {"tempest.test.one": "[gate]",
                           "tempest.test.two": "[gate,smoke]",
                           "tempest.test.three(scenario)": "",
                           "tempest.test.four(another_scenario)": "[gate]",
                           "tempest.test.five": ""}
        self.assertEqual(expected_output, output)

    def test_get_tempest_test_ids_fail(self):
        """Test when the test listing subprocess returns a non-zero exit
        status.
        """
        process_mock = mock.Mock(returncode=1)
        attrs = {'communicate.return_value': (mock.ANY, None)}
        process_mock.configure_mock(**attrs)
        subprocess.Popen = mock.Mock(return_value=process_mock)
        with self.assertRaises(subprocess.CalledProcessError):
            self.parser._get_tempest_test_ids()

    def test_form_test_id_mappings(self):
        """Test the test ID to attribute dict builder function."""
        test_list = ["tempest.test.one[gate]",
                     "tempest.test.two[gate,smoke]",
                     "tempest.test.three(scenario)",
                     "tempest.test.four[gate](another_scenario)",
                     "tempest.test.five"]

        expected_output = {"tempest.test.one": "[gate]",
                           "tempest.test.two": "[gate,smoke]",
                           "tempest.test.three(scenario)": "",
                           "tempest.test.four(another_scenario)": "[gate]",
                           "tempest.test.five": ""}
        output = self.parser._form_test_id_mappings(test_list)
        self.assertEqual(expected_output, output)

    def test_get_base_test_ids_from_list_file(self):
        """test that we can get the base test IDs from a test list file."""
        list_file = self.test_path + "/test-list.txt"
        test_list = self.parser._get_base_test_ids_from_list_file(list_file)
        expected_list = ['tempest.api.test1',
                         'tempest.api.test2',
                         'tempest.api.test3(scenario)']
        self.assertEqual(expected_list, sorted(test_list))

    def test_get_base_test_ids_from_list_files_invalid_file(self):
        """Test that we get an exception when passing in a nonexistent file."""
        some_file = self.test_path + "/nonexistent.json"
        with self.assertRaises(Exception):
            self.parser._get_base_test_ids_from_list_file(some_file)

    def test_get_base_test_ids_from_list_file_url(self):
        """Test that we can parse the test cases from a test list URL."""
        list_file = self.test_path + "/test-list.txt"

        with open(list_file, 'rb') as f:
            content = f.read()

        @httmock.all_requests
        def request_mock(url, request):
            return {'status_code': 200,
                    'content': content}

        with httmock.HTTMock(request_mock):
            online_list = self.parser._get_base_test_ids_from_list_file(
                "http://127.0.0.1/test-list.txt")

        expected_list = ['tempest.api.test1',
                         'tempest.api.test2',
                         'tempest.api.test3(scenario)']
        self.assertEqual(expected_list, sorted(online_list))

    def test_get_base_test_ids_from_list_file_invalid_url(self):
        """Test a case of an invalid URL schema."""
        with self.assertRaises(requests.exceptions.RequestException):
            self.parser._get_base_test_ids_from_list_file("foo://sasas.com")

    def test_get_full_test_ids(self):
        """Test that full test IDs can be formed."""
        tempest_ids = {"tempest.test.one": "[gate]",
                       "tempest.test.two": "[gate,smoke]",
                       "tempest.test.three(scenario)": "",
                       "tempest.test.four(another_scenario)": "[gate]",
                       "tempest.test.five": ""}

        base_ids = ["tempest.test.one",
                    "tempest.test.four(another_scenario)",
                    "tempest.test.five"]

        output_list = self.parser._get_full_test_ids(tempest_ids, base_ids)
        expected_list = ["tempest.test.one[gate]",
                         "tempest.test.four[gate](another_scenario)",
                         "tempest.test.five"]
        self.assertEqual(expected_list, output_list)

    def test_get_full_test_ids_with_nonexistent_test(self):
        """Test when a test ID doesn't exist in the Tempest environment."""
        tempest_ids = {"tempest.test.one": "[gate]",
                       "tempest.test.two": "[gate,smoke]"}
        base_ids = ["tempest.test.one", "tempest.test.foo"]
        output_list = self.parser._get_full_test_ids(tempest_ids, base_ids)

        self.assertEqual(["tempest.test.one[gate]"], output_list)

    def test_write_normalized_test_list(self):
        """Test that a normalized test list is written to disk."""
        test_ids = ["tempest.test.one[gate]", "tempest.test.five"]
        test_file = self.parser._write_normalized_test_list(test_ids)

        # Check that the tempest IDs in the file match the expected test
        # ID list.
        with open(test_file, 'rb') as f:
            file_contents = f.read()
        testcase_list = list(filter(None,
                                    file_contents.decode('utf-8').split('\n')))

        self.assertEqual(test_ids, testcase_list)

    def test_setup_venv(self):
        """Test whether the proper script is called to setup a virtualenv."""
        process_mock = mock.Mock(returncode=0)
        subprocess.Popen = mock.Mock(return_value=process_mock)
        self.parser.setup_venv(logging.DEBUG)
        subprocess.Popen.assert_called_with(
            ("python", "%s/tools/install_venv.py" % self.tempest_dir),
            cwd=self.tempest_dir,
            stdout=None)

    def test_setup_venv_fail(self):
        """Test whether the proper script is called to setup a virtualenv."""
        process_mock = mock.Mock(returncode=1)
        subprocess.Popen = mock.Mock(return_value=process_mock)
        with self.assertRaises(subprocess.CalledProcessError):
            self.parser.setup_venv(logging.DEBUG)

    @mock.patch.object(parser.TestListParser, "get_normalized_test_list")
    def test_create_whitelist(self, mock_get_normalized):
        """Test whether a test list is properly parsed to extract test names"""
        test_list = [
            "tempest.test.one[id-11111111-2222-3333-4444-555555555555,gate]",
            "tempest.test.two[comp,id-22222222-3333-4444-5555-666666666666]",
            "tempest.test.three[id-33333333-4444-5555-6666-777777777777](gate)"
        ]

        expected_list = "tempest.test.one\[\n"\
                        "tempest.test.two\[\n"\
                        "tempest.test.three\[\n"

        tmpfile = tempfile.mktemp()
        with open(tmpfile, 'w') as f:
            [f.write(item + "\n") for item in test_list]
        mock_get_normalized.return_value = tmpfile

        result = open(self.parser.create_whitelist(tmpfile)).read()
        self.assertEqual(result, expected_list)
