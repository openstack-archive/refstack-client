#
# Copyright (c) 2014 Piston Cloud Computing, Inc. All Rights Reserved.
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

import json
import logging
import os
import tempfile

import httmock
import mock
from mock import MagicMock
import unittest


import refstack_client.refstack_client as rc
import refstack_client.list_parser as lp


class TestRefstackClient(unittest.TestCase):

    test_path = os.path.dirname(os.path.realpath(__file__))
    conf_file_name = '%s/refstack-client.test.conf' % test_path

    def patch(self, name, **kwargs):
        """
        :param name: Name of class to be patched
        :param kwargs: directly passed to mock.patch
        :return: mock
        """
        patcher = mock.patch(name, **kwargs)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def mock_argv(self, command='test', **kwargs):
        """
        Build argv for test.
        :param conf_file_name: Configuration file name
        :param verbose: verbosity level
        :return: argv
        """
        argv = [command]
        if kwargs.get('verbose', None):
            argv.append(kwargs.get('verbose', None))
        argv.extend(['--url', 'http://127.0.0.1', '-y'])
        if kwargs.get('priv_key', None):
            argv.extend(('-i', kwargs.get('priv_key', None)))
        if command == 'test':
            argv.extend(
                ('-c', kwargs.get('conf_file_name', self.conf_file_name)))
            if kwargs.get('test_cases', None):
                argv.extend(('--', kwargs.get('test_cases', None)))

        return argv

    def mock_keystone(self):
        """
        Mock the Keystone client methods.
        """
        self.mock_identity_service = MagicMock(
            name='service', **{'type': 'identity', 'id': 'test-id'})
        self.mock_ks_client = MagicMock(
            name='ks_client',
            **{'services.list.return_value': [self.mock_identity_service]}
        )
        self.ks_client_builder = self.patch(
            'refstack_client.refstack_client.ksclient.Client',
            return_value=self.mock_ks_client
        )

    def setUp(self):
        """
        Test case setup
        """
        logging.disable(logging.CRITICAL)

    def test_verbose(self):
        """
        Test different verbosity levels.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        self.assertEqual(client.logger.level, logging.ERROR)

        args = rc.parse_cli_args(self.mock_argv(verbose='-v'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        self.assertEqual(client.logger.level, logging.INFO)

        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        self.assertEqual(client.logger.level, logging.DEBUG)

    def test_get_next_stream_subunit_output_file(self):
        """
        Test getting the subunit file from an existing .testrepository
        directory that has a next-stream file.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        output_file = client._get_next_stream_subunit_output_file(
            self.test_path)

        # The next-stream file contains a "1".
        expected_file = expected_file = self.test_path + "/.testrepository/1"
        self.assertEqual(expected_file, output_file)

    def test_get_next_stream_subunit_output_file_nonexistent(self):
        """
        Test getting the subunit output file from a nonexistent
        .testrepository directory.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        output_file = client._get_next_stream_subunit_output_file(
            "/tempest/path")
        expected_file = "/tempest/path/.testrepository/0"
        self.assertEqual(expected_file, output_file)

    def test_get_cpid_from_keystone_with_tenant_id(self):
        """
        Test getting the CPID from Keystone using an admin tenant ID.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        self.mock_keystone()
        cpid = client._get_cpid_from_keystone(client.conf)
        self.ks_client_builder.assert_called_with(
            username='admin', tenant_id='admin_tenant_id',
            password='test', auth_url='0.0.0.0:35357'
        )
        self.assertEqual('test-id', cpid)

    def test_get_cpid_from_keystone_with_tenant_name(self):
        """
        Test getting the CPID from Keystone using an admin tenant name.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        client.conf.remove_option('identity', 'admin_tenant_id')
        client.conf.set('identity', 'admin_tenant_name', 'admin_tenant_name')
        self.mock_keystone()
        cpid = client._get_cpid_from_keystone(client.conf)
        self.ks_client_builder.assert_called_with(
            username='admin', tenant_name='admin_tenant_name',
            password='test', auth_url='0.0.0.0:35357'
        )

        self.assertEqual('test-id', cpid)

    def test_get_cpid_from_keystone_no_admin_tenant(self):
        """
        Test exit under absence of information about admin tenant info.
        """
        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        client.conf.remove_option('identity', 'admin_tenant_id')
        self.assertRaises(SystemExit, client._get_cpid_from_keystone,
                          client.conf)

    def test_form_result_content(self):
        """
        Test that the request content is formed into the expected format.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        content = client._form_result_content(1, 1, ['tempest.sample.test'])
        expected = {'cpid': 1,
                    'duration_seconds': 1,
                    'results': ['tempest.sample.test']}
        self.assertEqual(expected, content)

    def test_save_json_result(self):
        """
        Test that the results are properly written to a JSON file.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        results = {'cpid': 1,
                   'duration_seconds': 1,
                   'results': ['tempest.sample.test']}
        temp_file = tempfile.NamedTemporaryFile()
        client._save_json_results(results, temp_file.name)

        # Get the JSON that was written to the file and make sure it
        # matches the expected value.
        json_file = open(temp_file.name)
        json_data = json.load(json_file)
        json_file.close()
        self.assertEqual(results, json_data)

    def test_get_passed_tests(self):
        """
        Test that only passing tests are retrieved from a subunit file.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        subunit_file = self.test_path + "/.testrepository/0"
        results = client.get_passed_tests(subunit_file)
        expected = [
            {'name': 'tempest.passed.test'},
            {'name': 'tempest.tagged_passed.test',
             'uuid': '0146f675-ffbd-4208-b3a4-60eb628dbc5e'}
        ]
        self.assertEqual(expected, results)

    @mock.patch('six.moves.input')
    def test_user_query(self, mock_input):
        client = rc.RefstackClient(rc.parse_cli_args(self.mock_argv()))
        self.assertTrue(client._user_query('42?'))

        mock_input.return_value = 'n'
        cli_args = self.mock_argv()
        cli_args.remove('-y')
        client = rc.RefstackClient(rc.parse_cli_args(cli_args))
        self.assertFalse(client._user_query('42?'))
        mock_input.return_value = 'yes'
        self.assertTrue(client._user_query('42?'))

    def test_post_results(self):
        """
        Test the post_results method, ensuring a requests call is made.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.logger.info = MagicMock()
        content = {'duration_seconds': 0,
                   'cpid': 'test-id',
                   'results': [{'name': 'tempest.passed.test', 'uid': None}]}
        expected_response = json.dumps({'test_id': 42})

        @httmock.urlmatch(netloc=r'(.*\.)?127.0.0.1$', path='/v1/results/')
        def refstack_api_mock(url, request):
            return expected_response

        with httmock.HTTMock(refstack_api_mock):
            client.post_results("http://127.0.0.1", content)

        client.logger.info.assert_called_with(
            'http://127.0.0.1/v1/results/ Response: '
            '%s' % expected_response
        )

    def test_post_results_with_sign(self):
        """
        Test the post_results method, ensuring a requests call is made.
        """
        argv = self.mock_argv(command='upload', priv_key='rsa_key')
        argv.append('fake.json')
        args = rc.parse_cli_args(argv)
        client = rc.RefstackClient(args)
        client.logger.info = MagicMock()
        content = {'duration_seconds': 0,
                   'cpid': 'test-id',
                   'results': [{'name': 'tempest.passed.test'}]}
        expected_response = json.dumps({'test_id': 42})

        @httmock.urlmatch(netloc=r'(.*\.)?127.0.0.1$', path='/v1/results/')
        def refstack_api_mock(url, request):
            return expected_response

        with httmock.HTTMock(refstack_api_mock):
            client.post_results("http://127.0.0.1", content,
                                sign_with=self.test_path + '/rsa_key')
        client.logger.info.assert_called_with(
            'http://127.0.0.1/v1/results/ Response: '
            '%s' % expected_response
        )

    def test_run_tempest(self):
        """
        Test that the test command will run the tempest script using the
        default configuration.
        """
        args = rc.parse_cli_args(
            self.mock_argv(verbose='-vv', test_cases='tempest.api.compute'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        mock_popen = self.patch(
            'refstack_client.refstack_client.subprocess.Popen',
            return_value=MagicMock(returncode=0))
        self.patch("os.path.isfile", return_value=True)
        self.mock_keystone()
        client.get_passed_tests = MagicMock(return_value=[{'name': 'test'}])
        client.logger.info = MagicMock()
        client._save_json_results = MagicMock()
        client.post_results = MagicMock()
        client.test()

        mock_popen.assert_called_with(
            ['%s/run_tempest.sh' % self.test_path, '-C', self.conf_file_name,
             '-V', '-t', '--', 'tempest.api.compute'],
            stderr=None
        )

        self.assertFalse(client.post_results.called)

    def test_run_tempest_upload(self):
        """
        Test that the test command will run the tempest script and call
        post_results when the --upload argument is passed in.
        """
        argv = self.mock_argv(verbose='-vv',
                              test_cases='tempest.api.compute')
        argv.insert(2, '--upload')
        args = rc.parse_cli_args(argv)
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        mock_popen = self.patch(
            'refstack_client.refstack_client.subprocess.Popen',
            return_value=MagicMock(returncode=0))
        self.patch("os.path.isfile", return_value=True)
        self.mock_keystone()
        client.get_passed_tests = MagicMock(return_value=['test'])
        client.post_results = MagicMock()
        client._save_json_results = MagicMock()
        client.test()
        mock_popen.assert_called_with(
            ['%s/run_tempest.sh' % self.test_path, '-C', self.conf_file_name,
             '-V', '-t', '--', 'tempest.api.compute'],
            stderr=None
        )

        self.assertTrue(client.post_results.called)

    def test_run_tempest_upload_with_sign(self):
        """
        Test that the test command will run the tempest script and call
        post_results when the --upload argument is passed in.
        """
        argv = self.mock_argv(verbose='-vv', priv_key='rsa_key',
                              test_cases='tempest.api.compute')
        argv.insert(2, '--upload')
        args = rc.parse_cli_args(argv)
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        mock_popen = self.patch(
            'refstack_client.refstack_client.subprocess.Popen',
            return_value=MagicMock(returncode=0)
        )
        self.patch("os.path.isfile", return_value=True)
        self.mock_keystone()
        client.get_passed_tests = MagicMock(return_value=['test'])
        client.post_results = MagicMock()
        client._save_json_results = MagicMock()
        client.test()
        mock_popen.assert_called_with(
            ['%s/run_tempest.sh' % self.test_path, '-C', self.conf_file_name,
             '-V', '-t', '--', 'tempest.api.compute'],
            stderr=None
        )

        self.assertTrue(client.post_results.called)
        client.post_results.assert_called_with(
            'http://127.0.0.1',
            {'duration_seconds': 0,
             'cpid': 'test-id',
             'results': ['test']},
            sign_with='rsa_key'
        )

    def test_run_tempest_with_test_list(self):
        """Test that the Tempest script runs with a test list file."""
        argv = self.mock_argv(verbose='-vv')
        argv.extend(['--test-list', 'test-list.txt'])
        args = rc.parse_cli_args(argv)
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        mock_popen = self.patch(
            'refstack_client.refstack_client.subprocess.Popen',
            return_value=MagicMock(returncode=0))
        self.patch("os.path.isfile", return_value=True)
        self.mock_keystone()
        client.get_passed_tests = MagicMock(return_value=[{'name': 'test'}])
        client._save_json_results = MagicMock()
        client.post_results = MagicMock()
        lp.TestListParser.get_normalized_test_list = MagicMock(
            return_value="/tmp/some-list")
        client.test()

        lp.TestListParser.get_normalized_test_list.assert_called_with(
            'test-list.txt')
        mock_popen.assert_called_with(
            ['%s/run_tempest.sh' % self.test_path, '-C', self.conf_file_name,
             '-V', '-t', '--', '--load-list', '/tmp/some-list'],
            stderr=None
        )

    def test_run_tempest_no_conf_file(self):
        """
        Test when a nonexistent configuration file is passed in.
        """
        args = rc.parse_cli_args(self.mock_argv(conf_file_name='ptn-khl'))
        client = rc.RefstackClient(args)
        self.assertRaises(SystemExit, client.test)

    def test_run_tempest_nonexisting_directory(self):
        """
        Test when the Tempest directory does not exist.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = "/does/not/exist"
        self.assertRaises(SystemExit, client.test)

    def test_run_tempest_result_tag(self):
        """
        Check that the result JSON file is renamed with the result file tag
        when the --result-file-tag argument is passed in.
        """
        argv = self.mock_argv(verbose='-vv',
                              test_cases='tempest.api.compute')
        argv.insert(2, '--result-file-tag')
        argv.insert(3, 'my-test')
        args = rc.parse_cli_args(argv)
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        mock_popen = self.patch(
            'refstack_client.refstack_client.subprocess.Popen',
            return_value=MagicMock(returncode=0))
        self.patch("os.path.isfile", return_value=True)
        self.mock_keystone()
        client.get_passed_tests = MagicMock(return_value=['test'])
        client._save_json_results = MagicMock()
        client.test()

        mock_popen.assert_called_with(
            ['%s/run_tempest.sh' % self.test_path, '-C', self.conf_file_name,
             '-V', '-t', '--', 'tempest.api.compute'],
            stderr=None
        )

        directory = os.path.dirname(os.path.realpath(__file__))
        # Since '1' is in the next-stream file, we expect the JSON output file
        # to be 'my-test-1.json'.
        expected_file = directory + "/.testrepository/my-test-1.json"
        client._save_json_results.assert_called_with(mock.ANY, expected_file)

    def test_failed_run(self):
        """
        Test when the Tempest script returns a non-zero exit code.
        """
        self.patch('refstack_client.refstack_client.subprocess.Popen',
                   return_value=MagicMock(returncode=1))
        self.mock_keystone()
        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client.logger.error = MagicMock()
        client.test()
        self.assertTrue(client.logger.error.called)

    def test_upload(self):
        """
        Test that the upload command runs as expected.
        """
        upload_file_path = self.test_path + "/.testrepository/0.json"
        args = rc.parse_cli_args(
            self.mock_argv(command='upload', priv_key='rsa_key')
            + [upload_file_path])
        client = rc.RefstackClient(args)

        client.post_results = MagicMock()
        client.upload()
        expected_json = {
            'duration_seconds': 0,
            'cpid': 'test-id',
            'results': [
                {'name': 'tempest.passed.test'},
                {'name': 'tempest.tagged_passed.test',
                 'uuid': '0146f675-ffbd-4208-b3a4-60eb628dbc5e'}
            ]
        }
        client.post_results.assert_called_with('http://127.0.0.1',
                                               expected_json,
                                               sign_with='rsa_key')

    def test_upload_nonexisting_file(self):
        """
        Test when the file to be uploaded does not exist.
        """
        upload_file_path = self.test_path + "/.testrepository/foo.json"
        args = rc.parse_cli_args(['upload', upload_file_path,
                                  '--url', 'http://api.test.org'])
        client = rc.RefstackClient(args)
        self.assertRaises(SystemExit, client.upload)

    def test_yield_results(self):
        """
        Test the yield_results method, ensuring that results are retrieved.
        """
        args = rc.parse_cli_args(self.mock_argv(command='list'))
        client = rc.RefstackClient(args)
        expected_response = {
            "pagination": {
                "current_page": 1,
                "total_pages": 1
            },
            "results": [
                {
                    "cpid": "42",
                    "created_at": "2015-04-28 13:57:05",
                    "test_id": "1",
                    "url": "http://127.0.0.1:8000/output.html?test_id=1"
                },
                {
                    "cpid": "42",
                    "created_at": "2015-04-28 13:57:05",
                    "test_id": "2",
                    "url": "http://127.0.0.1:8000/output.html?test_id=2"
                }]}

        @httmock.urlmatch(netloc=r'(.*\.)?127.0.0.1$', path='/v1/results/')
        def refstack_api_mock(url, request):
            return json.dumps(expected_response)

        with httmock.HTTMock(refstack_api_mock):
            results = client.yield_results("http://127.0.0.1")
            self.assertEqual(expected_response['results'], next(results))
            self.assertRaises(StopIteration, next, results)

    @mock.patch('six.moves.input', side_effect=KeyboardInterrupt)
    @mock.patch('sys.stdout', new_callable=MagicMock)
    def test_list(self, mock_stdout, mock_input):
        args = rc.parse_cli_args(self.mock_argv(command='list'))
        client = rc.RefstackClient(args)
        results = [[{"cpid": "42",
                    "created_at": "2015-04-28 13:57:05",
                    "test_id": "1",
                    "url": "http://127.0.0.1:8000/output.html?test_id=1"},
                   {"cpid": "42",
                    "created_at": "2015-04-28 13:57:05",
                    "test_id": "2",
                    "url": "http://127.0.0.1:8000/output.html?test_id=2"}]]
        mock_results = MagicMock()
        mock_results.__iter__.return_value = results
        client.yield_results = MagicMock(return_value=mock_results)
        client.list()
        self.assertTrue(mock_stdout.write.called)

    def test_sign_pubkey(self):
        """
        Test that the test command will run the tempest script and call
        post_results when the --upload argument is passed in.
        """
        args = rc.parse_cli_args(['sign',
                                  os.path.join(self.test_path, 'rsa_key')])
        client = rc.RefstackClient(args)
        pubkey, signature = client._sign_pubkey()
        self.assertTrue(pubkey.startswith('ssh-rsa AAAA'))
        self.assertTrue(signature.startswith('413cb954'))