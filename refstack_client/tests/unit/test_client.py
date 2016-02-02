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

import hashlib
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
        if kwargs.get('silent', None):
            argv.append(kwargs.get('silent', None))
        argv.extend(['--url', 'http://127.0.0.1', '-y'])
        if kwargs.get('priv_key', None):
            argv.extend(('-i', kwargs.get('priv_key', None)))
        if command == 'test':
            argv.extend(
                ('-c', kwargs.get('conf_file_name', self.conf_file_name)))
            if kwargs.get('test_cases', None):
                argv.extend(('--', kwargs.get('test_cases', None)))
        return argv

    def mock_data(self):
        """
        Mock the Keystone client methods.
        """
        self.mock_identity_service_v2 = {'type': 'identity',
                                         'endpoints': [{'id': 'test-id'}]}
        self.mock_identity_service_v3 = {'type': 'identity',
                                         'id': 'test-id'}
        self.v2_config = {'auth_url': 'http://0.0.0.0:35357/v2.0/tokens',
                          'auth_version': 'v2',
                          'domain_name': 'Default',
                          'password': 'test',
                          'tenant_id': 'admin_tenant_id',
                          'tenant_name': 'tenant_name',
                          'username': 'admin'}

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
        self.assertEqual(client.logger.level, logging.INFO)

        args = rc.parse_cli_args(self.mock_argv(verbose='-v'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        self.assertEqual(client.logger.level, logging.DEBUG)

        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        self.assertEqual(client.logger.level, logging.DEBUG)

        args = rc.parse_cli_args(self.mock_argv(silent='-s'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        self.assertEqual(client.logger.level, logging.WARNING)

        args = rc.parse_cli_args(self.mock_argv(silent='-s'))
        args = rc.parse_cli_args(self.mock_argv(verbose='-v'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        self.assertRaises(SystemExit, client.__init__(args))

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

    def test_get_cpid_account_file_not_found(self):
        """
        Test that the client will exit if an accounts file is specified,
        but does not exist.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()

        client.conf.add_section('auth')
        client.conf.set('auth',
                        'test_accounts_file',
                        '%s/some-file.yaml' % self.test_path)

        self.mock_data()
        with self.assertRaises(SystemExit):
            client._get_keystone_config(client.conf)

    def test_get_keystone_config_account_file_empty(self):
        """
        Test that the client will exit if an accounts file exists,
        but is empty.
        """
        self.patch(
            'refstack_client.refstack_client.read_accounts_yaml',
            return_value=None)

        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()

        client.conf.add_section('auth')
        client.conf.set('auth',
                        'test_accounts_file',
                        '%s/some-file.yaml' % self.test_path)

        self.mock_data()
        with self.assertRaises(SystemExit):
            client._get_keystone_config(client.conf)

    def test_get_keystone_config(self):
        """
        Test that keystone configs properly parsed.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        client.conf.set('identity', 'tenant_name', 'tenant_name')
        self.mock_data()
        actual_result = client._get_keystone_config(client.conf)
        expected_result = self.v2_config
        self.assertEqual(expected_result, actual_result)

    def test_get_cpid_from_keystone_by_tenant_name_from_account_file(self):
        """
        Test getting a CPID from Keystone using an admin tenant name
        from an accounts file.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        client.conf.add_section('auth')
        client.conf.set('auth',
                        'test_accounts_file',
                        '%s/test-accounts.yaml' % self.test_path)
        self.mock_data()
        actual_result = client._get_keystone_config(client.conf)
        expected_result = None
        self.assertEqual(expected_result, actual_result['tenant_id'])
        accounts = [
            {
                'username': 'admin',
                'tenant_id': 'tenant_id',
                'password': 'test'
            }
        ]
        self.patch(
            'refstack_client.refstack_client.read_accounts_yaml',
            return_value=accounts)
        actual_result = client._get_keystone_config(client.conf)
        self.assertEqual('tenant_id', actual_result['tenant_id'])

    def test_generate_keystone_data(self):
        """Test that correct data is generated."""
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        client.conf.set('identity', 'tenant_name', 'tenant_name')
        self.mock_data()
        configs = client._get_keystone_config(client.conf)
        actual_results = client._generate_keystone_data(configs)
        expected_results = ('v2', 'http://0.0.0.0:35357/v2.0/tokens',
                            {'auth':
                                {'passwordCredentials':
                                    {
                                        'username': 'admin', 'password': 'test'
                                    },
                                 'tenantId': 'admin_tenant_id'}})
        self.assertEqual(expected_results, actual_results)

    def test_get_cpid_from_keystone_v3_varying_catalogs(self):
        """
        Test getting the CPID from keystone API v3 with varying catalogs.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        client.conf.remove_option('identity', 'tenant_id')
        client.conf.set('identity', 'tenant_name', 'tenant_name')
        client.conf.set('identity-feature-enabled', 'api_v3', 'true')
        self.mock_data()
        configs = client._get_keystone_config(client.conf)
        auth_version, auth_url, content = \
            client._generate_keystone_data(configs)
        client._generate_cpid_from_endpoint = MagicMock()

        # Test when the identity ID is None.
        ks3_ID_None = {'token': {'catalog':
                                 [{'type': 'identity', 'id': None}]}}

        @httmock.all_requests
        def keystone_api_v3_mock(url, request):
            return httmock.response(201, ks3_ID_None)
        with httmock.HTTMock(keystone_api_v3_mock):
            client._get_cpid_from_keystone(auth_version, auth_url, content)
            client._generate_cpid_from_endpoint.assert_called_with(auth_url)

        # Test when the catalog is empty.
        ks3_catalog_empty = {'token': {'catalog': []}}
        client._generate_cpid_from_endpoint = MagicMock()

        @httmock.all_requests
        def keystone_api_v3_mock2(url, request):
            return httmock.response(201, ks3_catalog_empty)
        with httmock.HTTMock(keystone_api_v3_mock2):
            client._get_cpid_from_keystone(auth_version, auth_url, content)
            client._generate_cpid_from_endpoint.assert_called_with(auth_url)

        # Test when there is no service catalog.
        ks3_no_catalog = {'token': {}}
        client._generate_cpid_from_endpoint = MagicMock()

        @httmock.all_requests
        def keystone_api_v3_mock3(url, request):
            return httmock.response(201, ks3_no_catalog)
        with httmock.HTTMock(keystone_api_v3_mock3):
            client._get_cpid_from_keystone(auth_version, auth_url, content)
            client._generate_cpid_from_endpoint.assert_called_with(auth_url)

        #Test when catalog has other non-identity services.
        ks3_other_services = {'token': {'catalog': [{'type': 'compute',
                                        'id': 'test-id1'},
                                        {'type': 'identity',
                                         'id': 'test-id2'}]}}
        client._generate_cpid_from_endpoint = MagicMock()

        @httmock.all_requests
        def keystone_api_v3_mock4(url, request):
            return httmock.response(201, ks3_other_services)
        with httmock.HTTMock(keystone_api_v3_mock4):
            cpid = client._get_cpid_from_keystone(auth_version,
                                                  auth_url,
                                                  content)
            self.assertFalse(client._generate_cpid_from_endpoint.called)
            self.assertEqual('test-id2', cpid)

    def test_get_cpid_from_keystone_failure_handled(self):
        """Test that get cpid from keystone API failure handled."""
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        client.conf.set('identity', 'tenant_name', 'tenant_name')
        client.logger.warning = MagicMock()
        client._generate_cpid_from_endpoint = MagicMock()
        self.mock_data()
        configs = client._get_keystone_config(client.conf)
        auth_version, url, content = client._generate_keystone_data(configs)

        @httmock.urlmatch(netloc=r'(.*\.)?127.0.0.1$', path='/v2/tokens')
        def keystone_api_mock(auth_version, url, request):
            return None
        with httmock.HTTMock(keystone_api_mock):
            client._get_cpid_from_keystone(auth_version, url, content)
            client._generate_cpid_from_endpoint.assert_called_with(url)

    def test_generate_cpid_from_endpoint(self):
        """
        Test that an endpoint's hostname is properly hashed.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        cpid = client._generate_cpid_from_endpoint('http://some.url:5000/v2')
        expected = hashlib.md5('some.url').hexdigest()
        self.assertEqual(expected, cpid)

        with self.assertRaises(ValueError):
            client._generate_cpid_from_endpoint('some.url:5000/v2')

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

    def test_upload_prompt(self):
        """
        Test the _upload_prompt method.
        """
        client = rc.RefstackClient(rc.parse_cli_args(self.mock_argv()))

        # When user says yes.
        client._user_query = MagicMock(return_value=True)
        client.post_results = MagicMock()
        client._upload_prompt({'some': 'data'})
        client.post_results.assert_called_with(
            'http://127.0.0.1', {'some': 'data'}, sign_with=None
        )

        # When user says no.
        client._user_query = MagicMock(return_value=False)
        client.post_results = MagicMock()
        client._upload_prompt({'some': 'data'})
        self.assertFalse(client.post_results.called)

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
                '%s' % expected_response)

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
                '%s' % expected_response)

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
        self.mock_data()
        client.get_passed_tests = MagicMock(return_value=[{'name': 'test'}])
        client.logger.info = MagicMock()
        client._save_json_results = MagicMock()
        client.post_results = MagicMock()
        client._get_keystone_config = MagicMock(
            return_value=self.v2_config)
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
        self.mock_data()
        client.get_passed_tests = MagicMock(return_value=['test'])
        client.post_results = MagicMock()
        client._save_json_results = MagicMock()
        client._get_keystone_config = MagicMock(
            return_value=self.v2_config)
        client._get_cpid_from_keystone = MagicMock()
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
        self.mock_data()
        client.get_passed_tests = MagicMock(return_value=['test'])
        client.post_results = MagicMock()
        client._save_json_results = MagicMock()
        client._get_keystone_config = MagicMock(
            return_value=self.v2_config)
        client._get_cpid_from_keystone = MagicMock(
            return_value='test-id')
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
        self.mock_data()
        client.get_passed_tests = MagicMock(return_value=[{'name': 'test'}])
        client._save_json_results = MagicMock()
        client.post_results = MagicMock()
        lp.TestListParser.get_normalized_test_list = MagicMock(
            return_value="/tmp/some-list")
        client._get_keystone_config = MagicMock(
            return_value=self.v2_config)
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
        self.mock_data()
        client.get_passed_tests = MagicMock(return_value=['test'])
        client._save_json_results = MagicMock()
        client._get_keystone_config = MagicMock(
            return_value=self.v2_config)
        client._get_cpid_from_keystone = MagicMock(
            return_value='test-id')
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
        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        self.mock_data()
        client.logger.error = MagicMock()
        client._get_keystone_config = MagicMock(
            return_value=self.v2_config)
        client._get_cpid_from_keystone = MagicMock()
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

    def test_subunit_upload(self):
        """
        Test that the subunit upload command runs as expected.
        """
        upload_file_path = self.test_path + "/.testrepository/0"
        args = rc.parse_cli_args(
            self.mock_argv(command='upload-subunit', priv_key='rsa_key')
            + ['--keystone-endpoint', 'http://0.0.0.0:5000/v2.0']
            + [upload_file_path])
        client = rc.RefstackClient(args)
        client.post_results = MagicMock()
        client.upload_subunit()
        expected_json = {
            'duration_seconds': 0,
            'cpid': hashlib.md5('0.0.0.0').hexdigest(),
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

    def test_set_env_params(self):
        """
        Test that the environment variables are correctly set.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        client._prep_test()
        conf_dir = os.path.abspath(os.path.dirname(self.conf_file_name))
        conf_file = os.path.basename(self.conf_file_name)
        self.assertEqual(os.environ.get('TEMPEST_CONFIG_DIR'), conf_dir)
        self.assertEqual(os.environ.get('TEMPEST_CONFIG'), conf_file)
