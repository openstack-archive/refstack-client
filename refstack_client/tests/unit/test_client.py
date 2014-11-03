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

import logging
import json
import os
import tempfile
import subprocess

import mock
from mock import MagicMock
import unittest

import refstack_client.refstack_client as rc


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

    def mock_argv(self, conf_file_name=None, verbose=None):
        """
        Build argv for test.
        :param conf_file_name: Configuration file name
        :param verbose: verbosity level
        :return: argv
        """
        if conf_file_name is None:
            conf_file_name = self.conf_file_name
        argv = ['test',
                '-c', conf_file_name,
                '--test-cases', 'tempest.api.compute',
                '--url', '0.0.0.0']
        if verbose:
            argv.append(verbose)
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
        expected = ['tempest.passed.test']
        self.assertEqual(expected, results)

    def test_run_tempest(self):
        """
        Test that the test command will run the tempest script using the
        default configuration.
        """
        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        mock_popen = self.patch(
            'refstack_client.refstack_client.subprocess.Popen',
            return_value=MagicMock(returncode=0))
        self.mock_keystone()
        client.get_passed_tests = MagicMock(return_value=['test'])
        client.post_results = MagicMock()
        client._save_json_results = MagicMock()
        client.test()
        mock_popen.assert_called_with(
            ('%s/run_tempest.sh' % self.test_path, '-C', self.conf_file_name,
             '-V', '-t', '--', 'tempest.api.compute'),
            stderr=None
        )

        expected_content = {'duration_seconds': mock.ANY,
                            'cpid': 'test-id',
                            'results': ['test']}
        client.post_results.assert_called_with('0.0.0.0', expected_content)

    def test_run_tempest_offline(self):
        """
        Test that the test command will run the tempest script in offline mode.
        """
        argv = self.mock_argv(verbose='-vv')
        argv.append('--offline')
        args = rc.parse_cli_args(argv)
        client = rc.RefstackClient(args)
        client.tempest_dir = self.test_path
        mock_popen = self.patch(
            'refstack_client.refstack_client.subprocess.Popen',
            return_value=MagicMock(returncode=0))
        self.mock_keystone()
        client.get_passed_tests = MagicMock(return_value=['test'])
        client.post_results = MagicMock()
        client._save_json_results = MagicMock()
        client.test()
        mock_popen.assert_called_with(
            ('%s/run_tempest.sh' % self.test_path, '-C', self.conf_file_name,
             '-V', '-t', '--', 'tempest.api.compute'),
            stderr=None
        )

        # The method post_results should not be called if --offline was
        # specified.
        self.assertFalse(client.post_results.called)

    def test_run_tempest_no_conf_file(self):
        """
        Test when a nonexistent configuration file is passed in.
        """
        args = rc.parse_cli_args(self.mock_argv(conf_file_name='ptn-khl'))
        client = rc.RefstackClient(args)
        self.assertRaises(SystemExit, client.test)

    def test_run_tempest_nonexisting_directory(self):
        """
        Test when a nonexistent Tempest directory is passed in.
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        self.assertRaises(SystemExit, client.test)

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
        args = rc.parse_cli_args(['upload', upload_file_path,
                                  '--url', 'http://api.test.org'])
        client = rc.RefstackClient(args)

        client.post_results = MagicMock()
        client.upload()
        expected_json = {'duration_seconds': 0,
                         'cpid': 'test-id',
                         'results': ['tempest.passed.test']}

        client.post_results.assert_called_with('http://api.test.org',
                                               expected_json)

    def test_upload_nonexisting_file(self):
        """
        Test that the upload file does not exist
        """
        upload_file_path = self.test_path + "/.testrepository/foo.json"
        args = rc.parse_cli_args(['upload', upload_file_path,
                                  '--url', 'http://api.test.org'])
        client = rc.RefstackClient(args)
        self.assertRaises(SystemExit, client.upload)

    def _set_mocks_for_setup(self):
        """
        Setup mocks for testing setup command in positive case
        """
        env = dict()
        env['args'] = rc.parse_cli_args(['setup', '-r', 'havana-eol',
                                         '--tempest-dir', '/tmp/tempest'])
        env['raw_input'] = self.patch(
            'refstack_client.refstack_client.get_input',
            return_value='yes'
        )
        env['exists'] = self.patch(
            'refstack_client.refstack_client.os.path.exists',
            return_value=True
        )
        env['rmtree'] = self.patch(
            'refstack_client.refstack_client.shutil.rmtree',
            return_value=True
        )
        env['test_commit_sha'] = '42'
        env['tag'] = MagicMock(
            **{'commit.hexsha': env['test_commit_sha']}
        )
        env['tag'].configure_mock(name='havana-eol')
        env['git.reset'] = MagicMock()
        env['repo'] = MagicMock(
            tags=[env['tag']],
            **{'git.reset': env['git.reset']}
        )
        self.patch(
            'refstack_client.refstack_client.git.Repo.clone_from',
            return_value=env['repo']
        )
        env['os.chdir'] = self.patch(
            'refstack_client.refstack_client.os.chdir'
        )
        env['subprocess.check_output'] = self.patch(
            'refstack_client.refstack_client.subprocess.check_output',
            return_value='Ok!'
        )
        return env

    def _check_mocks_for_setup(self, env):
        """
        Check mocks after successful run 'setup' command
        """
        env['exists'].assert_called_once_with('/tmp/tempest')
        env['rmtree'].assert_called_once_with('/tmp/tempest')
        env['git.reset'].assert_called_once_with(
            env['test_commit_sha'], hard=True
        )
        env['os.chdir'].assert_has_calls([mock.call('/tmp/tempest'),
                                          mock.call(os.getcwd())])
        env['subprocess.check_output'].assert_has_calls([
            mock.call(['virtualenv', '.venv'],
                      stderr=subprocess.STDOUT),
            mock.call(['.venv//bin//pip', 'install', '-r', 'requirements.txt'],
                      stderr=subprocess.STDOUT)
        ])
