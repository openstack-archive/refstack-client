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
import ConfigParser
import logging
import os
import subprocess
import tempfile

import mock
from mock import MagicMock
import unittest

import refstack_client.refstack_client as rc


class TestRefstackClient(unittest.TestCase):
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
        Build argv for test
        :param conf_file_name: Configuration file name
        :param verbose: verbosity level
        :return: argv
        """
        if conf_file_name is None:
            conf_file_name = self.conf_file_name
        argv = ['-c', conf_file_name,
                '--tempest-dir', self.test_path,
                '--test-cases', 'tempest.api.compute',
                '--url', '0.0.0.0']
        if verbose:
            argv.append(verbose)
        return argv

    def setUp(self):
        """
        Test case setup
        """
        logging.disable(logging.CRITICAL)
        self.mock_tempest_process = MagicMock(name='tempest_runner')
        self.mock_popen = self.patch(
            'refstack_client.refstack_client.subprocess.Popen',
            return_value=self.mock_tempest_process
        )
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
        self.test_path = os.path.dirname(os.path.realpath(__file__))
        self.conf_file_name = '%s/refstack-client.test.conf' % self.test_path

    def test_verbose(self):
        """
        Test different verbosity levels
        """
        args = rc.parse_cli_args(self.mock_argv())
        client = rc.RefstackClient(args)
        self.assertEqual(client.logger.level, logging.ERROR)

        args = rc.parse_cli_args(self.mock_argv(verbose='-v'))
        client = rc.RefstackClient(args)
        self.assertEqual(client.logger.level, logging.INFO)

        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        self.assertEqual(client.logger.level, logging.DEBUG)

    def test_no_conf_file(self):
        """
        Test not existing configuration file
        """
        args = rc.parse_cli_args(self.mock_argv(conf_file_name='ptn-khl'))
        self.assertRaises(SystemExit, rc.RefstackClient, args)

    def test_run_with_default_config(self):
        """
        Test run with default configuration.
        admin_tenant_id is set in configuration.
        """
        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        client.run()
        self.mock_popen.assert_called_with(
            ('%s/run_tempest.sh' % self.test_path, '-C', self.conf_file_name,
             '-N', '-t', '--', 'tempest.api.compute'),
            stderr=None
        )
        self.ks_client_builder.assert_called_with(
            username='admin', tenant_id='admin_tenant_id',
            password='test', auth_url='0.0.0.0:35357'
        )
        self.assertEqual('test-id', client.cpid)

    def test_run_with_admin_tenant_name(self):
        """
        Test run with admin default configuration.
        admin_tenant_name is set in configuration.
        """
        base_conf = ConfigParser.SafeConfigParser()
        base_conf.read(self.conf_file_name)
        base_conf.remove_option('identity', 'admin_tenant_id')
        base_conf.set('identity', 'admin_tenant_name', 'admin_tenant_name')
        test_conf = tempfile.NamedTemporaryFile()
        base_conf.write(test_conf)
        test_conf.flush()
        args = rc.parse_cli_args(self.mock_argv(conf_file_name=test_conf.name,
                                                verbose='-vv'))
        client = rc.RefstackClient(args)
        client.run()
        self.ks_client_builder.assert_called_with(
            username='admin', tenant_name='admin_tenant_name',
            password='test', auth_url='0.0.0.0:35357'
        )
        self.assertEqual('test-id', client.cpid)

    def test_check_admin_tenant(self):
        """
        Test exit under absence information about admin tenant info
        """
        base_conf = ConfigParser.SafeConfigParser()
        base_conf.read(self.conf_file_name)
        base_conf.remove_option('identity', 'admin_tenant_id')
        test_conf = tempfile.NamedTemporaryFile()
        base_conf.write(test_conf)
        test_conf.flush()
        args = rc.parse_cli_args(self.mock_argv(conf_file_name=test_conf.name,
                                                verbose='-vv'))
        self.assertRaises(SystemExit, rc.RefstackClient, args)

    def test_failed_run(self):
        """
        Test failed tempest run
        """
        self.mock_tempest_process.communicate = MagicMock(
            side_effect=subprocess.CalledProcessError(returncode=1,
                                                      cmd='./run_tempest.sh')
        )
        args = rc.parse_cli_args(self.mock_argv(verbose='-vv'))
        client = rc.RefstackClient(args)
        self.assertEqual(client.logger.level, logging.DEBUG)
        client.run()
