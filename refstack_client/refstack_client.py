#!/usr/bin/env python
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


"""
Run Tempest and upload results to RefStack.

This module runs the Tempest test suite on an OpenStack environment given a
Tempest configuration file.

"""

import argparse
import binascii
import ConfigParser
import itertools
import json
import logging
import os
import subprocess
import time

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from keystoneclient.v2_0 import client as ksclient2
from keystoneclient.v3 import client as ksclient3
import requests
import requests.exceptions
import six.moves
from subunit_processor import SubunitProcessor
from list_parser import TestListParser
import yaml


def get_input():
    """
    Wrapper for raw_input. Necessary for testing.
    """
    return raw_input().lower()  # pragma: no cover


def read_accounts_yaml(path):
    """Reads a set of accounts from the specified file"""
    with open(path, 'r') as yaml_file:
        accounts = yaml.load(yaml_file)
    return accounts


class RefstackClient:
    log_format = "%(asctime)s %(name)s:%(lineno)d %(levelname)s %(message)s"

    def __init__(self, args):
        '''Prepare a tempest test against a cloud.'''
        self.logger = logging.getLogger("refstack_client")
        self.console_log_handle = logging.StreamHandler()
        self.console_log_handle.setFormatter(
            logging.Formatter(self.log_format))
        self.logger.addHandler(self.console_log_handle)

        self.args = args
        self.tempest_dir = '.tempest'

        if self.args.verbose > 1:
            self.logger.setLevel(logging.DEBUG)
        elif self.args.verbose == 1:
            self.logger.setLevel(logging.INFO)
        else:
            self.logger.setLevel(logging.ERROR)

    def _prep_test(self):
        '''Prepare a tempest test against a cloud.'''

        # Check that the config file exists.
        if not os.path.isfile(self.args.conf_file):
            self.logger.error("Conf file not valid: %s" % self.args.conf_file)
            exit(1)

        # Check that the Tempest directory is an existing directory.
        if not os.path.isdir(self.tempest_dir):
            self.logger.error("Tempest directory given is not a directory or "
                              "does not exist: %s" % self.tempest_dir)
            exit(1)

        self.tempest_script = os.path.join(self.tempest_dir,
                                           'run_tempest.sh')

        self.conf_file = self.args.conf_file
        self.conf = ConfigParser.SafeConfigParser()
        self.conf.read(self.args.conf_file)
        self.tempest_script = os.path.join(self.tempest_dir,
                                           'run_tempest.sh')

    def _prep_upload(self):
        '''Prepare an upload to the RefStack_api'''
        if not os.path.isfile(self.args.file):
            self.logger.error("File not valid: %s" % self.args.file)
            exit(1)

        self.upload_file = self.args.file

    def _get_next_stream_subunit_output_file(self, tempest_dir):
        '''This method reads from the next-stream file in the .testrepository
           directory of the given Tempest path. The integer here is the name
           of the file where subunit output will be saved to.'''
        try:
            subunit_file = open(os.path.join(
                                tempest_dir, '.testrepository',
                                'next-stream'), 'r').read().rstrip()
        except (IOError, OSError):
            self.logger.debug('The .testrepository/next-stream file was not '
                              'found. Assuming subunit results will be stored '
                              'in file 0.')

            # Testr saves the first test stream to .testrepository/0 when
            # there is a newly generated .testrepository directory.
            subunit_file = "0"

        return os.path.join(tempest_dir, '.testrepository', subunit_file)

    def _get_cpid_from_keystone(self, conf_file):
        '''This will get the Keystone service ID which is used as the CPID.'''
        try:
            # Prefer Keystone V3 API if it is enabled
            auth_version = (
                'v3' if (conf_file.has_option('identity-feature-enabled',
                                              'api_v3')
                         and conf_file.getboolean('identity-feature-enabled',
                                                  'api_v3')
                         and conf_file.has_option('identity', 'uri_v3'))
                else 'v2')

            if conf_file.has_option('auth', 'test_accounts_file'):
                account_file = os.path.expanduser(
                    conf_file.get('auth', 'test_accounts_file'))
                if not os.path.isfile(account_file):
                    self.logger.error(
                        'Accounts file not found: %s' % account_file)
                    exit(1)

                accounts = read_accounts_yaml(account_file)
                if not accounts:
                    self.logger.error('Accounts file %s found, '
                                      'but was empty.' % account_file)
                    exit(1)

                account = accounts[0]
                username = account.get('username')
                password = account.get('password')
                tenant_id = account.get('tenant_id')
                tenant_name = account.get('tenant_name')
            else:
                username = conf_file.get('identity', 'username')
                password = conf_file.get('identity', 'password')

                if self.conf.has_option('identity', 'tenant_id'):
                    tenant_id = conf_file.get('identity', 'tenant_id')
                else:
                    tenant_id = None
                    tenant_name = conf_file.get('identity', 'tenant_name')

            args = {
                'insecure': self.args.insecure,
                'username': username,
                'password': password
            }
            if tenant_id:
                args['tenant_id'] = tenant_id
            else:
                args['tenant_name'] = tenant_name

            if auth_version == 'v2':
                args['auth_url'] = conf_file.get('identity', 'uri')
                client = ksclient2.Client(**args)
                token = client.auth_ref
                for service in token['serviceCatalog']:
                    if service['type'] == 'identity':
                        return service['endpoints'][0]['id']
            elif auth_version == 'v3':
                args['auth_url'] = conf_file.get('identity', 'uri_v3')
                if conf_file.has_option('identity', 'domain_name'):
                    args['project_domain_name'] = conf_file.get('identity',
                                                                'domain_name')
                    args['user_domain_name'] = conf_file.get('identity',
                                                             'domain_name')
                if conf_file.has_option('identity', 'region'):
                    args['region_name'] = conf_file.get('identity',
                                                        'region')
                client = ksclient3.Client(**args)
                token = client.auth_ref
                for service in token['catalog']:
                    if service['type'] == 'identity':
                        return service['id']
            else:
                raise ValueError('Auth_version %s is unsupported'
                                 '' % auth_version)

        except ConfigParser.Error as e:
            # Most likely a missing section or option in the config file.
            self.logger.error("Invalid Config File: %s" % e)
            exit(1)

    def _form_result_content(self, cpid, duration, results):
        '''This method will create the content for the request. The spec at
           github.com/openstack/refstack/blob/master/specs/approved/api-v1.md.
           defines the format expected by the API.'''
        content = {}
        content['cpid'] = cpid
        content['duration_seconds'] = duration
        content['results'] = results
        return content

    def _save_json_results(self, results, path):
        '''Save the output results from the Tempest run as a JSON file'''
        file = open(path, "w+")
        file.write(json.dumps(results, indent=4, separators=(',', ': ')))
        file.close()

    def _user_query(self, q):
        """Ask user a query. Return true if user agreed (yes/y)"""
        if self.args.quiet:
            return True
        try:
            inp = six.moves.input(q + ' (yes/y): ')
        except KeyboardInterrupt:
            return
        else:
            return inp.lower() in ('yes', 'y')

    def get_passed_tests(self, result_file):
        '''Get a list of tests IDs that passed Tempest from a subunit file.'''
        subunit_processor = SubunitProcessor(result_file)
        results = subunit_processor.process_stream()
        return results

    def post_results(self, url, content, sign_with=None):
        '''Post the combined results back to the server.'''
        endpoint = '%s/v1/results/' % url
        headers = {'Content-type': 'application/json'}
        data = json.dumps(content)
        self.logger.debug('API request content: %s ' % content)
        if sign_with:
            data_hash = SHA256.new()
            data_hash.update(data.encode('utf-8'))
            with open(sign_with) as key_pair_file:
                try:
                    key = RSA.importKey(key_pair_file.read())
                except (IOError, ValueError) as e:
                    self.logger.info('Error during upload key pair %s'
                                     '' % key_pair_file)
                    self.logger.exception(e)
                    return
            signer = PKCS1_v1_5.new(key)
            sign = signer.sign(data_hash)
            headers['X-Signature'] = binascii.b2a_hex(sign)
            headers['X-Public-Key'] = key.publickey().exportKey('OpenSSH')
        try:
            response = requests.post(endpoint,
                                     data=data,
                                     headers=headers,
                                     verify=not self.args.insecure)
            self.logger.info(endpoint + " Response: " + str(response.text))
        except Exception as e:
            self.logger.info('Failed to post %s - %s ' % (endpoint, e))
            self.logger.exception(e)
            return

        if response.status_code == 201:
            resp = response.json()
            print 'Test results uploaded!\nURL: %s' % resp.get('url', '')

    def test(self):
        '''Execute Tempest test against the cloud.'''
        self._prep_test()
        results_file = self._get_next_stream_subunit_output_file(
            self.tempest_dir)
        cpid = self._get_cpid_from_keystone(self.conf)

        self.logger.info("Starting Tempest test...")
        start_time = time.time()

        # Run the tempest script, specifying the conf file, the flag
        # telling it to use a virtual environment (-V), and the flag
        # telling it to run the tests serially (-t).
        cmd = [self.tempest_script, '-C', self.conf_file, '-V', '-t']

        # If a test list was specified, have it take precedence.
        if self.args.test_list:
            self.logger.info("Normalizing test list...")
            parser = TestListParser(os.path.abspath(self.tempest_dir))
            parser.setup_venv(self.logger.getEffectiveLevel())
            list_file = parser.get_normalized_test_list(self.args.test_list)
            if list_file:
                cmd += ('--', '--load-list', list_file)
            else:
                self.logger.error("Error normalizing passed in test list.")
                exit(1)
        elif 'arbitrary_args' in self.args:
            # Add the tempest test cases to test as arguments. If no test
            # cases are specified, then all Tempest API tests will be run.
            cmd += self.args.arbitrary_args
        else:
            cmd += ['--', "tempest.api"]

        # If there were two verbose flags, show tempest results.
        if self.args.verbose > 1:
            stderr = None
        else:
            # Suppress tempest results output. Note that testr prints
            # results to stderr.
            stderr = open(os.devnull, 'w')

        # Execute the tempest test script in a subprocess.
        process = subprocess.Popen(cmd, stderr=stderr)
        process.communicate()

        # If the subunit file was created, then the Tempest test was at least
        # started successfully.
        if os.path.isfile(results_file):
            end_time = time.time()
            elapsed = end_time - start_time
            duration = int(elapsed)

            self.logger.info('Tempest test complete.')
            self.logger.info('Subunit results located in: %s' % results_file)

            results = self.get_passed_tests(results_file)
            self.logger.info("Number of passed tests: %d" % len(results))

            content = self._form_result_content(cpid, duration, results)

            if self.args.result_tag:
                file_name = os.path.basename(results_file)
                directory = os.path.dirname(results_file)
                file_name = '-'.join([self.args.result_tag, file_name])
                results_file = os.path.join(directory, file_name)

            json_path = results_file + ".json"
            self._save_json_results(content, json_path)
            self.logger.info('JSON results saved in: %s' % json_path)

            # If the user specified the upload argument, then post
            # the results.
            if self.args.upload:
                self.post_results(self.args.url, content,
                                  sign_with=self.args.priv_key)
        else:
            self.logger.error("Problem executing Tempest script. Exit code %d",
                              process.returncode)

    def upload(self):
        '''Perform upload to RefStack URL.'''
        self._prep_upload()
        json_file = open(self.upload_file)
        json_data = json.load(json_file)
        json_file.close()
        if self._user_query('Test results will be uploaded to %s. '
                            'Ok?' % self.args.url):
            self.post_results(self.args.url, json_data,
                              sign_with=self.args.priv_key)

    def yield_results(self, url, start_page=1,
                      start_date='', end_date='', cpid=''):
        endpoint = '%s/v1/results/' % url
        headers = {'Content-type': 'application/json'}
        for page in itertools.count(start_page):
            params = {'page': page}
            for param in ('start_date', 'end_date', 'cpid'):
                if locals()[param]:
                    params.update({param: locals()[param]})
            try:
                resp = requests.get(endpoint, headers=headers, params=params)
                resp.raise_for_status()
            except requests.exceptions.HTTPError as e:
                self.logger.info('Failed to list %s - %s ' % (endpoint, e))
                raise StopIteration
            else:
                resp = resp.json()
                results = resp.get('results', [])
                yield results
                if resp['pagination']['total_pages'] == page:
                    raise StopIteration

    def list(self):
        """Retrieve list with last test results from RefStack."""
        results = self.yield_results(self.args.url,
                                     start_date=self.args.start_date,
                                     end_date=self.args.end_date)
        for page_of_results in results:
            for r in page_of_results:
                print('%s - %s' % (r['created_at'], r['url']))
            try:
                six.moves.input('Press Enter to go to next page...')
            except KeyboardInterrupt:
                return

    def _sign_pubkey(self):
        """Generate self signature for public key"""
        try:
            with open(self.args.priv_key_to_sign) as priv_key_file:
                private_key = RSA.importKey(priv_key_file.read())
        except (IOError, ValueError) as e:
            self.logger.error('Error reading private key %s'
                              '' % self.args.priv_key_to_sign)
            self.logger.exception(e)
            return
        pubkey_filename = '.'.join((self.args.priv_key_to_sign, 'pub'))
        try:
            with open(pubkey_filename) as pub_key_file:
                pub_key = pub_key_file.read()
        except IOError:
            self.logger.error('Public key file %s not found. '
                              'Public key is generated from private one.'
                              '' % pubkey_filename)
            pub_key = private_key.publickey().exportKey('OpenSSH')
        data_hash = SHA256.new()
        data_hash.update('signature'.encode('utf-8'))
        signer = PKCS1_v1_5.new(private_key)
        signature = binascii.b2a_hex(signer.sign(data_hash))
        return pub_key, signature

    def self_sign(self):
        """Generate signature for public key."""
        pub_key, signature = self._sign_pubkey()
        print('Public key:\n%s\n' % pub_key)
        print('Self signature:\n%s\n' % signature)


def parse_cli_args(args=None):

    usage_string = ('refstack-client [-h] <ARG> ...\n\n'
                    'To see help on specific argument, do:\n'
                    'refstack-client <ARG> -h')

    parser = argparse.ArgumentParser(
        description='RefStack-client arguments',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        usage=usage_string
    )

    subparsers = parser.add_subparsers(help='Available subcommands.')

    # Arguments that go with all subcommands.
    shared_args = argparse.ArgumentParser(add_help=False)

    shared_args.add_argument('-v', '--verbose',
                             action='count',
                             help='Show verbose output.')

    shared_args.add_argument('-y',
                             action='store_true',
                             dest='quiet',
                             required=False,
                             help='Assume Yes to all prompt queries')

    # Arguments that go with network-related  subcommands (test, list, etc.).
    network_args = argparse.ArgumentParser(add_help=False)
    network_args.add_argument('--url',
                              action='store',
                              required=False,
                              default=os.environ.get(
                                  'REFSTACK_URL', 'http://refstack.net/api'),
                              type=str,
                              help='RefStack API URL to upload results to. '
                                   'Defaults to env[REFSTACK_URL] or '
                                   'http://refstack.net/api if it is not set '
                                   '(--url http://localhost:8000).')

    network_args.add_argument('-k', '--insecure',
                              action='store_true',
                              dest='insecure',
                              required=False,
                              help='Skip SSL checks while interacting '
                                   'with RefStack API and Keystone endpoint')

    network_args.add_argument('-i', '--sign',
                              type=str,
                              required=False,
                              dest='priv_key',
                              help='Path to private RSA key. '
                                   'OpenSSH RSA keys format supported')

    # Upload command
    parser_upload = subparsers.add_parser(
        'upload', parents=[shared_args, network_args],
        help='Upload an existing result file.'
    )

    parser_upload.add_argument('file',
                               type=str,
                               help='Path of JSON results file.')

    parser_upload.set_defaults(func="upload")

    # Test command
    parser_test = subparsers.add_parser(
        'test', parents=[shared_args, network_args],
        help='Run Tempest against a cloud.')

    parser_test.add_argument('-c', '--conf-file',
                             action='store',
                             required=True,
                             dest='conf_file',
                             type=str,
                             help='Path of the Tempest configuration file to '
                                  'use.')

    parser_test.add_argument('-r', '--result-file-tag',
                             action='store',
                             required=False,
                             dest='result_tag',
                             type=str,
                             help='Specify a string to prefix the result '
                                  'file with to easier distinguish them. ')

    parser_test.add_argument('--test-list',
                             action='store',
                             required=False,
                             dest='test_list',
                             type=str,
                             help='Specify the file path or URL of a test '
                                  'list text file. This test list will '
                                  'contain specific test cases that should '
                                  'be tested.')

    parser_test.add_argument('-u', '--upload',
                             action='store_true',
                             required=False,
                             help='After running Tempest, upload the test '
                                  'results to the default RefStack API server '
                                  'or the server specified by --url.')

    # This positional argument will allow arbitrary arguments to be passed in
    # with the usage of '--'.
    parser_test.add_argument('arbitrary_args',
                             nargs=argparse.REMAINDER,
                             help='After the first "--", you can pass '
                                  'arbitrary arguments to the Tempest runner. '
                                  'This can be used for running specific test '
                                  'cases or test lists. Some examples are: '
                                  '-- tempest.api.compute.images.test_list_'
                                  'image_filters '
                                  '-- --load-list /tmp/test-list.txt')
    parser_test.set_defaults(func="test")

    # List command
    parser_list = subparsers.add_parser(
        'list', parents=[shared_args, network_args],
        help='List last results from RefStack')
    parser_list.add_argument('--start-date',
                             required=False,
                             dest='start_date',
                             type=str,
                             help='Specify a date for start listing of '
                                  'test results '
                                  '(e.g. --start-date "2015-04-24 01:23:56").')
    parser_list.add_argument('--end-date',
                             required=False,
                             dest='end_date',
                             type=str,
                             help='Specify a date for end listing of '
                                  'test results '
                                  '(e.g. --end-date "2015-04-24 01:23:56").')
    parser_list.set_defaults(func='list')

    # Sign command
    parser_sign = subparsers.add_parser(
        'sign', parents=[shared_args],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help='Generate signature for public key.')
    parser_sign.add_argument('priv_key_to_sign',
                             type=str,
                             help='Path to private RSA key. '
                                  'OpenSSH RSA keys format supported')

    parser_sign.set_defaults(func='self_sign')

    return parser.parse_args(args=args)
