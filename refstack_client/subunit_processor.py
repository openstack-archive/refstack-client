# Copyright 2014 IBM Corp.
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

import os
import re
import subunit
import testtools
import unittest


class TempestSubunitTestResultPassOnly(testtools.TestResult):
    """Class to process subunit stream.

       This class maintains a list of test IDs that pass.
    """

    def __init__(self, stream, descriptions, verbosity):
        """Initialize with super class signature."""
        super(TempestSubunitTestResultPassOnly, self).__init__()
        self.results = []

    def addSuccess(self, testcase):
        """Overwrite super class method for additional data processing."""
        super(TempestSubunitTestResultPassOnly, self).addSuccess(testcase)
        # Remove any [] and () from the test ID before appending it.
        self.results.append(
            {'name': re.sub('[\(\[].*[\]\)]', '', testcase.id())}
        )

    def get_results(self):
        return self.results


class SubunitProcessor():
    """A class to replay subunit data from a stream."""

    def __init__(self, in_stream,
                 result_class=TempestSubunitTestResultPassOnly):
        self.in_stream = in_stream
        self.result_class = result_class

    def process_stream(self):
        """Read and process subunit data from a stream."""
        with open(self.in_stream, 'r') as fin:
            test = subunit.ProtocolTestCase(fin)
            runner = unittest.TextTestRunner(stream=open(os.devnull, 'w'),
                                             resultclass=self.result_class)

            # Run (replay) the test from subunit stream.
            test_result = runner.run(test)
            return test_result.get_results()
