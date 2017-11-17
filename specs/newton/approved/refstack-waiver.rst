=============================================================
Defcore waiver for additional properties on Nova API response
=============================================================

Launchpad blueprint: https://blueprints.launchpad.net/refstack/+spec/refstack-waiver

Defcore waiver: https://review.openstack.org/#/c/333067/

Defcore committee approved above waiver which allows vendors who are using the
Nova 2.0 API with additional properties to disable strict response checking
when testing products for the OpenStack Powered program in 2016.

This spec defines the changes needed for refstack-client to optionally bypass
Tempest strict validation.

Problem description
===================

Vendors need an automated way to apply the waiver. The proposed method is to
run Tempest from the RefStack client, identify tests that fail because of
strict response checking, and rerun those tests with strict checking disabled.

APIs and test cases using the waiver must be clearly identified.

Proposed change
===============

1. Workflow

- Vendor run Tempest suite as usual: via refstack-client test, ostestr, testr
  or with any other test runner. Some test cases failed due to additional
  properties in Nova response.

- Vendor have the subunit test results file from the Tempest test execution.

- Vendor have the Tempest configuration file.

- Vendor rerun failed test cases by running ``refstack-client bypass-extras``
  command. Command identifies failed test cases, disables Tempest strict
  validations, rerun test cases, and enables strict validations again.

.. code-block:: bash

   $ refstack-client bypass-extras --subunit-file <results> --conf-file <tempest-conf-file>

- Output of bypass-extras command is a zip bundle containing the following
  files:

  - tests_list - List of failed test cases due to additional properties.

  - patched_schemas - List of tempest schemas which value was set to True
    (to allow additional properties).

  - api_details - API call details from each failed test case (due to
    additional properties).

  - rerun_test_results - The subunit result file for the re-run test cases.

  - combined_test_results.json - The Refstack JSON file with the combined
    passed TCs from both initial and rerun subunit files.

2. Implement "bypass-extras" Refstack command:
Assume Tempest test suite was run independently.
Subunit test results and Tempest configuration files are available.

*bypass-extras* command is the helper tool for vendors to bypass the strict
validation of additional properties in Tempest. Process steps and
implementation details are explained on step 3.

.. code-block:: bash

    $ refstack-client --help

    usage: refstack-client [-h] <ARG> ...
    ...
        bypass-extras    Apply Defcore waiver to identify additional properties
                         on Nova API response. Re-runs failed test cases
                         without Tempest strict response validations.

    $ refstack-client bypass-extras --help

    usage: refstack-client [-h] <ARG> ...

    To see help on specific argument, do:
    refstack-client <ARG> -h waiver
       [-h] [-s | -v] [-y] [--url URL] [-k] [-i PRIV_KEY] file

    optional arguments:
        -h, --help          Show this help message and exit
        -s, --silent        Suppress output except warnings and errors.
        -v, --verbose       Show verbose output.
        -y                  Assume Yes to all prompt queries
        --subunit-file      Path to subunit test result file.
        -c, --conf-file     Path of the Tempest configuration file to use.

3. Flow for ``bypass-extras`` command.

Having as input a subunit test results file and a Tempest configuration file:

3.1 Find failed test cases and its details

Integrate code from find_additional_properties.py into Refstack-client to
analyze subunit stream (from input results file). Find failed test cases
due to additional properties in the response. Reconstruct the tempest schema
causing the test case failure. Run subunit-describe-calls
filter command to get test cases API call details.

Input: subunit-results

Output files:

- tests_list - List of failed test cases due to additional properties.

- patched_schemas - List of tempest schemas causing errors

- api_details - API calls from each test case.

3.2 Patch Tempest:

Create patch for .tempest virtual environment which lives under refstack-client
installation.

- Modify tempest/lib/api_schema/response/compute/v2_1/__init__.py:

  - Import module where schema lives.

  - Set schema addtionalProperties key to True so that additional properties
    are accepted - bypass strict validation.

3.3 Rerun failed test cases using patched refstack-client .tempest environment

Use tests_list as withelist for ostestr in order to re-run failed test cases.

.. code-block:: bash
   ostestr --serial -w test_list

Input: test_list and conf-file files.

Output: rerun_test_results subunit file

3.4 Remove Tempest patch

Regardless of previous steps outcome, unpatching Tempest step will be
attempted.

Clean __init__.py by opening with access mode 'w'

3.5 Create refstack JSON format files

Transform subunit result files - The one provided as input and the rerun
test results - into a combined refstack JSON format.

Input: initial_results_file, rerun_test_results files.

Output: combined_test_results.json files.

3.6 Create zip bundle

Alternatives
------------

- Add additional property to Tempest config file

- For Tempest patch
  Comment the validate_response call by looking into the service_client.py file
  for the corresponding method (search through code files).

- Manual process
   Products applying for the OpenStack Powered Trademark in 2016 may
   request the waiver by submitting subunit data from their Tempest run
   that can be manually analyzed by the `find_additional_properties.py` script
   from the DefCore repository. This script will identify tests that
   failed because of additional properties. The vendor will then need
   to manually modify tempest-lib to remove additional checks on the impacted
   APIs.

Data model impact
-----------------

None

REST API impact
---------------

None

Security impact
---------------

None

Notifications impact
--------------------

None

Other end user impact
---------------------

None

Performance Impact
------------------

None

Other deployer impact
---------------------

None

Developer impact
----------------

None

Implementation
==============

Assignee(s)
-----------

Primary assignee:

 luz-cazares

Other contributors:

 Chris Hoge

Work Items
----------

- Add *bypass-extras* command to refstack-client.
- Integrate find_additional_properties code
- Method to call subunit-describe-calls filter
- Implement JSON schema gathering from test exception
- Implement Tempest patch
- Implement Tempest unpatch
- Create zip bundle with file results
- Add *bypass-extras* command usage documentation

Dependencies
============

None

Testing
=======

Add unit testing for the new command, verify expected outcomes are met.

Documentation Impact
====================

Add refstack-client bypass-extras  usage information under refstack-client/
README.rst


References
==========

None
