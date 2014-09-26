refstack-client
===============

refstack-client is a command line utility that allows you to execute Tempest
test runs based on configurations you specify.  When finished running Tempest
it sends the passed test data back to the Refstack API server.

**Usage (Ubuntu)**

We've created an "easy button" for Ubuntu.

$ sh ./setup_ubuntu_env.sh

**Start testing**

1. Prepare a tempest configuration file that is customized to your cloud
   environment.
2. Change the directory to the refstack-client directory
   (i.e. cd ~/refstack-client).
3. Source to use the correct Python environment.

   source test_runner/bin/activate

4. Execute test by typing:

   ./refstack-client -c "Path of the tempest configuration file to use"

   **Note:**

   a. Adding -v option will show the summary output.
   b. Adding -vv option will show the Tempest test result output.
   c. Adding -t option will only test a particular test case or a test group.
      This option can be used for quick verification of the target test cases
      (i.e. -t "tempest.api.identity.admin.test_roles").
   d. Adding --url option will upload the test results to a Refstack API server
      instead of the default Refstack API server.
   e. Adding --offline option will not upload the test results.
