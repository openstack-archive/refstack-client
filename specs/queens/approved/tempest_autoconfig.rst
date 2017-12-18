===============================
Automatic Tempest Configuration
===============================

Problem Description
===================

A big barrier of entry to running the Interop tests is the fact that
configuring tempest is done by the person running the tests and it requires
knowledge of tempest that an end user of a cloud may not have.

Proposed solution
=================

To make running the Interop tests easier for people that don't know anything
about tempest, the tempest.conf can be created automatically by the
refstack-client and provide an example tempest.conf populated with values from
the target cloud.

.. code-block:: bash

    $ source openstackrc file
    $ refstack-client config -h
          --os-cloud <name of the cloud> # Using specific cloud.yaml files
          --use-test-accounts <Use accounts from accounts.yaml>
    $ # we can also use discover-tempest-config to generate tempest.conf
    $ discover-tempest-config --create

Data model impact
-----------------

None

REST API impact
---------------

None

Security impact
---------------

* A basic refstack-client assumption is non-admin credentials. If a feature
  is not discovered by the tool due to lack of permissions, the tool should
  be able to handle proper exceptions by notifying proper message and continue
  processing.

Performance Impact
------------------

None

Other Deployer Impact
---------------------

One of the main goals of this project is to create a script that can be
consumed by any project needing to configure tempest. It is not going to install
any tempest plugins.

Developer impact
----------------

The tool should be generic so that it can be used as a python dependency so
that other projects can benefit from it.

Implementation
==============

Assignee(s)
-----------

Primary assignee:
* Chandan Kumar (chandankumar)
* Martin Kopec (martinkopec)
* Arx Cruz (arxcruz)
* Luigi Toscano (tosky)

Other contributors:

 TBD

Work Items
==========

- Refactor the python-tempestconf code to auto-generate the required tempest.conf for running interop tests using non-admin accounts.
- Implement `refstack-client config` in order to integrate with refstack.
- Add respective CI jobs to test the `refstack-client config` by running Interop tests.
- Add proper info message as a feature is not getting created on how to create it.
  For example: If glance image is not getting uploaded, provide proper commands on how to upload manually.
- Add proper documentation stating what configurations are getting generated and how to use them.

Dependencies
============

- Existing script: https://git.openstack.org/cgit/openstack/python-tempestconf

Testing
=======

The python-tempestconf project has sufficient testing, and that the
refstack-client can depend on upstream testing of the dependent product.

Documentation Impact
====================

Documentation will be added to the client and readme files that describes
how to use the configuration discovery.

References
==========

- Launchpad blueprint: https://blueprints.launchpad.net/refstack/+spec/tempest-config-script
- Pike PTG refstack etherpad: https://etherpad.openstack.org/p/refstack-pike-ptg
- Queens PTG config script discussion etherpad: https://etherpad.openstack.org/p/InteropDenver2017PTG_TempestAutoconfig
