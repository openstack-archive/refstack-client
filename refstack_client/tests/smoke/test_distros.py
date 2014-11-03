import os
import subprocess
import unittest


def get_project_path():
    path = os.path.dirname(os.path.realpath(__file__))
    while 'setup.py' not in os.listdir(path):
        path = os.path.realpath(os.path.join(path, '..'))
    return path


class TestSequenceFunctions(unittest.TestCase):
    scp_command = ('scp %s:/opt/stack/tempest/etc/'
                   'tempest.conf %s')
    pull_command = ('docker pull %s')
    test_command = ('docker run -t -v %s:/refstack-client -w /refstack-client/'
                    'refstack_client/tests/smoke --rm %s ./run_in_docker')

    def run_test(self, distro):
        subprocess.check_call(self.pull_command % distro, shell=True)
        subprocess.check_call(self.test_command % (get_project_path(), distro),
                              shell=True)

    def setUp(self):
        devstack_host = os.environ.get('DEVSTACK_HOST', None)
        self.assertIsNotNone(devstack_host)
        subprocess.check_call(
            self.scp_command % (devstack_host, get_project_path()),
            shell=True
        )

    def test_ubuntu_14(self):
        distro_image = 'ubuntu:12.04'
        self.run_test(distro_image)

    def test_ubuntu_12(self):
        distro_image = 'ubuntu:14.04'
        self.run_test(distro_image)

    def test_centos6(self):
        distro_image = 'centos:centos6'
        self.run_test(distro_image)

    def test_centos7(self):
        distro_image = 'centos:centos7'
        self.run_test(distro_image)

    def test_fedora_21(self):
        distro_image = 'fedora:21'
        self.run_test(distro_image)

    def test_opensuse_13(self):
        # offcial opensuse image has outdated certificates
        # we can't use it while this issue isn't fixed
        distro_image = 'opensuse/13.2'
        self.run_test(distro_image)

if __name__ == '__main__':
    unittest.main()
