# insure base requirements are installed
sudo apt-get install -y git python-pip wget unzip
sudo apt-get install -y libxml2-dev libxslt-dev lib32z1-dev python2.7-dev libssl-dev
sudo apt-get install -y libsasl2-dev libffi-dev
sudo pip install virtualenv

# If we've already created it, source it. If not, start and then source it.
if [ ! -d test_runner ]; then
  virtualenv test_runner
fi

source test_runner/bin/activate

pip install -r requirements.txt
