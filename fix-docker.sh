sudo apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg-agent \
  software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88

sudo add-apt-repository \
  "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) \
  stable"

curl -fsSL https://apt.dockerproject.org/gpg | sudo apt-key add -
sudo apt-add-repository "deb https://apt.dockerproject.org/repo ubuntu-$(lsb_release -cs) main"
sudo apt-get update -y 

sudo apt-get install -y docker-ce=5:18.09.1~3-0~ubuntu-xenial --allow-downgrades
