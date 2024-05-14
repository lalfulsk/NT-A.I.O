sudo apt update && \
sudo apt install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget && \
wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz && \
tar -xf Python-2.7.18.tgz && \
cd Python-2.7.18 && \
./configure --enable-optimizations --prefix=/usr/local && \
sudo make altinstall && \
cd .. && \
rm -rf Python-2.7.18 Python-2.7.18.tgz && \
sudo ln -sf /usr/local/bin/python2.7 /usr/bin/python
