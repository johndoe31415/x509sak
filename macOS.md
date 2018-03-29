### Installation on macOS

Install [brew](https://brew.sh/)

```
brew install git python3 openssl graphviz
pip3 install pyasn1 pyasn1_modules
git clone https://github.com/johndoe31415/x509sak
sudo mv x509sak /usr/local/
sudo chown -R root:admin /usr/local/x509sak
sudo ln -s /usr/local/x509sak/x509sak.py /usr/local/bin/x509sak
```
