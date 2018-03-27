### Installation on macOS

Install [brew](https://brew.sh/)

```
brew install git python3 openssl graphviz
pip3 install pyasn1 pyasn1_modules
git clone https://github.com/johndoe31415/x509sak /usr/local/x509sak
sudo mv x509sak /usr/local/
sudo ln -s /usr/local/x509sak/x509sak.py /usr/local/bin/x509sak
```

Change first line of /usr/local/x509sak/x509sak.py to `#!/usr/bin/env python3`
(Change requested in PR #1)
