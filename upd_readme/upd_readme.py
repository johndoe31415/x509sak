#!/usr/bin/python3
#
#
import os
import subprocess
from Patcher import Patcher

def _get_output(cmd):
	proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
	(stdout, stderr) = proc.communicate()
	stdout = stdout.decode().rstrip("\r\n").lstrip("\r\n")
	return stdout

os.chdir("..")
patcher = Patcher("README.md", filetype = "markdown")


stdout = _get_output([ "./x509sak.py" ])
text = "\n```\n$ ./x509sak.py\n%s\n```\n" % (stdout)
patcher.patch("summary", text)

commands = [ "buildchain", "graph", "findcrt", "createca", "createcsr", "signcsr", "revokecrt", "genbrokenrsa", "dumpkey", "forgecert" ]
for command in commands:
	stdout = _get_output([ "./x509sak.py", command, "--help" ])
	text = "\n```\n%s\n```\n" % (stdout)
	patcher.patch("cmd-%s" % (command), text)

