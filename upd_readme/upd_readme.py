#!/usr/bin/python3
#
#
import os
import re
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

commands = [ ]
command_re = re.compile("Begin of cmd-(?P<cmdname>[a-z]+)")
for match in command_re.finditer(patcher.read()):
	cmdname = match.groupdict()["cmdname"]
	commands.append(cmdname)

for command in commands:
	stdout = _get_output([ "./x509sak.py", command, "--help" ])
	text = "\n```\n%s\n```\n" % (stdout)
	patcher.patch("cmd-%s" % (command), text)

