#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2018 Johannes Bauer
#
#	This file is part of x509sak.
#
#	x509sak is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	x509sak is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with x509sak; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import os
import subprocess
from x509sak.Tools import CmdTools
from x509sak.Exceptions import CmdExecutionFailedException

class SubprocessExecutor(object):
	_verbose = False
	_pause_after_failed_execution = False
	_pause_before_execution = False

	@classmethod
	def run(cls, cmd, success_retcodes = None, on_failure = "exception", return_stdout = False, discard_stderr = False, stdin = None, env = None):
		assert(on_failure in [ "exception", "pass" ])
		cmd_str = CmdTools.cmdline(cmd, env)
		if env is not None:
			full_env = dict(os.environ)
			full_env.update(env)
		else:
			full_env = None

		if success_retcodes is None:
			success_retcodes = [ 0 ]

		if cls._verbose or cls._pause_before_execution:
			print(cmd_str)
		if cls._pause_before_execution:
			input("About to execute above command, press RETURN to continue...")

		if discard_stderr:
			stderr = subprocess.PIPE
		else:
			stderr = subprocess.STDOUT
		proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = stderr, stdin = subprocess.PIPE, env = full_env)
		(stdout, stderr) = proc.communicate(stdin)

		success = proc.returncode in success_retcodes
		if cls._verbose:
			if success:
				print("Successful: %s" % (cmd_str))
			else:
				print("Failed: %s" % (cmd_str))
				print(stdout.decode())
				print()

		# Execution failed.
		if (not success):
			if on_failure == "exception":
				if cls._pause_after_failed_execution:
					print("Execution failed: %s" % (cmd_str))
					print("Input: %s" % (stdin))
					print("Return code: %d (expected one of %s)." % (proc.returncode, str(success_retcodes)))
					print("stdout was:")
					print(stdout.decode())
					if (stderr is not None) and (len(stderr) > 0):
						print("stderr was:")
						print(stderr.decode())
					input("Hit ENTER to continue...")
				raise CmdExecutionFailedException("Execution of command failed: %s" % (cmd_str))

		if return_stdout:
			return (success, stdout)
		else:
			return success

	@classmethod
	def set_verbose(cls):
		cls._verbose = True

	@classmethod
	def pause_after_failed_execution(cls):
		cls._pause_after_failed_execution = True

	@classmethod
	def pause_before_execution(cls):
		cls._pause_before_execution = True
