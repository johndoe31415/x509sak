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

import subprocess
from x509sak.Tools import CmdTools

class SubprocessExecutor(object):
	_verbose = False
	_pause_after_failed_execution = False

	@classmethod
	def run(cls, cmd, success_retcodes = None, exception_on_failure = True, return_stdout = False, discard_stderr = False, stdin = None):
		if success_retcodes is None:
			success_retcodes = [ 0 ]

		if cls._verbose:
			print(CmdTools.cmdline(cmd))

		if discard_stderr:
			stderr = subprocess.PIPE
		else:
			stderr = subprocess.STDOUT
		proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = stderr, stdin = subprocess.PIPE)
		(stdout, stderr) = proc.communicate(stdin)

		success = proc.returncode in success_retcodes
		if cls._verbose:
			if success:
				print("Successful: %s" % (CmdTools.cmdline(cmd)))
			else:
				print("Failed: %s" % (CmdTools.cmdline(cmd)))
				print(stdout.decode())
				print()

		# Execution failed.
		if (not success) and exception_on_failure:
			if cls._pause_after_failed_execution:
				print("Execution failed: %s" % (CmdTools.cmdline(cmd)))
				print("Input: %s" % (stdin))
				print("Return code: %d (expected one of %s)." % (proc.returncode, str(success_retcodes)))
				print("stdout was:")
				print(stdout.decode())
				if (stderr is not None) and (len(stderr) > 0):
					print("stderr was:")
					print(stderr.decode())
				input("Hit ENTER to continue...")
			raise Exception("Execution of command failed: %s" % (CmdTools.cmdline(cmd)))

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
