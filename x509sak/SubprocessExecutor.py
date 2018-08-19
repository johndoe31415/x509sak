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

class ExecutionResult(object):
	def __init__(self, executor, stdout, stderr, return_code):
		self._executor = executor
		self._stdout = stdout
		self._stderr = stderr
		self._return_code = return_code

	@property
	def stdout(self):
		return self._stdout

	@property
	def stdout_text(self, codec = "utf-8"):
		return self.stdout.decode(codec)

	@property
	def stderr(self):
		return self._stderr

	@property
	def stderr_text(self, codec = "utf-8"):
		return self.stderr.decode(codec)

	@property
	def stdouterr(self):
		return self._stdout + self._stderr

	@property
	def stdouterr_text(self, codec = "utf-8"):
		return self.stdouterr.decode(codec)

	@property
	def return_code(self):
		return self._return_code

	@property
	def successful(self):
		return self.return_code in self._executor.success_return_codes

class SubprocessExecutor(object):
	_verbose = False
	_pause_after_failed_execution = False
	_pause_before_execution = False

	#def __init__(self, cmd, success_return_codes = None, on_failure = "exception", returnval = "stdout", discard_stderr = False, stdin = None, env = None):
	def __init__(self, cmd, success_return_codes = None, on_failure = "exception", stdin = None, env = None):
		assert(on_failure in [ "exception", "pass", "exception-nopause" ])
		self._cmd = cmd
		self._success_return_codes = success_return_codes
		self._on_failure = on_failure
		self._stdin = stdin
		self._env = env

		if self._success_return_codes is None:
			self._success_return_codes = (0, )
		if self._env is None:
			self._env = { }

	@property
	def stdin(self):
		return self._stdin

	@property
	def success_return_codes(self):
		return self._success_return_codes

	@property
	def cmd_str(self):
		return CmdTools.cmdline(self._cmd, self._env)

	def _pre_execution(self):
		if self._verbose or self._pause_before_execution:
			print(self.cmd_str)
		if self._pause_before_execution:
			input("About to execute above command, press RETURN to continue...")

	def _post_execution(self, execution_result):
		if self._verbose:
			success_error = {
				False:	"✖",
				True:	"✓",
			}[execution_result.successful]
			print("%s %3d: %s" % (success_error, execution_result.return_code, self.cmd_str))

			print(execution_result.stdout)
			print()

		# Execution failed.
		if not execution_result.successful:
			if self._on_failure == "exception":
				if self._pause_after_failed_execution:
					print("Execution failed: %s" % (self.cmd_str))
					print("Input: %s" % (self.stdin))
					print("Return code: %d (expected %s)." % (execution_result.return_code, ", ".join("%d" % (code) for code in sorted(self.success_return_codes))))
					print("stdout was:")
					print(execution_result.stdout)
					if len(execution_result.stderr) > 0:
						print("stderr was:")
						print(execution_result.stderr)
					input("Hit ENTER to continue...")
			if self._on_failure in [ "exception", "exception-nopause" ]:
				raise CmdExecutionFailedException("Execution of subprocess failed: %s" % (os.path.basename(self._cmd[0])), execution_result = execution_result)

	def run(self):
		self._pre_execution()
		env = dict(os.environ)
		env.update(self._env)

		proc = subprocess.Popen(self._cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE, stdin = subprocess.PIPE, env = env)
		(stdout, stderr) = proc.communicate(self._stdin)
		execution_result = ExecutionResult(executor = self, stdout = stdout, stderr = stderr, return_code = proc.returncode)

		self._post_execution(execution_result)
		return execution_result

	@classmethod
	def set_verbose(cls):
		cls._verbose = True

	@classmethod
	def pause_after_failed_execution(cls):
		cls._pause_after_failed_execution = True

	@classmethod
	def pause_before_execution(cls):
		cls._pause_before_execution = True
