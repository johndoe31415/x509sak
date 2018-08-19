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
from x509sak.HexDump import HexDump

class ExecutionResult(object):
	def __init__(self, executor, stdout, stderr, return_code):
		self._executor = executor
		self._stdout = stdout
		self._stderr = stderr
		self._return_code = return_code

	@property
	def executor(self):
		return self._executor

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

	def _dump_data(self, text, bin_data):
		print("%s (%d bytes):" % (text, len(bin_data)))
		try:
			text_data = bin_data.decode("utf-8")
			print(text_data)
		except UnicodeDecodeError:
			HexDump().dump(bin_data)

	def dump(self):
		success_error_str = {
			False:	"✖",
			True:	"✓",
		}[self.successful]
		success_return_codes = ", ".join("%d" % (code) for code in sorted(self.executor.success_return_codes))
		print("%s %3d (OK = %s): %s" % (success_error_str, self.return_code, success_return_codes, self.executor.cmd_str))
		if (self.executor.stdin is None) or (len(self.executor.stdin) == 0):
			print("No stdin.")
		else:
			self._dump_data("stdin", self.executor.stdin)
		if len(self.stdout) == 0:
			print("No stdout.")
		else:
			self._dump_data("stdout", self.stdout)
		if len(self.stderr) == 0:
			print("No stderr.")
		else:
			self._dump_data("stderr", self.stderr)

class SubprocessExecutor(object):
	_failed_verbose = False
	_all_verbose = False
	_pause_after_failed_execution = False
	_pause_before_execution = False

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
		if self._all_verbose or self._pause_before_execution:
			print(self.cmd_str)
		if self._pause_before_execution:
			input("About to execute above command, press RETURN to continue...")

	def _post_execution(self, execution_result):
		dumped = False
		if self._all_verbose or (self._failed_verbose and (not execution_result.successful) and (self._on_failure != "pass")):
			dumped = True
			execution_result.dump()

		# Execution failed.
		if not execution_result.successful:
			if self._on_failure == "exception":
				if self._pause_after_failed_execution:
					if not dumped:
						# Don't output this twice.
						execution_result.dump()
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
	def set_failed_verbose(cls):
		cls._failed_verbose = True

	@classmethod
	def set_all_verbose(cls):
		cls._all_verbose = True

	@classmethod
	def pause_after_failed_execution(cls):
		cls._pause_after_failed_execution = True

	@classmethod
	def pause_before_execution(cls):
		cls._pause_before_execution = True
