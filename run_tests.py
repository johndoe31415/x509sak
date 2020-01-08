#!/usr/bin/env python3
#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
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

try:
	import coverage
except ImportError:
	coverage = None
import random
import time
import sys
import re
import os
import json
import unittest
import argparse
import collections
import subprocess
import shutil
import io
import tempfile
import contextlib
import inspect
import glob
import multiprocessing
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.FriendlyArgumentParser import FriendlyArgumentParser
from x509sak.ParallelExecutor import ParallelExecutor

class OutputRedirector(object):
	def __init__(self):
		self._stdout_f = None
		self._stderr_f = None
		self._stdout = None
		self._stderr = None

	@property
	def stdout(self):
		return self._stdout

	@property
	def stderr(self):
		return self._stderr

	def _backup_and_replace_fd(self, fd):
		replacement_file = tempfile.NamedTemporaryFile(mode = "w+b", prefix = "fd_", suffix = ".bin")
		fd_backup = os.dup(fd)
		os.dup2(replacement_file.fileno(), fd)
		return (fd_backup, replacement_file)

	def _restore_fd(self, fd_backup_file, fd):
		(fd_backup, replacement_file) = fd_backup_file
		replacement_file.seek(0)
		data = replacement_file.read()
		os.dup2(fd_backup, fd)
		return data

	def __enter__(self):
		self._stdout_f = self._backup_and_replace_fd(sys.stdout.fileno())
		self._stderr_f = self._backup_and_replace_fd(sys.stderr.fileno())

	def __exit__(self, *args):
		self._stderr = self._restore_fd(self._stderr_f, sys.stderr.fileno())
		self._stdout = self._restore_fd(self._stdout_f, sys.stdout.fileno())

class TestStats(object):
	def __init__(self, test_count):
		self._starttime = time.time()
		self._endtime = None
		self._test_count = test_count
		self._stats = {
			"cumulative_time":		0,
			"pass": { },
			"fail": { },
			"error": { },
		}
		self._last_progress_msg = None

	def _status_string(self):
		return "%d in %.1f secs (cumulative %.1f secs), successful: %d (%.0f%%), failures: %d (%.0f%%)" % (
					self.run_count, self.runtime, self._stats["cumulative_time"],
					self.pass_count, 100 * self.pass_count / self.run_count,
					self.fail_count, 100 * self.fail_count / self.run_count)

	def _show_progress(self, test_case, test_result):
		now = time.time()
		if (self._last_progress_msg is not None) and ((now - self._last_progress_msg) < 0.1):
			# Don't update every 100ms
			return

		if self._last_progress_msg is not None:
			# Progress line from previous output, delete.
			sys.stdout.write("\r\x1b[2K")
		self._last_progress_msg = now

		if test_result["resultcode"] != "pass":
			print("%s: %s.%s" % (test_result["resultcode"], test_case.class_name, test_case.test_name))

		sys.stdout.write("%d of %d (%.1f%%): %s" % (self.run_count, self.test_count, self.run_count / self.test_count * 100, self._status_string()))
		sys.stdout.flush()

	@property
	def runtime(self):
		if self._endtime is None:
			# Still running
			return time.time() - self._starttime
		else:
			return self._endtime - self._starttime

	def finish(self):
		self._endtime = time.time()
		self._stats["time"] = self.runtime
		print()

	def register_result(self, test_case, test_result, show_progress = False):
		self._stats["cumulative_time"] += test_result["tdiff"]
		tcid = test_case.test.id()
		details = { key: test_result[key] for key in [ "tdiff", "resultcode", "error_text", "stdout", "stderr" ] }
		self._stats[test_result["resultcode"]][tcid] = details
		if show_progress:
			self._show_progress(test_case, test_result)

	def all_details(self):
		yield from self._stats["pass"].items()
		yield from self._stats["fail"].items()
		yield from self._stats["error"].items()

	def failed_details(self):
		yield from self._stats["fail"].items()
		yield from self._stats["error"].items()

	@property
	def run_count(self):
		return self.pass_count + self.fail_count

	@property
	def pass_count(self):
		return len(self._stats["pass"])

	@property
	def fail_count(self):
		return len(self._stats["fail"]) + len(self._stats["error"])

	@property
	def test_count(self):
		return self._test_count

	@property
	def failed_tcids(self):
		return [ tcid for (tcid, details) in self.failed_details() ]

	@property
	def runtimes_by_id(self):
		return { tcid: details["tdiff"] for (tcid, details) in self.all_details() }

	def write_failed_tests_file(self, filename):
		with open(filename, "w") as f:
			json.dump(self.failed_tcids, fp = f)

	def _dump_tcdetails(self, tcid, tcdetails):
		print("%s: %s" % (tcid, tcdetails["resultcode"]))
		if tcdetails["stdout"] != "":
			print(tcdetails["stdout"])
		if tcdetails["stderr"] != "":
			print(tcdetails["stderr"])
		if tcdetails["error_text"] != "":
			print(tcdetails["error_text"])

	def update_time_estimates(self, time_estimate_filename):
		try:
			with open(time_estimate_filename) as f:
				time_estimates = json.load(f)
		except (FileNotFoundError, json.JSONDecodeError):
			time_estimates = { }
		time_estimates.update(self.runtimes_by_id)
		with open(time_estimate_filename, "w") as f:
			json.dump(time_estimates, f)

	def dump(self):
		for (count, (tcid, tcdetails)) in enumerate(sorted(self.failed_details())):
			if count != 0:
				print("-" * 120)
			else:
				print("~" * 120)
			self._dump_tcdetails(tcid, tcdetails)

		print("~" * 120, file = sys.stderr)

		if self.run_count > 0:
			print("ran: %s" % (self._status_string()))
		else:
			print("No tests were run.", file = sys.stderr)

InstanciatedTestCase = collections.namedtuple("InstanciatedTestCase", [ "module_name", "class_name", "test_name", "test" ])
class SelectiveTestRunner(object):
	def __init__(self, args, root_module, failed_tests_file = None):
		self._args = args
		self._root_modules = [ root_module ]
		self._suite = [ ]
		self._failed_tests_file = failed_tests_file
		self._include_regexes = [ re.compile(text, flags = re.IGNORECASE) for text in self._args.target ]
		self._exclude_regexes = [ re.compile(text, flags = re.IGNORECASE) for text in self._args.exclude ]
		self._found_testcases = { testcase.test.id(): testcase for testcase in self._enumerate_all_tests() }
		self._test_results = None

		search_term_given = len(self._include_regexes) > 0
		have_failed_tests = (not self._args.all) and (os.path.isfile(self._failed_tests_file))
		if len(self._args.full_id) > 0:
			# Ignore all other arguments, full ID takes full precedence
			self._add_testcases_with_full_id(self._args.full_id)
		elif search_term_given and ((not have_failed_tests) or self._args.target_has_precedence):
			# Have include regex, this takes second precedence
			self._add_all_included_tests()
		elif have_failed_tests:
			# No full IDs and no include regexes given, failed testcases is
			# number three
			try:
				with open(self._failed_tests_file) as f:
					full_testcase_ids = json.load(f)
				self._add_testcases_with_full_id(full_testcase_ids)
			except json.JSONDecodeError:
				self._add_all_included_tests()
		else:
			# Otherwise just run everything
			self._add_all_included_tests()
			with contextlib.suppress(FileNotFoundError):
				os.unlink(".examinecert_stats.json")
		try:
			os.unlink(self._failed_tests_file)
		except FileNotFoundError:
			pass
		self._rearrange_testsuite()

	def _rearrange_testsuite(self):
		random.shuffle(self._suite)

	def _is_testcase_included(self, testcase):
		test_id = testcase.class_name + "." + testcase.test_name
		if (len(self._include_regexes) == 0) or any(regex.search(test_id) for regex in self._include_regexes):
			# Testcase is included in principle, now check for possible
			# exclusions
			if any(regex.search(test_id) for regex in self._exclude_regexes):
				return False
			else:
				return True
		else:
			# Testcase not included
			return False

	def _enumerate_module(self, root_module):
		module_name = root_module.__name__

		for (test_class_name, test_class) in inspect.getmembers(root_module, predicate = inspect.isclass):
			for (test_func_name, test_func) in inspect.getmembers(test_class, predicate = lambda fn: inspect.isfunction(fn) and fn.__name__.startswith("test_")):
				test = test_class(test_func_name)
				instanciated_testcase = InstanciatedTestCase(module_name = module_name, class_name = test_class_name, test_name = test_func_name, test = test)
				yield instanciated_testcase

	def _add_testcase(self, testcase):
		if self._args.verbose:
			print("Testing: %s.%s" % (testcase.class_name, testcase.test_name))
		self._suite.append(testcase)

	def _enumerate_all_tests(self):
		for root_module in self._root_modules:
			for testcase in self._enumerate_module(root_module):
				yield testcase

	def _add_all_included_tests(self):
		for testcase in self._found_testcases.values():
			if self._is_testcase_included(testcase):
				self._add_testcase(testcase)

	def _add_testcases_with_full_id(self, full_ids):
		for full_id in full_ids:
			testcase = self._found_testcases.get(full_id)
			if testcase is not None:
				self._add_testcase(testcase)
			else:
				print("Warning: Could not find testcase %s among %d discovered tests." % (full_id, len(self._found_testcases)), file = sys.stderr)

	def _worker(self, test_case):
		t0 = time.time()
		output_redirect = OutputRedirector()
		with output_redirect:
			result = test_case.test()
		t1 = time.time()

		error_text = ""
		for err_source in [ result.failures, result.errors ]:
			for (err_class, err_text) in err_source:
				error_text += "%s\n" % (str(err_class))
				error_text += err_text

		if len(result.errors) > 0:
			resultcode = "error"
		elif len(result.failures) > 0:
			resultcode = "fail"
		else:
			resultcode = "pass"

		result = {
			"tdiff":		t1 - t0,
			"resultcode":	resultcode,
			"error_text":	error_text,
			"stdout":		output_redirect.stdout.decode("utf-8", errors = "ignore"),
			"stderr":		output_redirect.stderr.decode("utf-8", errors = "ignore"),
		}
		return (test_case, result)

	def _dot_progress(self, test_case, result):
		character = {
			"pass":		".",
			"fail":		"F",
			"error":	"E",
		}.get(result["resultcode"], "?")
		sys.stdout.write(character)
		sys.stdout.flush()

	def _process_test_result(self, result):
		(test_case, result) = result
		self._test_results.register_result(test_case, result, show_progress = not self._args.dot_progress)
		if self._args.dot_progress:
			self._dot_progress(test_case, result)

	def run(self):
		print("Running %d testcases using %d parallel processes." % (len(self._suite), self._args.parallel), file = sys.stderr)
		self._test_results = TestStats(len(self._suite))
		if len(self._suite) > 0:
			self._parallel_processor = ParallelExecutor(work_generator = lambda: iter(self._suite), result_processing_function = self._process_test_result, worker_function = self._worker)
			try:
				self._parallel_processor.run()
			except KeyboardInterrupt:
				print("Interrupted.")
		self._test_results.finish()
		return self._test_results

parser = FriendlyArgumentParser()
parser.add_argument("-e", "--exclude", metavar = "class_name", action = "append", default = [ ], help = "Exclude specific test cases. Can be regexes matching the \"{classname}.{testname}\" specifiers.")
parser.add_argument("-a", "--all", action = "store_true", help = "Regardless of a perviously persisted failed test file, test everything.")
parser.add_argument("-i", "--full-id", metavar = "tcid", default = [ ], action = "append", help = "Specify a number of test cases by their full testcase ID. Can be supplied multiple times. Takes highest precedence.")
parser.add_argument("-c", "--coverage", action = "count", default = 0, help = "Run all subprocesses through code coverage measurement. Specify twice to also show text report in console after run and three times to render HTML page and open up browser.")
parser.add_argument("-d", "--debug-dumps", action = "store_true", help = "For certain testcases, automatically create debug dumpfiles. These can either be for tracing errors but also might include statistical information.")
parser.add_argument("--dot-progress", action = "store_true", help = "Show dots instead of progress bar.")
parser.add_argument("-T", "--target-has-precedence", action = "store_true", help = "By default, when a search pattern is given on the command line but there are failed tests, the target is ignored and only the failed tests are re-run. When this option is given, the precedence is reversed and the target is always honored even in spite of failed tests.")
parser.add_argument("-f", "--fail-fast", action = "store_true", help = "Fail fast, i.e., do not continue testing after the first test fails.")
parser.add_argument("-p", "--parallel", metavar = "processes", type = int, default = multiprocessing.cpu_count(), help = "Split up testbench and concurrently run on multiple threads. Defaults to %(default)s.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity.")
parser.add_argument("target", metavar = "classname", type = str, nargs = "*", help = "Target for testing; can be a regex matching the \"{classname}.{testname}\" specifiers. By default, all are included.")
args = parser.parse_args(sys.argv[1:])

if len(args.full_id) > 0:
	if args.all or (len(args.exclude) > 0):
		raise Exception("Either full ID can be specified or --all / --exclude. Not both.")

if args.coverage and (coverage is None):
	raise Exception("Code coverage analysis requires the 'coverage' package to be installed.")

if args.coverage:
	with contextlib.suppress(FileNotFoundError):
		shutil.rmtree("htmlcov")
	for coverage_datafile in glob.glob(".coverage.*"):
		os.unlink(coverage_datafile)

if args.coverage > 0:
	coverage_omit_dirs = [
		"/usr/*",
		os.path.expanduser("~/.local") + "/*",
	]
	os.environ["X509SAK_COVERAGE"] = json.dumps({
		"coverage_path":	os.path.realpath(os.path.dirname(__file__)) + "/",
		"omit":				",".join(coverage_omit_dirs),
	})
if args.debug_dumps:
	os.environ["X509SAK_DEBUG_DUMPS"] = "1"

if args.verbose >= 1:
	SubprocessExecutor.set_failed_verbose()
if args.verbose >= 2:
	SubprocessExecutor.set_all_verbose()
if args.verbose >= 3:
	SubprocessExecutor.pause_after_failed_execution()

if args.coverage > 0:
	cov = coverage.Coverage(concurrency = "multiprocessing", check_preimported = True, omit = coverage_omit_dirs)
	cov.start()

import x509sak.tests
testrunner = SelectiveTestRunner(args, x509sak.tests, failed_tests_file = ".tests_failed.json")
results = testrunner.run()
results.dump()
if args.coverage > 0:
	cov.stop()
	cov.save()
	cov.combine()
	if args.coverage == 1:
		cov.report()
	elif args.coverage >= 2:
		cov.html_report()

results.update_time_estimates(".tests_estimate.json")
if results.fail_count == 0:
	returncode = 0
else:
	results.write_failed_tests_file(".tests_failed.json")
	returncode = 1

#if (not args.subprocess) and (args.coverage >= 1):
#	subprocess.call([ "coverage", "report" ])
#if (not args.subprocess) and (args.coverage >= 2):
#	subprocess.call([ "coverage", "html" ])
#	subprocess.call([ "chromium-browser", "htmlcov/index.html" ])
sys.exit(returncode)
