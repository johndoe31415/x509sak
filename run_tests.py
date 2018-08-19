#!/usr/bin/env python3
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
import x509sak.tests
import tempfile
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.FriendlyArgumentParser import FriendlyArgumentParser

class Bucket(object):
	def __init__(self):
		self._content = [ ]
		self._weight = 0

	@property
	def weight(self):
		return self._weight

	@property
	def content(self):
		return self._content

	def put(self, obj, weight):
		self._content.append(obj)
		self._weight += weight

	def __lt__(self, other):
		return self.weight < other.weight

class Bucketizer(object):
	def __init__(self):
		self._objects = [ ]

	def add_item(self, obj, weight):
		self._objects.append((weight, obj))

	def split_into(self, bucket_count, verbose = None):
		buckets = [ Bucket() for i in range(bucket_count) ]
		for (weight, obj) in reversed(sorted(self._objects)):
			# Place object in bucket that has least total weight
			buckets.sort()
			buckets[0].put(obj, weight)
		buckets = [ bucket for bucket in buckets if len(bucket.content) > 0 ]
		if verbose:
			print("Split into %d parallel buckets:" % (len(buckets)))
			buckets.sort()
			for (bid, bucket) in enumerate(buckets):
				print("    %2d  weight = %.1f" % (bid, bucket.weight))
		return [ bucket.content for bucket in buckets ]

class TestStats(object):
	def __init__(self, runtime = 0, run = None, failed = None, errored = None, processes = 1):
		self._stats = {
			"total_time":		runtime,
			"cumulative_time":	0,
			"run":				run or { },
			"failed":			[ ],
			"processes":		processes,
		}
		if failed is not None:
			self._stats["failed"] += self._failures_to_dict(failed, failtype = "failed")
		if errored is not None:
			self._stats["failed"] += self._failures_to_dict(errored, failtype = "errored")

	@classmethod
	def from_json(cls, filename):
		with open(filename) as f:
			stats_json = json.load(f)
		stats = cls()
		stats._stats = stats_json
		return stats

	def merge(self, stats):
		self._stats["cumulative_time"] += stats._stats["total_time"]
		self._stats["run"].update(stats._stats["run"])
		self._stats["failed"] += stats._stats["failed"]
		self._stats["processes"] += stats._stats["processes"]

	@property
	def processes(self):
		return self._stats["processes"]

	@property
	def run_cnt(self):
		return len(self._stats["run"])

	@property
	def success_cnt(self):
		return self.run_cnt - self.failed_cnt

	@property
	def failed_cnt(self):
		return len(self._stats["failed"])

	@property
	def successful(self):
		return self.failed_cnt == 0

	@staticmethod
	def _failures_to_dict(failures, failtype = "errored"):
		return [ {
			"failtype":		failtype,
			"instance":		str(testcase),
			"tcid":			testcase.id(),
			"traceback":	traceback.rstrip("\r\n"),
		} for (testcase, traceback) in failures ]

	def _to_dict(self):
		return self._stats

	def write_to_json_file(self, filename):
		with open(filename, "w") as f:
			json.dump(self._stats, fp = f)

	def write_failed_tests_file(self, filename):
		with open(filename, "w") as f:
			json.dump([ failure["tcid"] for failure in self._stats["failed"] ], fp = f)

	def merge_test_estimation_time(self, filename):
		try:
			with open(filename) as f:
				estimate = json.load(f)
		except (FileNotFoundError, json.decoder.JSONDecodeError):
			estimate = { }
		estimate.update(self._stats["run"])
		with open(filename, "w") as f:
			json.dump(estimate, fp= f)

	def dump(self):
		for failure in self._stats["failed"]:
			print("~" * 120, file = sys.stderr)
			print("%s: %s" % (failure["failtype"], failure["instance"]), file = sys.stderr)
			print(failure["traceback"], file = sys.stderr)
		print("~" * 120, file = sys.stderr)

		if self.run_cnt > 0:
			print("run: %d in %.1f secs (%d processes, cumulative %.1f secs), successful: %d (%.0f%%), failures: %d (%.0f%%)" % (
						self.run_cnt, self._stats["total_time"], self.processes, self._stats["cumulative_time"],
						self.success_cnt, 100 * self.success_cnt / self.run_cnt,
						self.failed_cnt, 100 * self.failed_cnt / self.run_cnt))
		else:
			print("No tests were run.", file = sys.stderr)

class SelectiveTestRunner(object):
	_InstanciatedTestCase = collections.namedtuple("InstanciatedTestCase", [ "module_name", "class_name", "test_name", "test" ])

	def __init__(self, args, root_module, failed_tests_file = None):
		self._args = args
		self._root_modules = [ root_module ]
		self._suite = unittest.TestSuite()
		self._failed_tests_file = failed_tests_file
		self._include_regexes = [ re.compile(text, flags = re.IGNORECASE) for text in self._args.target ]
		self._exclude_regexes = [ re.compile(text, flags = re.IGNORECASE) for text in self._args.exclude ]
		self._found_testcases = { testcase.test.id(): testcase for testcase in self._enumerate_all_tests() }
		self._test_result = None
		if len(self._args.full_id) > 0:
			# Ignore all other arguments, full ID takes full precedence
			self._add_testcases_with_full_id(self._args.full_id)
		elif (not self._args.all) and (os.path.isfile(self._failed_tests_file)):
			with open(self._failed_tests_file) as f:
				full_testcase_ids = json.load(f)
			self._add_testcases_with_full_id(full_testcase_ids)
			os.unlink(self._failed_tests_file)
		else:
			self._add_all_included_tests()

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

		for test_class_name in sorted(dir(root_module)):
			if test_class_name.startswith("_"):
				continue
			test_class = getattr(root_module, test_class_name)
			if (not isinstance(test_class, type)) or (not issubclass(test_class, unittest.TestCase)):
				continue
			for test_method_name in dir(test_class):
				if not test_method_name.startswith("test_"):
					continue
				test = test_class(test_method_name)
				instanciated_testcase = self._InstanciatedTestCase(module_name = module_name, class_name = test_class_name, test_name = test_method_name, test = test)
				yield instanciated_testcase

	def _add_testcase(self, testcase):
		if self._args.verbose:
			print("Testing: %s.%s" % (testcase.class_name, testcase.test_name))
		self._suite.addTest(testcase.test)

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

	def _wait_until_finished(self):
		for i in range(self._subprocess_cnt):
			self._subprocess_sem.acquire()
	def _wait_for_subprocess(self, subproc):
		subproc.wait()
		self._subprocess_sem.release()

	def _run_single(self):
		t0_total = time.time()
		self._test_result = unittest.TextTestResult(stream = sys.stderr, descriptions = True, verbosity = 1)
		time_taken = { }
		for testcase in self._suite:
			t0 = time.time()
			testcase.run(self._test_result)
			t1 = time.time()
			time_taken[testcase.id()] = t1 - t0
		t1_total = time.time()
		runtime = t1_total - t0_total
		test_stats = TestStats(runtime = runtime, run = time_taken, failed = self._test_result.failures, errored = self._test_result.errors)
		return test_stats

	def _run_parallel(self):
		result_tempfiles = [ ]
		coverage_tempfiles = [ ]

		try:
			with open(".tests_estimate.json") as f:
				estimate = json.load(f)
		except (FileNotFoundError, json.decoder.JSONDecodeError):
			estimate = { }

		t0 = time.time()
		bucketizer = Bucketizer()
		for testcase in self._suite:
			bucketizer.add_item(testcase.id(), weight = estimate.get(testcase.id(), 1))
		buckets = bucketizer.split_into(bucket_count = self._args.parallel, verbose = self._args.verbose)

		procs = [ ]
		for (bid, bucket) in enumerate(buckets):
			env = dict(os.environ)
			result_tempfile = tempfile.NamedTemporaryFile(prefix = "bucket_%02d_" % (bid), suffix = ".json")
			result_tempfiles.append(result_tempfile)
			if self._args.coverage > 0:
				cmdline = [ "coverage", "run", "--append", "--omit", "/usr/*,run_tests.py" ]
			else:
				cmdline = [ ]
			cmdline += [ "./run_tests.py", "--parallel", "1", "--subprocess", "--dump-json", result_tempfile.name ]
			if self._args.coverage > 0:
				coverage_tempfile = tempfile.NamedTemporaryFile(prefix = "bucket_%02d_" % (bid), suffix = ".txt", delete = False)
				os.unlink(coverage_tempfile.name)
				coverage_tempfiles.append(coverage_tempfile)
				cmdline += [ "--coverage" ]
				env["COVERAGE_FILE"] = coverage_tempfile.name
				env["X509SAK_COVERAGE"] = "1"

			# Shuffle randomly so not all fast tests come at the very end
			random.shuffle(bucket)
			for tcid in bucket:
				cmdline += [ "-i", tcid ]
			if self._args.verbose > 0:
				cmdline += [ "-" + ("v" * self._args.verbose) ]
			proc = subprocess.Popen(cmdline, env = env)
			procs.append(proc)

		# Then wait for all procs to finish up
		for proc in procs:
			proc.wait()
		t1 = time.time()

		# Finally, coalesce results
		merged_results = TestStats(runtime = t1 - t0, processes = 0)
		for result_tempfile in result_tempfiles:
			merged_results.merge(TestStats.from_json(result_tempfile.name))

		# Also coalesce the coverage files
		if len(coverage_tempfiles) > 0:
			coverage_filenames = [ coverage_tempfile.name for coverage_tempfile in coverage_tempfiles ]
			cmd = [ "coverage", "combine", "--append" ] + coverage_filenames
			subprocess.check_call(cmd)
		return merged_results

	def run(self):
		if self._args.parallel == 1:
			return self._run_single()
		else:
			return self._run_parallel()

parser = FriendlyArgumentParser()
parser.add_argument("-e", "--exclude", metavar = "class_name", action = "append", default = [ ], help = "Exclude specific test cases. Can be regexes matching the \"{classname}.{testname}\" specifiers.")
parser.add_argument("-a", "--all", action = "store_true", help = "Regardless of a perviously persisted failed test file, test everything.")
parser.add_argument("-i", "--full-id", metavar = "tcid", default = [ ], action = "append", help = "Specify a number of test cases by their full testcase ID. Can be supplied multiple times. Takes highest precedence.")
parser.add_argument("-c", "--coverage", action = "count", default = 0, help = "Run all subprocesses through code coverage measurement. Specify twice to also show text report in console after run and three times to render HTML page and open up browser.")
parser.add_argument("--dump-json", metavar = "filename", type = str, help = "Create a JSON dump of all testcase data and write it to the given file instead of printing results to stdout.")
parser.add_argument("--subprocess", action = "store_true", help = argparse.SUPPRESS)
parser.add_argument("-p", "--parallel", metavar = "processes", type = int, default = 12, help = "Split up testbench and concurrently run on multiple threads. Defaults to %(default)s.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity.")
parser.add_argument("target", metavar = "classname", type = str, nargs = "*", help = "Target for testing; can be a regex matching the \"{classname}.{testname}\" specifiers. By default, all are included.")
args = parser.parse_args(sys.argv[1:])

if len(args.full_id) > 0:
	if args.all or (len(args.exclude) > 0):
		raise Exception("Either full ID can be specified or --all / --exclude. Not both.")

if (not args.subprocess) and args.coverage:
	try:
		shutil.rmtree("htmlcov")
	except FileNotFoundError:
		pass
	try:
		os.unlink(".coverage")
	except FileNotFoundError:
		pass

if args.coverage:
	os.environ["X509SAK_COVERAGE"] = "1"

if args.verbose >= 1:
	SubprocessExecutor.set_failed_verbose()
if args.verbose >= 2:
	SubprocessExecutor.set_all_verbose()
if args.verbose >= 3:
	SubprocessExecutor.pause_after_failed_execution()
runner = SelectiveTestRunner(args, x509sak.tests, failed_tests_file = ".tests_failed.json")
results = runner.run()

if args.dump_json is None:
	# Print results
	print(file = sys.stderr)
	results.dump()
	results.merge_test_estimation_time(".tests_estimate.json")
	if results.successful:
		returncode = 0
	else:
		results.write_failed_tests_file(".tests_failed.json")
		returncode = 1
else:
	# Be quiet about results, write them to the JSON file
	results.write_to_json_file(args.dump_json)
	returncode = 0

if (not args.subprocess) and (args.coverage >= 1):
	subprocess.call([ "coverage", "report" ])
if (not args.subprocess) and (args.coverage >= 2):
	subprocess.call([ "coverage", "html" ])
	subprocess.call([ "chromium-browser", "htmlcov/index.html" ])

sys.exit(returncode)
