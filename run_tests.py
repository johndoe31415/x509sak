#!/usr/bin/env python3
import sys
import re
import os
import json
import unittest
import argparse
import collections
import x509sak.tests
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.FriendlyArgumentParser import FriendlyArgumentParser

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
		if (not self._args.all) and (os.path.isfile(self._failed_tests_file)):
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
			if not issubclass(test_class, unittest.TestCase):
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

	def run(self):
		runner = unittest.TextTestRunner()
		self._test_result = runner.run(self._suite)
		return self._test_result.wasSuccessful()

	def write_failed_tests_file(self):
		failed_test_ids = [ test_instance.id() for (test_instance, msg) in (self._test_result.errors + self._test_result.failures) ]
		with open(self._failed_tests_file, "w") as f:
			json.dump(failed_test_ids, fp = f)

parser = FriendlyArgumentParser()
parser.add_argument("-c", "--coverage", action = "store_true", help = "Run all subprocess through code coverage measurement; note that run_tests itself needs to be run through coverage as well.")
parser.add_argument("--exclude", metavar = "class_name", action = "append", default = [ ], help = "Exclude specific test cases. Can be regexes matching the \"{classname}.{testname}\" specifiers.")
parser.add_argument("--all", action = "store_true", help = "Regardless of a perviously persisted failed test file, test everything.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity.")
parser.add_argument("target", metavar = "classname", type = str, nargs = "*", help = "Target for testing; can be a regex matching the \"{classname}.{testname}\" specifiers. By default, all are included.")
args = parser.parse_args(sys.argv[1:])

if args.coverage:
	os.environ["X509SAK_COVERAGE"] = "1"
	os.environ["COVERAGE_FILE"] = os.path.realpath(".") + "/.coverage"

if args.verbose >= 1:
	SubprocessExecutor.set_verbose()
if args.verbose >= 2:
	SubprocessExecutor.pause_after_failed_execution()
runner = SelectiveTestRunner(args, x509sak.tests, failed_tests_file = ".failed_tests.json")
if runner.run():
	sys.exit(0)
else:
	runner.write_failed_tests_file()
	sys.exit(1)
