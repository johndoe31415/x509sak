#!/usr/bin/python3
import sys
import unittest
import argparse
import x509sak.tests
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser()
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity.")
parser.add_argument("target", metavar = "classname", type = str, nargs = "*", help = "Target for testing")
args = parser.parse_args(sys.argv[1:])

if args.verbose >= 1:
	SubprocessExecutor.set_verbose()
if args.verbose >= 2:
	SubprocessExecutor.pause_after_failed_execution()

test_class_names = args.target or sorted(dir(x509sak.tests))

test_classes = [ ]
for test_class_name in test_class_names:
	if test_class_name.startswith("_"):
		continue
	test_class = getattr(x509sak.tests, test_class_name)
	test_classes.append(test_class)

suite = unittest.TestSuite()
loader = unittest.TestLoader()
for test_class in test_classes:
	class_suite = loader.loadTestsFromTestCase(test_class)
	suite.addTests(class_suite)

runner = unittest.TextTestRunner()
result = runner.run(suite)
if not result.wasSuccessful():
	sys.exit(1)
