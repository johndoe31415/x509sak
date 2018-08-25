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

from x509sak.tests.BaseTest import BaseTest
from x509sak.KwargsChecker import KwargsChecker
from x509sak.Exceptions import InvalidInputException

class KwargsCheckerTests(BaseTest):
	def test_normal(self):
		checker = KwargsChecker(required_arguments = set([ "foo", "bar" ]))
		checker.check({ "foo": 2, "bar": 9 })

		checker = KwargsChecker(required_arguments = set([ "foo", "bar" ]), optional_arguments = set([ "moo" ]))
		checker.check({ "foo": 2, "bar": 9 })
		checker.check({ "foo": 2, "bar": 9, "moo": 12 })

		checker = KwargsChecker(optional_arguments = set([ "moo" ]))
		checker.check({ })
		checker.check({ "moo": 9 })

	def test_missing_required(self):
		checker = KwargsChecker(required_arguments = set([ "foo", "bar" ]))
		with self.assertRaises(InvalidInputException):
			checker.check({ "foo": 2 })
		with self.assertRaises(InvalidInputException):
			checker.check({ "foo": 2, "BAR": 9 })
		with self.assertRaises(InvalidInputException):
			checker.check({ "foo": 2, "BAR": 9, "MOO": 12 })
		with self.assertRaises(InvalidInputException):
			checker.check({ "foo": 2, "BAR": 9, "MOO": 12 }, hint = "foobar")

		checker = KwargsChecker(required_arguments = set([ "foo", "bar" ]), optional_arguments = set([ "muh" ]))
		with self.assertRaises(InvalidInputException):
			checker.check({ "foo": 2, "BAR": 9, "MOO": 12 }, hint = "foobar")

	def test_single(self):
		checker = KwargsChecker(required_arguments = set([ "foo", "bar" ]), optional_arguments = set([ "moo" ]))
		checker.check_single("foo")
		checker.check_single("bar")
		checker.check_single("moo")
		with self.assertRaises(InvalidInputException):
			checker.check_single("fux")
		with self.assertRaises(InvalidInputException):
			checker.check_single("fux", hint = "foobarhint")
