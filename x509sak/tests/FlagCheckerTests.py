#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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

from x509sak.tests import BaseTest
from x509sak.FlagChecker import FlagChecker

class FlagCheckerTests(BaseTest):
	def test_all_ok(self):
		checker = FlagChecker().may_have("a", "b", "c")
		self.assertEqual(list(checker.check([ ])), [ ])
		self.assertEqual(list(checker.check([ "a", "c" ])), [ ])
		self.assertEqual(list(checker.check([ "a", "b", "c" ])), [ ])

	def test_missing(self):
		checker = FlagChecker().may_have("a", "b", "c").must_have("d")
		results = list(checker.check([ "a", "c" ]))
		self.assertEqual(len(results), 1)
		self.assertEqual(results[0].check_type, "missing")
		self.assertEqual(list(results[0].flags), [ "d" ])

	def test_unusual(self):
		checker = FlagChecker().may_have("a", "b", "c")
		results = list(checker.check([ "x" ]))
		self.assertEqual(len(results), 1)
		self.assertEqual(results[0].check_type, "unusual")
		self.assertEqual(list(results[0].flags), [ "x" ])

	def test_excessive(self):
		checker = FlagChecker().may_have("a", "b", "c").may_not_have("d")
		results = list(checker.check([ "a", "c" ]))
		self.assertEqual(len(results), 0)

		results = list(checker.check([ "a", "d", "c" ]))
		self.assertEqual(results[0].check_type, "excess")
		self.assertEqual(list(results[0].flags), [ "d" ])

	def test_complex(self):
		checker = FlagChecker().complex_check([ "a", "b", "c"], min_count = 1).may_have("d", "e", "f")
		self.assertEqual(list(checker.check([ "a" ])), [ ])
		self.assertEqual(list(checker.check([ "a", "b" ])), [ ])
		self.assertEqual(list(checker.check([ "a", "b", "c" ])), [ ])
		self.assertEqual(list(checker.check([ "a", "b", "c" ])), [ ])
		self.assertEqual(list(checker.check([ "e", "f", "a" ])), [ ])

		results = list(checker.check([ "e", "f" ]))
		self.assertEqual(len(results), 1)
		self.assertEqual(results[0].check_type, "complex_too_few")
		self.assertEqual(list(results[0].flags), [ ])
		self.assertEqual(list(sorted(results[0].reference)), [ "a", "b", "c" ])
