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
from x509sak.BijectiveDict import BijectiveDict

class BijectiveDictTests(BaseTest):
	def test_simple(self):
		bijd = BijectiveDict({
			"a":	"1",
			"b":	"2",
			"c":	"3",
		})
		self.assertEqual(bijd["a"], "1")
		self.assertEqual(bijd["b"], "2")
		self.assertEqual(bijd["c"], "3")
		with self.assertRaises(KeyError):
			bijd["B"]

		self.assertEqual(bijd.inverse("3"), "c")
		self.assertEqual(bijd.inverse("2"), "b")
		self.assertEqual(bijd.inverse("1"), "a")
		with self.assertRaises(KeyError):
			bijd.inverse("4")

	def test_nonbijective(self):
		with self.assertRaises(Exception):
			bijd = BijectiveDict({
				"a":	"1",
				"b":	"2",
				"c":	"2",
			})

	def test_key_predicate(self):
		bijd = BijectiveDict({
			"a":	"1",
			"b":	"2",
			"c":	"3",
		}, key_predicate = lambda key: key.lower())
		self.assertEqual(bijd["b"], "2")
		self.assertEqual(bijd["B"], "2")

	def test_key_predicate_nonbijective(self):
		with self.assertRaises(Exception):
			bijd = BijectiveDict({
				"a":	"1",
				"A":	"2",
				"c":	"2",
			}, key_predicate = lambda key: key.lower())

