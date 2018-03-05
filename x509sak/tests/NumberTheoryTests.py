#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2017-2017 Johannes Bauer
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

import unittest
from x509sak.NumberTheory import NumberTheory

class NumberTheoryTests(unittest.TestCase):
	def test_egcd(self):
		(g, s, t) = NumberTheory.egcd(4567, 123)
		self.assertEqual(g, 1)
		self.assertEqual(s, -23)
		self.assertEqual(t, 854)

		(g, s, t) = NumberTheory.egcd(123, 4567)
		self.assertEqual(g, 1)
		self.assertEqual(s, 854)
		self.assertEqual(t, -23)

		(g, s, t) = NumberTheory.egcd(101 * 17, 101 * 11)
		self.assertEqual(g, 101)
		self.assertEqual(s, 2)
		self.assertEqual(t, -3)
