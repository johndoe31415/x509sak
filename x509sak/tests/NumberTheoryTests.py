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

import random
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

	def test_modinv(self):
		p = 2003
		for i in range(10):
			r = random.randint(2, p - 1)
			inv = NumberTheory.modinv(r, p)
			self.assertEqual(r * inv % p, 1)

	def test_gen_prime(self):
		primes = set()
		for i in range(15):
			p = NumberTheory.gen_insecure_probable_prime(6)
			q = NumberTheory.gen_insecure_probable_prime(6)
			primes.add(p)
			primes.add(q)
			n = p * q
			self.assertEqual(n.bit_length(), 12)

		# With reasonal probability, all will be hit
		self.assertEqual(primes, set([ 53, 59, 61 ]))

	def test_gen_fastprime(self):
		p = NumberTheory.gen_insecure_probable_fastprime(10)
		print()
		print(p)
		print()
		jifodsjfoisd
		for n in [ 20, 50, 100, 150, 200, 500 ]:
			p = NumberTheory.gen_insecure_probable_fastprime(n)
			print(p)
			self.assertTrue(NumberTheory.is_probable_prime(p))

