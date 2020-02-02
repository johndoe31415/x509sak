#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2020 Johannes Bauer
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
import random
from x509sak.tests import BaseTest
from x509sak.Exceptions import InvalidInputException
from x509sak.NumberTheory import NumberTheory

class NumberTheoryTests(BaseTest):
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
		for _ in range(10):
			r = random.randint(2, p - 1)
			inv = NumberTheory.modinv(r, p)
			self.assertEqual(r * inv % p, 1)

	def test_gen_prime(self):
		primes = set()
		for _ in range(15):
			p = NumberTheory.randprime_bits(6, two_msb_set = True)
			q = NumberTheory.randprime_bits(6, two_msb_set = True)
			primes.add(p)
			primes.add(q)
			n = p * q
			self.assertEqual(n.bit_length(), 12)

		# With reasonal probability, all will be hit
		self.assertEqual(primes, set([ 53, 59, 61 ]))

	def test_crt(self):
		moduli = { 2: 1, 3: 2, 5: 3, 7: 4, 11: 5, 13: 6, 17: 7 }
		solution = NumberTheory.solve_crt(moduli)
		for (modulus, remainder) in moduli.items():
			self.assertEqual(solution % modulus, remainder)

	def test_pollard_rho_prime(self):
		p = 2003
		self.assertIsNone(NumberTheory.pollard_rho(p), None)

	def test_pollard_rho_success(self):
		p = 3513360553
		q = 2841366767
		n = p * q
		self.assertIn(NumberTheory.pollard_rho(n), [ p, q ])

	def test_pollard_rho_give_up(self):
		# There's a small chance this test may fail. :-)
		p = 95749913370328252241446208736506188314802113993127662348226135040475696867509
		q = 99274458486037483860318981815348157562287354834427068777154647405331367500099
		n = p * q
		self.assertIsNone(NumberTheory.pollard_rho(n, max_iterations = 10))

	def test_carryless_multiplication(self):
		for x in [ 0, 1, 2, 3, 4, 5, 123, 267, 498327849327 ]:
			self.assertEqual(NumberTheory.cl_mul(0, x), 0)
			self.assertEqual(NumberTheory.cl_mul(x, 0), 0)
			self.assertEqual(NumberTheory.cl_mul(1, x), x)
			self.assertEqual(NumberTheory.cl_mul(x, 1), x)
			self.assertEqual(NumberTheory.cl_mul(2, x), 2 * x)
			self.assertEqual(NumberTheory.cl_mul(x, 2), 2 * x)
			self.assertEqual(NumberTheory.cl_mul(x, 1024), 1024 * x)
			self.assertEqual(NumberTheory.cl_mul(1024, x), 1024 * x)

			self.assertEqual(NumberTheory.cl_mul(x, 1 | 2 | 8 | 256), (1 * x) ^ (2 * x) ^ (8 * x) ^ (256 * x))
			self.assertEqual(NumberTheory.cl_mul(1 | 2 | 8 | 256, x), (1 * x) ^ (2 * x) ^ (8 * x) ^ (256 * x))

	def test_polynomial_reduction(self):
		self.assertEqual(NumberTheory.binpoly_reduce(0, 0x10001), 0)
		self.assertEqual(NumberTheory.binpoly_reduce(0x123, 0x10001), 0x123)
		self.assertEqual(NumberTheory.binpoly_reduce(0x1234, 0x10001), 0x1234)
		self.assertEqual(NumberTheory.binpoly_reduce(0x12345, 0x10001), 0x2344)
		self.assertEqual(NumberTheory.binpoly_reduce(0x20000, 0x10001), 0x2)

	def test_sqrt_3_mod_4(self):
		p = 9937818373633759003
		self.assertEqual(p % 4, 3)

		for value in [ 1, 123, 123456789, 0x123456789 ]:
			value = value % p
			sqr = (value * value) % p
			(sqrt_pos, sqrt_neg) = NumberTheory.sqrt_mod_p(sqr, p)
			self.assertEqual((sqrt_pos & 1), 0)
			self.assertEqual((sqrt_neg & 1), 1)
			self.assertEqual((sqrt_pos * sqrt_pos) % p, sqr)
			self.assertEqual((sqrt_neg * sqrt_neg) % p, sqr)

	def test_sqrt_5_mod_8(self):
		for p in [ 11948800825345174421 ]:
			self.assertEqual(p % 8, 5)

			for value in [ 1, 123, 123456789, 0x123456789 ]:
				value = value % p
				sqr = (value * value) % p
				(sqrt_pos, sqrt_neg) = NumberTheory.sqrt_mod_p(sqr, p)
				self.assertEqual((sqrt_pos & 1), 0)
				self.assertEqual((sqrt_neg & 1), 1)
				self.assertEqual((sqrt_pos * sqrt_pos) % p, sqr)

	def test_hweight_margin(self):
		r = int.from_bytes(os.urandom(16), byteorder = "little")
		self.assertTrue(NumberTheory.hamming_weight_analysis(r).plausibly_random)

		n = 0x10000000000000
		self.assertFalse(NumberTheory.hamming_weight_analysis(n).plausibly_random)

	def test_modinv_exception(self):
		with self.assertRaises(InvalidInputException):
			NumberTheory.modinv(0, 101)

	def test_probable_prime(self):
		self.assertTrue(NumberTheory.is_probable_prime(2))
		self.assertTrue(NumberTheory.is_probable_prime(3))
		self.assertTrue(NumberTheory.is_probable_prime(5))
		self.assertTrue(NumberTheory.is_probable_prime(101))
		self.assertFalse(NumberTheory.is_probable_prime(0))
		self.assertFalse(NumberTheory.is_probable_prime(1))
		self.assertFalse(NumberTheory.is_probable_prime(4))

	def test_iterprimes(self):
		primes = [ value for (no, value) in zip(range(25), NumberTheory.iter_primes()) ]
		self.assertEqual(primes, [ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97])

	def test_find_small_factor(self):
		self.assertEqual(NumberTheory.find_small_factor(7 * 2003), 7)
		self.assertEqual(NumberTheory.find_small_factor(2 * 2003), 2)
		self.assertEqual(NumberTheory.find_small_factor(71 * 2003), 71)
		self.assertEqual(NumberTheory.find_small_factor(2003), None)

	def test_factor(self):
		self.assertEqual(list(sorted(NumberTheory.factor(101 * 211))), [ 101, 211 ])
		self.assertEqual(list(sorted(NumberTheory.factor(2 ** 4))), [ 2, 2, 2, 2 ])
		self.assertEqual(list(sorted(NumberTheory.factor(2 * 2 * 3 * 3 * 5))), [ 2, 2, 3, 3, 5 ])

	def test_possible_divisors(self):
		self.assertEqual(list(sorted(NumberTheory.possible_divisors([ 2, 2, 3 ]))), [ 1, 2, 3, 4, 6, 12 ])
		self.assertEqual(list(sorted(NumberTheory.possible_divisors([ 2, 3, 5 ]))), [ 1, 2, 3, 5, 6, 10, 15, 30 ])

	def test_isqrt(self):
		self.assertEqual(NumberTheory.isqrt(0), 0)
		self.assertEqual(NumberTheory.isqrt(1), 1)
		self.assertEqual(NumberTheory.isqrt(2), 1)
		self.assertEqual(NumberTheory.isqrt(3), 1)
		self.assertEqual(NumberTheory.isqrt(4), 2)
		self.assertEqual(NumberTheory.isqrt(5), 2)
		self.assertEqual(NumberTheory.isqrt(27), 5)
		self.assertEqual(NumberTheory.isqrt(35), 5)
		self.assertEqual(NumberTheory.isqrt(36), 6)
		self.assertEqual(NumberTheory.isqrt(123456789), 11111)
		self.assertEqual(NumberTheory.isqrt(1234567890), 35136)
