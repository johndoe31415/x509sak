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

import random
from x509sak.tests import BaseTest
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
			p = NumberTheory.gen_insecure_probable_prime(6)
			q = NumberTheory.gen_insecure_probable_prime(6)
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

	def __test_gen_fastprime1(self):
		cnt = 0
		for _ in range(10):
			p = NumberTheory.gen_insecure_probable_fastprime(200)
			if NumberTheory.is_probable_prime(p):
				cnt += 1
			else:
				print("NOPRIME")
		print(cnt)

	def __test_gen_fastprime2(self):
		for n in [ 20, 50, 100, 150, 200, 500 ]:
			p = NumberTheory.gen_insecure_probable_fastprime(n)
			self.assertTrue(NumberTheory.is_probable_prime(p))

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

