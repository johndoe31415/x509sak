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

class NumberTheory(object):
	"""Collection of number theoretic functions and modular arithmetic
	helpers."""

	@classmethod
	def egcd(cls, a, b):
		"""Extended Euclidian algorithm."""
		(s, t, u, v) = (1, 0, 0, 1)
		while True:
			if b == 0:
				return (a, s, t)

			(q, r) = divmod(a, b)
			(a, b, s, t, u, v) = (b, r, u, v, s - (q * u), t - (q * v))

	@classmethod
	def modinv(cls, a, m):
		"""Calculate modular inverse of a modulo m."""
		(g, x, y) = cls.egcd(a, m)
		if g != 1:
			raise Exception("Modular inverse of %d mod %d does not exist" % (a, m))
		else:
			return x % m

	@classmethod
	def _miller_rabin_isprime_round(cls, n):
		"""Single Miller-Rabin primality test round."""
		d = n - 1
		j = 0
		while (d % 2) == 0:
			d //= 2
			j += 1

		a = random.randint(2, n - 2)
		if pow(a, d, n) == 1:
			return True
		for r in range(j):
			if pow(a, d * (2 ** r), n) == n - 1:
				return True
		return False

	@classmethod
	def is_probable_prime(cls, p, trials = 10):
		"""Probabilistic Miller-Rabin primality test for a number p with
		'trials' Miller-Rabin rounds."""
		if p in [ 2, 3 ]:
			return True
		for i in range(trials):
			if not cls._miller_rabin_isprime_round(p):
				return False
		return True

	@classmethod
	def gen_insecure_probable_prime(cls, bitlength):
		"""Generate a cryptographically INSECURE probabilistic (p < 1e-6)
		prime."""
		minval = 2 ** (bitlength - 1)
		maxval = (2 ** bitlength) - 1
		while True:
			n = random.randint(minval, maxval)
			n |= 1
			n |= 2 ** (bitlength - 2)
			if cls.is_probable_prime(n):
				return n

	@classmethod
	def solve_crt(cls, moduli):
		"""Solve the Chinese Remainder Theorem for the given values and
		moduli."""
		# Calculate product of all moduli
		product = 1
		for modulus in moduli.keys():
			product *= modulus

		# Then determine the solution
		solution = 0
		for modulus in moduli.keys():
			if moduli[modulus] == 0:
				continue

			rem_product = product // modulus
			one_value = cls.modinv(rem_product, modulus)
			solution += rem_product * one_value * moduli[modulus]

		return solution % product

	@classmethod
	def iter_primes(cls):
		yield 2
		p = 3
		while True:
			if cls.is_probable_prime(p):
				yield p
			p += 2

	@classmethod
	def __gen_insecure_probable_fastprime(cls, nprimes):
		"""Generate a cryptographically INSECURE probabilistic fast prime
		consisting of n CRT moduli. Must have at least nprimes >= 10 (otherwise
		probability that generation fails and erroneously returns 1)."""
		assert(nprimes >= 10)
		i = 0
		moduli = { }
		for p in cls.iter_primes():
			q = random.randint(1, p - 1)
			moduli[p] = q
			i += 1
			if i == nprimes:
				break
		print(sorted(moduli.items()))
		prime = cls.solve_crt(moduli)
		assert(prime != 1)
		return prime

