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
		(g, x, y) = cls._egcd(a, m)
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
	def _is_probable_prime(cls, p, trials = 10):
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
			if cls._is_probable_prime(n):
				return n

	@classmethod
	def gen_insecure_probable_fastprime(cls, nprimes):
		"""Generate a cryptographically INSECURE probabilistic fast prime
		consisting of n CRT moduli."""
		p = 1
		i = 0
		result = { }
		while i < nprimes:
			p += 2
			if cls._is_probable_prime(p):
				q = random.randint(1, p - 1)
				result[p] = q
				i += 1
		print(result)
		return result

