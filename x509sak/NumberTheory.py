#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
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

import math
import random
import collections
from x509sak.Exceptions import InvalidInputException

class NumberTheory():
	"""Collection of number theoretic functions and modular arithmetic
	helpers."""

	_HammingWeightAnalysis = collections.namedtuple("HammingWeightAnalysis", [ "value", "bitlen", "hweight", "rnd_min_hweight", "rnd_max_hweight", "plausibly_random" ])

	@classmethod
	def lcm(cls, a, b):
		"""Least common multiple."""
		return (a * b) // cls.gcd(a, b)

	@classmethod
	def gcd(cls, a, b):
		"""Euclidian algorithm to compute greatest common divisor."""
		while b != 0:
			(a, b) = (b, a % b)
		return a

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
		for _ in range(trials):
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
			add_value = rem_product * one_value * moduli[modulus]
			solution += add_value

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
	def pollard_rho(cls, n, max_iterations = None):
		"""Calculate Pollards Rho for a given number n. Returns either a prime
		factor of n or None."""
		def f(x, n):
			return ((x * x) + 1) % n

		(x, y, d) = (2, 2, 1)
		iterations = 0
		while d == 1:
			if (max_iterations is not None) and (iterations == max_iterations):
				return None
			x = f(x, n)
			y = f(f(y, n), n)
			d = cls.gcd(abs(x - y), n)
			iterations += 1
		if 1 < d < n:
			return d
		else:
			assert(d == n)
			return None

	@classmethod
	def cl_mul(cls, x, y):
		"""Carryless multiplication of x * y."""
		assert(isinstance(x, int))
		assert(isinstance(y, int))
		assert(x >= 0)
		assert(y >= 0)
		if x > y:
			(x, y) = (y, x)
		result = 0
		for bit in range(x.bit_length()):
			if x & (1 << bit):
				result ^= (y << bit)
		return result

	@classmethod
	def binpoly_reduce(cls, x, poly):
		"""Binary polynomial reduction of polynomial x against the given
		polynimal."""
		assert(isinstance(x, int))
		assert(isinstance(poly, int))
		assert(x >= 0)
		assert(poly > 0)
		while x >= poly:
			# Determine bit difference
			shift = x.bit_length() - poly.bit_length()
			x ^= (poly << shift)
		return x

	@classmethod
	def sqrt_mod_p(cls, x, p):
		"""Calculates the quadratic residue of x modulo p. Not a generic
		Tonelli-Shanks implementation, works only for p thats's 3 mod 4 or 5
		mod 8."""
		x %= p
		if (p % 4) == 3:
			sqrt = pow(x, (p + 1) // 4, p)
		elif (p % 8) == 5:
			# Two possibilities, depending on if x is a quartic residue modulo
			# p or not
			sqrt_qr = pow(x, (p + 3) // 8, p)
			if pow(sqrt_qr, 2, p) == x:
				# x is a quartic residue mod p
				sqrt = sqrt_qr
			else:
				# x is a quartic non-residue mod p
				sqrt = (sqrt_qr * pow(2, (p - 1) // 4, p)) % p
		else:
			raise NotImplementedError("Need to use Tonelli-Shanks algorithm to find quadratic residues for a p %% 8 == %d" % (p % 8))

		if ((sqrt * sqrt) % p) != (x % p):
			raise InvalidInputException("Given input value has no quadratric residue modulo p.")

		if (sqrt & 1) == 0:
			return (sqrt, p - sqrt)
		else:
			return (p - sqrt, sqrt)

	@classmethod
	def hamming_weight(cls, x):
		assert(isinstance(x, int))
		assert(x >= 0)
		weight = 0
		while x > 0:
			if x & 1:
				weight += 1
			x >>= 1
		return weight

	@classmethod
	def hamming_weight_margin(cls, bits):
		"""When a bitstring of length 'bits' is randomly generated, returns the
		Hamming weight margin in which 99.99% of all values fall. I.e., in
		99.99% of all values, the Hamming weight is between (bits / 2 - margin)
		and (bits / 2 + margin). This is a reasonable approximation that was
		calculated using fityk."""
		a0 = 8.885572
		a1 = 0.1179226
		a2 = 0.02057742
		margin = math.ceil(a0 * math.log(a1 * bits) + a2 * bits)
		if margin < 1:
			margin = 1
		return margin

	@classmethod
	def hamming_weight_analysis(cls, value, min_bit_length = None):
		"""Determines if a value is plausibly random with an error probability
		of around 0.01%."""
		bitlen = value.bit_length()
		if min_bit_length is not None:
			bitlen = max(min_bit_length, bitlen)
		margin = cls.hamming_weight_margin(bitlen)
		rnd_min_hweight = (bitlen // 2) - margin
		rnd_max_hweight = (bitlen // 2) + margin
		hweight = cls.hamming_weight(value)
		plausibly_random = rnd_min_hweight <= hweight <= rnd_max_hweight
		return cls._HammingWeightAnalysis(value = value, bitlen = bitlen, hweight = hweight, rnd_min_hweight = rnd_min_hweight, rnd_max_hweight = rnd_max_hweight, plausibly_random = plausibly_random)
