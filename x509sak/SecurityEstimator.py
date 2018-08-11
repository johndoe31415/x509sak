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

import enum
import math
from x509sak.NumberTheory import NumberTheory
from x509sak.ModulusDB import ModulusDB

class Verdict(enum.IntEnum):
	NO_SECURITY = 0
	BROKEN = 1
	WEAK = 2
	MEDIUM = 3
	HIGH = 4
	BEST_IN_CLASS = 5

class Commonness(enum.IntEnum):
	HIGHLY_UNUSUAL = 0
	UNUSUAL = 1
	FAIRLY_COMMON = 2
	COMMON = 3

class SecurityEstimator(object):
	_KNOWN_ALGORITHMS = { }
	_ALG_NAME = None

	@classmethod
	def register(cls, estimator_class):
		alg_name = estimator_class._ALG_NAME
		if alg_name is None:
			raise Exception("No algorithm name defined to register by.")
		if alg_name in cls._KNOWN_ALGORITHMS:
			raise Exception("Trying to re-register algorithm: %s" % (alg_name))
		cls._KNOWN_ALGORITHMS[alg_name] = estimator_class

	@classmethod
	def algorithm(cls, alg_name):
		if alg_name not in cls._KNOWN_ALGORITHMS:
			raise KeyError("Algorithm quality of '%s' cannot be estimated, Estimator class not registered." % (alg_name))
		return cls._KNOWN_ALGORITHMS[alg_name]()

	def analyze(self, *args, **kwargs):
		raise Exception(NotImplemented, "method 'analyze'")


class BitsSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "bits"

	def analyze(self, bits):
		if bits < 64:
			result = {
				"verdict":		Verdict.NO_SECURITY,
				"common":		Commonness.HIGHLY_UNUSUAL,
				"text":			"Breakable with little effort (commercial-off-the-shelf hardware).",
			}
		elif bits < 80:
			result = {
				"verdict":		Verdict.WEAK,
				"common":		Commonness.UNUSUAL,
				"text":			"Probably breakable with specialized hardware (limited purpose computers).",
			}
		elif bits < 104:
			result = {
				"verdict":		Verdict.WEAK,
				"common":		Commonness.UNUSUAL,
				"text":			"Nontrivial to break, but comparatively weak.",
			}
		elif bits < 160:
			# 128 Bit security level
			result = {
				"verdict":		Verdict.HIGH,
				"common":		Commonness.COMMON,
				"text":			"High level of security.",
			}
		elif bits < 224:
			# 192 Bit security level
			result = {
				"verdict":		Verdict.HIGH,
				"common":		Commonness.COMMON,
				"text":			"Very high level of security.",
			}
		else:
			# 256 bit security level
			result = {
				"verdict":		Verdict.BEST_IN_CLASS,
				"common":		Commonness.COMMON,
				"text":			"Exceptionally high level of security.",
			}
		result["bits"] = bits
		return result
SecurityEstimator.register(BitsSecurityEstimator)


class RSASecurityEstimator(SecurityEstimator):
	_ALG_NAME = "rsa"

	def __init__(self, test_probable_prime = True, pollards_rho_iterations = 10000):
		self._test_probable_prime = test_probable_prime
		self._pollards_rho_iterations = pollards_rho_iterations

	@staticmethod
	def analyze_e(e):
		if e == 1:
			return {
				"bits":			0,
				"verdict":		Verdict.NO_SECURITY,
				"common":		Commonness.HIGHLY_UNUSUAL,
				"text":			"RSA exponent is 1, this is a malicious key.",
			}
		elif e in [ 3, 5, 7, 17, 257 ]:
			return {
				"verdict":		Verdict.MEDIUM,
				"common":		Commonness.FAIRLY_COMMON,
				"text":			"RSA exponent is small, but fairly common.",
			}
		elif e < 65537:
			return {
				"verdict":		Verdict.MEDIUM,
				"common":		Commonness.UNUSUAL,
				"text":			"RSA exponent is small and an uncommon choice.",
			}
		elif e == 65537:
			return {
				"verdict":		Verdict.BEST_IN_CLASS,
				"common":		Commonness.COMMON,
				"text":			"RSA exponent is completely standard.",
			}
		else:
			return {
				"verdict":		Verdict.BEST_IN_CLASS,
				"common":		Commonness.HIGHLY_UNUSUAL,
				"text":			"RSA exponent is uncommonly large. This need not be a weakness, but is highly unusual and may cause compatibility issues.",
			}

	def analyze_n(self, n):
		if self._test_probable_prime:
			if NumberTheory.is_probable_prime(n):
				return {
					"bits":			0,
					"verdict":		Verdict.NO_SECURITY,
					"common":		Commonness.HIGHLY_UNUSUAL,
					"text":			"Modulus is prime, not a compound integer as we would expect for RSA.",
				}

		if self._pollards_rho_iterations > 0:
			small_factor = NumberTheory.pollard_rho(n, max_iterations = self._pollards_rho_iterations)
			if small_factor is not None:
				return {
					"bits":			0,
					"verdict":		Verdict.NO_SECURITY,
					"common":		Commonness.HIGHLY_UNUSUAL,
					"text":			"Modulus has small factors (%d), is trivially factorable." % (small_factor),
				}

		match = ModulusDB().find(n)
		if match is not None:
			return {
				"bits":			0,
				"verdict":		Verdict.NO_SECURITY,
				"common":		Commonness.HIGHLY_UNUSUAL,
				"text":			"Modulus found in public modulus database: %s" % (match.text),
			}

		# We estimate the complexity of factoring the modulus by the asymptotic
		# complexity of the GNFS.
		log2_n = n.bit_length()
		log_n = log2_n * math.log(2)
		bits_security = 2.5596 * (log_n ** (1/3)) * (math.log(log_n) ** (2/3))
		bits_security = math.floor(bits_security)
		return self.algorithm("bits").analyze(bits_security)

	def analyze(self, n, e):
		return {
			"n":	self.analyze_n(n),
			"e":	self.analyze_e(e),
		}
SecurityEstimator.register(RSASecurityEstimator)
