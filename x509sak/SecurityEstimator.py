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
import calendar
import datetime
from x509sak.NumberTheory import NumberTheory
from x509sak.ModulusDB import ModulusDB
from x509sak.CurveDB import CurveDB
from x509sak.OID import OIDDB, OID
from x509sak.Exceptions import LazyDeveloperException
from x509sak.AlgorithmDB import HashFunctions, SignatureAlgorithms
import x509sak.ASN1Models as ASN1Models
import pyasn1.codec.der.decoder

class AnalysisOptions(object):
	class RSATesting(enum.IntEnum):
		Full = 0
		Some = 1
		Fast = 2

	def __init__(self, rsa_testing = RSATesting.Full, include_raw_data = False):
		assert(isinstance(rsa_testing, self.RSATesting))
		self._rsa_testing = rsa_testing
		self._include_raw_data = include_raw_data

	@property
	def rsa_testing(self):
		return self._rsa_testing

	@property
	def include_raw_data(self):
		return self._include_raw_data

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

	def __init__(self, analysis_options = None):
		if analysis_options is None:
			analysis_options = AnalysisOptions()
		self._analysis_options = analysis_options

	@classmethod
	def register(cls, estimator_class):
		alg_name = estimator_class._ALG_NAME
		if alg_name is None:
			raise Exception("No algorithm name defined to register by.")
		if alg_name in cls._KNOWN_ALGORITHMS:
			raise Exception("Trying to re-register algorithm: %s" % (alg_name))
		cls._KNOWN_ALGORITHMS[alg_name] = estimator_class

	@classmethod
	def algorithm(cls, alg_name, analysis_options = None):
		if alg_name not in cls._KNOWN_ALGORITHMS:
			raise KeyError("Algorithm quality of '%s' cannot be estimated, Estimator class not registered." % (alg_name))
		return cls._KNOWN_ALGORITHMS[alg_name](analysis_options = analysis_options)

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

	def __init__(self, analysis_options = None):
		super().__init__(analysis_options = analysis_options)
		if self._analysis_options.rsa_testing == AnalysisOptions.RSATesting.Full:
			self._test_probable_prime = True
			self._pollards_rho_iterations = 10000
		elif self._analysis_options.rsa_testing == AnalysisOptions.RSATesting.Some:
			self._test_probable_prime = False
			self._pollards_rho_iterations = 5
		elif self._analysis_options.rsa_testing == AnalysisOptions.RSATesting.Fast:
			self._test_probable_prime = False
			self._pollards_rho_iterations = 0
		else:
			raise LazyDeveloperException(NotImplemented, self._analysis_options.rsa_testing)

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

	def analyze(self, pubkey):
		result = {
			"n": {
				"bits":		pubkey.n.bit_length(),
				"security":	self.analyze_n(pubkey.n),
			},
			"e": {
				"security":	self.analyze_e(pubkey.e),
			},
		}
		if self._analysis_options.include_raw_data:
			result["n"]["value"] = pubkey.n
			result["e"]["value"] = pubkey.e
		return result
SecurityEstimator.register(RSASecurityEstimator)


class ECCSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "ecc"
	def analyze(self, pubkey):
		curve = CurveDB().instanciate(oid = pubkey.curve_oid)

		# Check that the encoded public key point is on curve first
		Q = curve.point(pubkey.x, pubkey.y)
		if not Q.on_curve():
			return {
				"bits":			0,
				"verdict":		Verdict.NO_SECURITY,
				"common":		Commonness.HIGHLY_UNUSUAL,
				"text":			"Public key point Q is not on the underlying curve %s." % (pubkey.curve),
			}

		# Check that the encoded public key is not Gx
		if pubkey.x == curve.Gx:
			return {
				"bits":			0,
				"verdict":		Verdict.NO_SECURITY,
				"common":		Commonness.HIGHLY_UNUSUAL,
				"text":			"Public key point Q_x is equal to generator G_x on curve %s." % (pubkey.curve),
			}

		# We assume, completely out-of-the-blue and worst-case estimate, 32
		# automorphisms that could be present for any curve (see Duursma et
		# al., "Speeding up the discrete log computation on curves with
		# automorphisms"). Therefore, for a given order n, we estimate the
		# complexity in bits as:
		#
		# b = log2(sqrt(n / 32)) = (log2(n) / 2) - 2.5
		approx_curve_order_bits = math.log(curve.n, 2)
		bits_security = (approx_curve_order_bits / 2) - 2.5
		bits_security = math.floor(bits_security)
		security_estimate = self.algorithm("bits").analyze(bits_security)

		# Check if the affine X/Y coordinates of the public key are about the
		# same length as the curve order. If randomly generated, both X and Y
		# should be about the same		bitlength as the generator order. We're
		# warning for the topmost 32 bits cleared, i.e.  false positive rate
		# should be about p = 2^(-32) = 0.2 ppb = 1 : 4 billion.  This isn't
		# necessarily a security issue, but it is uncommon and unusual,
		# therefore we report it.
		field_len = curve.field_bits
		x_len = pubkey.x.bit_length()
		y_len = pubkey.y.bit_length()
		if ((field_len - x_len) >= 32) or ((field_len - y_len) >= 32):
			security_estimate["common"] = Commonness.HIGHLY_UNUSUAL
			security_estimate["text"] += " Affine public key field element lengths (x = %d bit, y = %d bit) differ from field element width of %d bits more than 32 bits; this is likely not coincidential." % (x_len, y_len, field_len)

		avg_weight = field_len // 2
		x_weight = NumberTheory.hamming_weight(pubkey.x)
		y_weight = NumberTheory.hamming_weight(pubkey.y)
		if (abs(avg_weight - x_weight) >= 32) or (abs(avg_weight - y_weight) >= 32):
			security_estimate["common"] = Commonness.HIGHLY_UNUSUAL
			security_estimate["text"] += " Hamming weight of public key field element lengths (H_x = %d, H_y = %d) differs from expected average of %d more than 32; this is likely not coincidential." % (x_weight, y_weight, avg_weight)

		return security_estimate
SecurityEstimator.register(ECCSecurityEstimator)

class CrtValiditySecurityEstimator(SecurityEstimator):
	_ALG_NAME = "crt_validity"

	def _format_datetime(self, dt):
		return {
			"iso":		dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
			"timet":	calendar.timegm(dt.utctimetuple()),
		}

	def analyze(self, not_before, not_after):
		return {
			"not_before":	self._format_datetime(not_before),
			"not_after":	self._format_datetime(not_after),
		}
		return "DATE"

SecurityEstimator.register(CrtValiditySecurityEstimator)


class SignatureSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "sig"

	def analyze(self, signature_alg_oid, signature_alg_params, signature):
		try:
			signature_alg_name = OIDDB.SignatureAlgorithms[signature_alg_oid]
		except KeyError:
			return {
				"common":		Commonness.HIGHLY_UNUSUAL,
				"text":			"Unsupported signature algorithm used (OID %s), cannot make security determination." % (signature_alg_oid),
			}

		if signature_alg_name not in SignatureAlgorithms:
			raise LazyDeveloperException("Signature OID %s known as %s, but cannot determine signature function/hash function from it." % (signature_alg_oid, signature_alg_name))
		signature_alg = SignatureAlgorithms[signature_alg_name]

		if signature_alg.hash_fnc is not None:
			hash_fnc = signature_alg.hash_fnc
		elif signature_alg.name == "RSASSA-PSS":
			# Need to look at parameters to determine hash function
			(asn1, tail) = pyasn1.codec.der.decoder.decode(signature_alg_params, asn1Spec = ASN1Models.RSASSA_PSS_Params())
			if asn1["hashAlgorithm"].hasValue():
				hash_oid = OID.from_str(str(asn1["hashAlgorithm"]["algorithm"]))
				hash_name = OIDDB.HashFunctions[hash_oid]
				hash_fnc = HashFunctions[hash_name]
			else:
				# Default for RSASSA-PSS is SHA-1
				hash_fnc = HashFunctions["sha1"]
		else:
			raise LazyDeveloperException("Unable to determine hash function for signature algorithm %s." % (signature_alg.name))

		return {
			"sig_alg":		signature_alg.name,
			"sig_fnc":		self.algorithm("sig_fnc", analysis_options = self._analysis_options).analyze(signature_alg.sig_fnc),
			"hash_fnc":		self.algorithm("hash_fnc", analysis_options = self._analysis_options).analyze(hash_fnc),
		}

SecurityEstimator.register(SignatureSecurityEstimator)


class CrtExtensionsSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "crt_exts"

	def analyze(self, extensions):
		return "TODO_CRT_EXTS"
SecurityEstimator.register(CrtExtensionsSecurityEstimator)

class SignatureFunctionSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "sig_fnc"

	def analyze(self, sig_fnc):
		return {
			"name":			sig_fnc.name,
		}
SecurityEstimator.register(SignatureFunctionSecurityEstimator)


class HashFunctionSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "hash_fnc"

	def analyze(self, hash_fnc):
		if hash_fnc.derating is None:
			bits_security = hash_fnc.output_bits / 2
		else:
			bits_security = hash_fnc.derating.security_lvl_bits
		result = {
			"name":			hash_fnc.name,
			"bitlen":		hash_fnc.output_bits,
			"security":		self.algorithm("bits", analysis_options = self._analysis_options).analyze(bits_security)
		}
		if hash_fnc.derating is not None:
			result["security"]["text"] += " Derated from ideal %d bits security level because of %s." % (hash_fnc.output_bits / 2, hash_fnc.derating.reason)
		return result
SecurityEstimator.register(HashFunctionSecurityEstimator)
