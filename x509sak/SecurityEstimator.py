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
import pyasn1.codec.der.decoder
from x509sak.NumberTheory import NumberTheory
from x509sak.ModulusDB import ModulusDB
from x509sak.OID import OIDDB, OID
from x509sak.Exceptions import LazyDeveloperException, UnknownAlgorithmException
from x509sak.AlgorithmDB import HashFunctions, SignatureAlgorithms
import x509sak.ASN1Models as ASN1Models

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

class SecurityJudgement(object):
	def __init__(self, text, bits = None, verdict = None, commonness = None):
		assert((bits is None) or isinstance(bits, (int, float)))
		assert((verdict is None) or isinstance(verdict, Verdict))
		assert((commonness is None) or isinstance(commonness, Commonness))
		self._text = text
		self._bits = bits
		self._verdict = verdict
		self._commonness = commonness
		if self._bits == 0:
			if self._verdict is None:
				self._verdict = Verdict.NO_SECURITY
			if self._commonness is None:
				self._commonness = Commonness.HIGHLY_UNUSUAL

	@property
	def text(self):
		return self._text

	@property
	def bits(self):
		return self._bits

	@property
	def verdict(self):
		return self._verdict

	@property
	def commonness(self):
		return self._commonness

	@staticmethod
	def _minof(a, b):
		if (a is None) and (b is None):
			return None
		elif (a is not None) and (b is not None):
			# Take minimum
			return min(a, b)
		elif b is None:
			return a
		else:
			return b

	def __add__(self, other):
		text = self.text + " " + other.text
		bits = self._minof(self.bits, other.bits)
		verdict = self._minof(self.verdict, other.verdict)
		commonness = self._minof(self.commonness, other.commonness)
		return SecurityJudgement(text, bits = bits, verdict = verdict, commonness = commonness)

	def to_dict(self):
		result = {
			"text":			self.text,
			"bits":			self.bits,
			"verdict":		self.verdict,
			"commonness":	self.commonness,
		}
		return { key: value for (key, value) in result.items() if value is not None }

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
		raise NotImplementedError("method 'analyze'")


class BitsSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "bits"

	def analyze(self, bits):
		if bits < 64:
			judgement = SecurityJudgement("Breakable with little effort (commercial-off-the-shelf hardware).", bits = bits, verdict = Verdict.NO_SECURITY, commonness = Commonness.HIGHLY_UNUSUAL)
		elif bits < 80:
			judgement = SecurityJudgement("Probably breakable with specialized hardware (limited purpose computers).", bits = bits, verdict = Verdict.WEAK, commonness = Commonness.UNUSUAL)
		elif bits < 104:
			judgement = SecurityJudgement("Nontrivial to break, but comparatively weak.", bits = bits, verdict = Verdict.WEAK, commonness = Commonness.UNUSUAL)
		elif bits < 160:
			# 128 Bit security level
			judgement = SecurityJudgement("High level of security.", bits = bits, verdict = Verdict.HIGH, commonness = Commonness.COMMON)
		elif bits < 224:
			# 192 Bit security level
			judgement = SecurityJudgement("Very high level of security.", bits = bits, verdict = Verdict.HIGH, commonness = Commonness.COMMON)
		else:
			# 256 bit security level
			judgement = SecurityJudgement("Exceptionally high level of security.", bits = bits, verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.COMMON)
		return judgement
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
			return SecurityJudgement("RSA exponent is 1, this is a malicious key.", bits = 0)
		elif e in [ 3, 5, 7, 17, 257 ]:
			return SecurityJudgement("RSA exponent is small, but fairly common.", verdict = Verdict.MEDIUM, commonness = Commonness.FAIRLY_COMMON)
		elif e < 65537:
			return SecurityJudgement("RSA exponent is small and an uncommon choice.", verdict = Verdict.MEDIUM, commonness = Commonness.UNUSUAL)
		elif e == 65537:
			return SecurityJudgement("RSA exponent is the most common choice.", verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.COMMON)
		else:
			return SecurityJudgement("RSA exponent is uncommonly large. This need not be a weakness, but is highly unusual and may cause interoperability issues.", verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.HIGHLY_UNUSUAL)

	def analyze_n(self, n):
		if self._test_probable_prime:
			if NumberTheory.is_probable_prime(n):
				return SecurityJudgement("Modulus is prime, not a compound integer as we would expect for RSA.", bits = 0)

		if self._pollards_rho_iterations > 0:
			small_factor = NumberTheory.pollard_rho(n, max_iterations = self._pollards_rho_iterations)
			if small_factor is not None:
				return SecurityJudgement("Modulus has small factor (%d) and is therefore trivially factorable." % (small_factor), bits = 0)

		match = ModulusDB().find(n)
		if match is not None:
			return SecurityJudgement("Modulus is known to be compromised: %s" % (match.text), bits = 0)

		judgement = None
		hweight_analysis = NumberTheory.hamming_weight_analysis(n)
		if not hweight_analysis.plausibly_random:
			judgement = SecurityJudgement("Modulus does not appear to be random. Expected a Hamming weight between %d and %d for a %d bit modulus, but found Hamming weight %d." % (hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight, hweight_analysis.bitlen, hweight_analysis.hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		# We estimate the complexity of factoring the modulus by the asymptotic
		# complexity of the GNFS.
		log2_n = n.bit_length()
		log_n = log2_n * math.log(2)
		bits_security = 2.5596 * (log_n ** (1/3)) * (math.log(log_n) ** (2/3))
		bits_security = math.floor(bits_security)
		if judgement is not None:
			return judgement + self.algorithm("bits").analyze(bits_security)
		else:
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
		result["security"] = result["n"]["security"] + result["e"]["security"]
		if self._analysis_options.include_raw_data:
			result["n"]["value"] = pubkey.n
			result["e"]["value"] = pubkey.e
		return result
SecurityEstimator.register(RSASecurityEstimator)


class ECCSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "ecc"
	def analyze(self, pubkey):
		curve = pubkey.curve

		# Check that the encoded public key point is on curve first
		Q = curve.point(pubkey.x, pubkey.y)
		if not Q.on_curve():
			return SecurityJudgement("Public key point Q is not on the underlying curve %s." % (pubkey.curve), bits = 0)

		# Check that the encoded public key is not Gx
		if Q.x == curve.Gx:
			return SecurityJudgement("Public key point Q_x is equal to generator G_x on curve %s." % (pubkey.curve), bits = 0)

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
			security_estimate += SecurityJudgement("Affine public key field element lengths (x = %d bit, y = %d bit) differ from field element width of %d bits more than 32 bits; this is likely not coincidential." % (x_len, y_len, field_len), commonness = Commonness.HIGHLY_UNUSUAL)

		hweight_analysis = NumberTheory.hamming_weight_analysis(pubkey.x)
		if not hweight_analysis.plausibly_random:
			security_estimate += SecurityJudgement("Hamming weight of public key field element's X coordinate is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		hweight_analysis = NumberTheory.hamming_weight_analysis(pubkey.y)
		if not hweight_analysis.plausibly_random:
			security_estimate += SecurityJudgement("Hamming weight of public key field element's Y coordinate is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)

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
		now = datetime.datetime.utcnow()
		if not_before > not_after:
			judgement = SecurityJudgement("'Not before' timestamp is greater than 'not after' timestamp. Certificate is always invalid.", bits = 0)
		elif now < not_before:
			judgement = SecurityJudgement("Certificate is not yet valid, becomes valid in the future.", bits = 0, commonness = Commonness.UNUSUAL)
		elif now > not_after:
			judgement = SecurityJudgement("Certificate has expired.", bits = 0, commonness = Commonness.COMMON)
		else:
			judgement = SecurityJudgement("Certificate is currently valid.", commonness = Commonness.COMMON)

		return {
			"not_before":	self._format_datetime(not_before),
			"not_after":	self._format_datetime(not_after),
			"security":		judgement,
		}

SecurityEstimator.register(CrtValiditySecurityEstimator)


class SignatureSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "sig"

	def analyze(self, signature_alg_oid, signature_alg_params, signature):
		signature_alg = SignatureAlgorithms.lookup("oid", signature_alg_oid)
		if signature_alg is None:
			raise UnknownAlgorithmException("Unsupported signature algorithm used (OID %s), cannot make security determination." % (signature_alg_oid))

		if signature_alg.value.hash_fnc is not None:
			# Signature algorithm requires a particular hash function
			hash_fnc = signature_alg.value.hash_fnc
		elif signature_alg == SignatureAlgorithms.RSASSA_PSS:
			# Need to look at parameters to determine hash function
			(asn1, tail) = pyasn1.codec.der.decoder.decode(signature_alg_params, asn1Spec = ASN1Models.RSASSA_PSS_Params())
			if asn1["hashAlgorithm"].hasValue():
				hash_oid = OID.from_str(str(asn1["hashAlgorithm"]["algorithm"]))
				hash_fnc = HashFunctions.lookup("oid", hash_oid)
				if hash_fnc is None:
					raise UnknownAlgorithmException("Unsupported hash algorithm used for RSA-PSS (OID %s), cannot make security determination." % (hash_oid))
			else:
				# Default for RSASSA-PSS is SHA-1
				hash_fnc = HashFunctions["sha1"]
		else:
			raise LazyDeveloperException("Unable to determine hash function for signature algorithm %s." % (signature_alg.name))

		result = {
			"name":			signature_alg.name,
			"sig_fnc":		self.algorithm("sig_fnc", analysis_options = self._analysis_options).analyze(signature_alg.value.sig_fnc),
			"hash_fnc":		self.algorithm("hash_fnc", analysis_options = self._analysis_options).analyze(hash_fnc),
		}
		result["security"] = result["sig_fnc"]["security"] + result["hash_fnc"]["security"]
		return result

SecurityEstimator.register(SignatureSecurityEstimator)


class CrtExtensionsSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "crt_exts"

	def analyze(self, extensions):
		return "TODO_CRT_EXTS"
SecurityEstimator.register(CrtExtensionsSecurityEstimator)

class SignatureFunctionSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "sig_fnc"

	def analyze(self, sig_fnc):
		if sig_fnc.value.name == "rsa-ssa-pss":
			judgement = SecurityJudgement("Not widely used padding scheme for RSA.", commonness = Commonness.UNUSUAL)
		elif sig_fnc.value.name == "eddsa":
			judgement = SecurityJudgement("Not widely used cryptosystem.", commonness = Commonness.UNUSUAL, verdict = Verdict.BEST_IN_CLASS)
		else:
			judgement = SecurityJudgement("Commonly used signature function.", commonness = Commonness.COMMON)

		return {
			"name":			sig_fnc.name,
			"pretty":		sig_fnc.value.pretty_name,
			"security":		judgement,
		}
SecurityEstimator.register(SignatureFunctionSecurityEstimator)


class HashFunctionSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "hash_fnc"

	def analyze(self, hash_fnc):
		if hash_fnc.value.derating is None:
			bits_security = hash_fnc.value.output_bits / 2
		else:
			bits_security = hash_fnc.value.derating.security_lvl_bits
		result = {
			"name":			hash_fnc.value.name,
			"pretty":		hash_fnc.value.pretty_name,
			"bitlen":		hash_fnc.value.output_bits,
			"security":		self.algorithm("bits", analysis_options = self._analysis_options).analyze(bits_security)
		}
		if hash_fnc.value.derating is not None:
			result["security"] += SecurityJudgement("Derated from ideal %d bits security level because of %s." % (hash_fnc.value.output_bits / 2, hash_fnc.value.derating.reason))
		return result
SecurityEstimator.register(HashFunctionSecurityEstimator)
