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

import math
import pyasn1
from x509sak.ModulusDB import ModulusDB
from x509sak.NumberTheory import NumberTheory
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, AnalysisOptions, Verdict, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements
from x509sak.Exceptions import LazyDeveloperException

@BaseEstimator.register
class RSASecurityEstimator(BaseEstimator):
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
		if e < 1:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Is_Zero_Or_Negative, "RSA exponent is zero or negative, this is a malicious key.", bits = 0)
		elif e == 1:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Is_0x1, "RSA exponent is 1, this is a malicious key.", bits = 0)
		elif e in [ 3, 5, 7, 17, 257 ]:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Small, "RSA exponent is small, but fairly common.", verdict = Verdict.MEDIUM, commonness = Commonness.FAIRLY_COMMON)
		elif e < 65537:
			return SecurityJudgement(JudgementCode.RSA_Exponent_SmallUnusual, "RSA exponent is small and an uncommon choice.", verdict = Verdict.MEDIUM, commonness = Commonness.UNUSUAL)
		elif e == 65537:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Is_0x10001, "RSA exponent is the most common choice.", verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.COMMON)
		else:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Large, "RSA exponent is uncommonly large. This need not be a weakness, but is highly unusual and may cause interoperability issues.", verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.HIGHLY_UNUSUAL)

	def analyze_n(self, n):
		judgements = SecurityJudgements()

		if n < 0:
			judgements += SecurityJudgement(JudgementCode.RSA_Modulus_Negative, "Modulus uses incorrect encoding, representation is a negative integer.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)

			# Fix up n so it's a positive integer for the rest of the tests
			bitlen = (n.bit_length() + 7) // 8 * 8
			mask = (1 << bitlen) - 1
			n = n & mask

		if self._test_probable_prime:
			if NumberTheory.is_probable_prime(n):
				judgements += SecurityJudgement(JudgementCode.RSA_Modulus_Prime, "Modulus is prime, not a compound integer as we would expect for RSA.", bits = 0)

		if self._pollards_rho_iterations > 0:
			small_factor = NumberTheory.pollard_rho(n, max_iterations = self._pollards_rho_iterations)
			if small_factor is not None:
				judgements += SecurityJudgement(JudgementCode.RSA_Modulus_Factorable, "Modulus has small factor (%d) and is therefore trivially factorable." % (small_factor), bits = 0)

		match = ModulusDB().find(n)
		if match is not None:
			judgements += SecurityJudgement(JudgementCode.RSA_Modulus_FactorizationKnown, "Modulus is known to be compromised: %s" % (match.text), bits = 0)

		hweight_analysis = NumberTheory.hamming_weight_analysis(n)
		if not hweight_analysis.plausibly_random:
			judgements += SecurityJudgement(JudgementCode.RSA_Modulus_BitBias, "Modulus does not appear to be random. Expected a Hamming weight between %d and %d for a %d bit modulus, but found Hamming weight %d." % (hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight, hweight_analysis.bitlen, hweight_analysis.hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		# We estimate the complexity of factoring the modulus by the asymptotic
		# complexity of the GNFS.
		log2_n = n.bit_length()
		log_n = log2_n * math.log(2)
		bits_security = 2.5596 * (log_n ** (1/3)) * (math.log(log_n) ** (2/3))
		bits_security = math.floor(bits_security)
		judgements += self.algorithm("bits").analyze(JudgementCode.RSA_Modulus_Length, bits_security)

		return judgements

	def analyze(self, pubkey):
		judgements = SecurityJudgements()
		result = {
			"cryptosystem":	"rsa",
			"specific": {
				"n": {
					"bits":		pubkey.n.bit_length(),
					"security":	self.analyze_n(pubkey.n),
				},
				"e": {
					"security":	self.analyze_e(pubkey.e),
				},
			},
			"security": judgements,
		}

		if pubkey.params is None:
			judgements += SecurityJudgement(JudgementCode.RSA_Parameter_Field_Not_Present, "RSA parameter field should be present and should be of Null type, but is not present at all. This is a direct violation of RFC3279, Sect. 2.2.1.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)
		else:
			# There is a parameters field present, it must be NULL
			try:
				(asn1_params, tail) = pyasn1.codec.der.decoder.decode(bytes(pubkey.params))
				if not isinstance(asn1_params, pyasn1.type.univ.Null):
					judgements += SecurityJudgement(JudgementCode.RSA_Parameter_Field_Not_Null, "RSA parameter field should be present and should be of Null type, but has different ASN.1 type. This is a direct violation of RFC3279, Sect. 2.2.1.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)
			except pyasn1.error.PyAsn1Error:
				judgements += SecurityJudgement(JudgementCode.RSA_Parameter_Field_Not_Null, "RSA parameter field should be present and should be of Null type, but has different non-DER type. This is a direct violation of RFC3279, Sect. 2.2.1.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)

		judgements += result["specific"]["n"]["security"]
		judgements += result["specific"]["e"]["security"]

		if self._analysis_options.include_raw_data:
			result["n"]["value"] = pubkey.n
			result["e"]["value"] = pubkey.e
		return result
