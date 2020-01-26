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

import math
from x509sak.AlgorithmDB import Cryptosystems
from x509sak.NumberTheory import NumberTheory
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, LiteratureReference
from x509sak.ECCMath import PrimeFieldEllipticCurve, BinaryFieldEllipticCurve
from x509sak.CurveDB import CurveDB

@BaseEstimator.register
class ECCSecurityEstimator(BaseEstimator):
	_ALG_NAME = "ecc"

	def _judge_curve_cofactor(self, curve):
		judgements = SecurityJudgements()

		if curve.h is None:
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_Cofactor_Missing, "Curve cofactor h is not present in explicit domain parameter encoding. This is allowed, but highly unusual.", commonness = Commonness.HIGHLY_UNUSUAL)
		else:
			if curve.h <= 0:
				judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_Cofactor_Invalid, "Curve cofactor h = %d is zero or negative. This is invalid." % (curve.h), bits = 0, commonness = Commonness.HIGHLY_UNUSUAL)
			elif curve.h > 8:
				judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_Cofactor_Large, "Curve cofactor is unusually large, h = %d. This is an indication the curve has non-ideal cryptographic properties; would expect h <= 8." % (curve.h), commonness = Commonness.HIGHLY_UNUSUAL)

			if curve.curvetype == "prime":
				field_size = curve.p
			elif curve.curvetype == "binary":
				# TODO: For GF(p), the number of group elements is simply p.
				# For GF(2^m), I'm fairly certiain it is the reduction
				# polynomial (essentially, it's modular polynomial arithmetic).
				# Not 100% sure though. Verify.
				field_size = curve.int_poly

			# Hasse Theorem on Elliptic Curves:
			# p - (2 * sqrt(p)) + 1 <= #E(F_p) <= p + (2 * sqrt(p)) + 1
			# #E(F_p) = n h
			# h >= (p - (2 * sqrt(p)) + 1) / n
			# h <= (p + (2 * sqrt(p)) + 1) / n
			sqrt_p = NumberTheory.isqrt(field_size)
			hasse_h_min = (field_size - (2 * (sqrt_p + 1)) + 1) // curve.n
			hasse_h_max = (field_size + (2 * (sqrt_p + 1)) + 1) // curve.n

			if not (hasse_h_min <= curve.h <= hasse_h_max):
				literature = LiteratureReference(author = "Helmut Hasse", title = "Zur Theorie der abstrakten elliptischen Funktionenkörper. I, II & III", year = 1936, source = "Crelle's Journal")
				judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_Cofactor_OutsideHasseBound, "Curve cofactor h = %d is outside the Hasse bound (%d <= h <= %d). Cofactor therefore is invalid." % (curve.h, hasse_h_min, hasse_h_max), bits = 0, commonness = Commonness.HIGHLY_UNUSUAL, literature = literature)
		return judgements

	def _judge_curve_embedding_degree(self, curve):
		d = 1
		for k in range(1, 50 + 1):
			d = (d * curve.p) % curve.n
			if d == 1:
				if (k == 1) or (NumberTheory.is_probable_prime(curve.n)):
					fail_text = "k = %d" % (k)
				else:
					fail_text = "k <= %d" % (k)
				literature = LiteratureReference(author = [ "Alfred Menezes", "Scott Vanstone", "Tatsuaki Okamoto" ], title = "Reducing Elliptic Curve Logarithms to Logarithms in a Finite Field", year = 1991, source = "ACM")
				return SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_LowEmbeddingDegree, "This curve has low embedding degree (%s), it fails the MOV condition. It can be compromised using the probabilistic polynomial-time MOV attack." % (fail_text), bits = 0, commonness = Commonness.HIGHLY_UNUSUAL, literature = literature)
		return None

	def _judge_prime_field_curve(self, curve):
		judgements = SecurityJudgements()

		if curve.h is not None:
			# TODO: We might be able to guess the cofactor because of the Hasse bound.
			# E(Fp) = p + 1 - t
			# t = p - E(Fp) + 1
			EFp = curve.n * curve.h
			trace = curve.p - EFp + 1
			if trace == 0:
				literature = LiteratureReference(author = [ "Alfred Menezes", "Scott Vanstone", "Tatsuaki Okamoto" ], title = "Reducing Elliptic Curve Logarithms to Logarithms in a Finite Field", year = 1991, source = "ACM")
				judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_SupersingularCurve, "This curve is supersingular, trace is zero. The curve can be attacked using the probabilistic polynomial-time MOV attack.", bits = 0, commonness = Commonness.HIGHLY_UNUSUAL, literature = literature)
			elif trace == 1:
				literature = LiteratureReference(author = [ "Nigel P. Smart" ], title = "The discrete logarithm problem on elliptic curves of trace one", year = 1997, month = 10, source = "HP Laboratories Bristol")
				judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_AnomalousCurve, "This curve is anomalous, #E(F_p) is equal to p. The curve can be attacked in linear time.", bits = 0, commonness = Commonness.HIGHLY_UNUSUAL, literature = literature)

		p = ((4 * (curve.a ** 3)) + (27 * (curve.b ** 2))) % curve.p
		if p == 0:
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_SingularCurve, "This curve is singular, 4a³ + 27b² = 0 mod p. Mathematical assumptions about the structure of the curve do not hold.", bits = 0, commonness = Commonness.HIGHLY_UNUSUAL)

		return judgements

	def _judge_binary_field_curve(self, curve):
		judgements = SecurityJudgements()

		EFpm = curve.n * curve.h
		if (EFpm % 2) == 1:
			# Supersingular: #E(F_p^m) = 1 mod p
			literature = LiteratureReference(author = [ "Alfred Menezes", "Scott Vanstone", "Tatsuaki Okamoto" ], title = "Reducing Elliptic Curve Logarithms to Logarithms in a Finite Field", year = 1991, source = "ACM")
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_SupersingularCurve, "This curve is supersingular, #E(F_p^m) = 1 mod p. The curve can be attacked using an probabilistic polynomial-time MOV attack.", bits = 0, commonness = Commonness.HIGHLY_UNUSUAL, literature = literature)

		literature = LiteratureReference(author = [ "Steven D. Galbraith", "Shishay W. Gebregiyorgis" ], title = "Summation polynomial algorithms for elliptic curves in characteristic two", year = 2014, source = "Progress in Cryptology -- INDOCRYPT 2014; LNCS 8885")
		judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_BinaryField, "Binary finite field elliptic curve is used. Recent advances in cryptography show there might be efficient attacks on such curves, hence it is recommended to use prime-field curves instead.", commonness = Commonness.UNUSUAL, literature = literature)

		if not NumberTheory.is_probable_prime(curve.m):
			literature = LiteratureReference(author = [ "Jeffrey Hoffstein", "Jill Pipher", "Joseph Silverman" ], title = "An Introduction to Mathematical Cryptography", year = 2008, source = "Springer")
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_WeilDescent, "Binary finite field elliptic curve has a field size that is non-primem, F(2^%d). Weil Descent attacks could be successful.", bits = 0, commonness = Commonness.HIGHLY_UNUSUAL, literature = literature)

		return judgements

	def _check_explicit_curve_params(self, curve):
		judgements = SecurityJudgements()

		curve_db = CurveDB()
		known_curve = curve_db.lookup_by_params(curve)
		if known_curve is None:
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_Name_UnknownExplicit, "Explicit curve domain parameter encoding with domain parameters that are not present in the database. Highly suspect, convervatively rating as broken security.", commonness = Commonness.HIGHLY_UNUSUAL, bits = 0)
		else:
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_Name_UnusedName, "Explicit curve domain parameter encoding is used; curve domain parameters are equal to curve %s (OID %s). Recommend switching to that named curve." % (known_curve.name, known_curve.oid))

		judgements += self._judge_curve_cofactor(curve)

		if curve.curvetype == "binary":
			if len(curve.poly) != len(set(curve.poly)):
				judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_BinaryField_DuplicatePolynomialPower, "ECC field polynomial contains duplicate powers: %s -- Conservatively rating as broken security." % (str(curve.poly)), commonness = Commonness.HIGHLY_UNUSUAL, bits = 0)

			for custom_coeff in curve.poly[1 : -1]:
				if custom_coeff <= 1:
					judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_BinaryField_InvalidPolynomialPower, "ECC field polynomial contains x^%d where it would be expected to see a power of two or higher." % (custom_coeff), commonness = Commonness.HIGHLY_UNUSUAL, bits = 0)
				elif custom_coeff >= curve.m:
					judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_BinaryField_InvalidPolynomialPower, "ECC field polynomial contains x^%d where it would be expected to see a power of less than x^m (i.e., x^%d)." % (custom_coeff, curve.m), commonness = Commonness.HIGHLY_UNUSUAL, bits = 0)
		elif curve.curvetype == "prime":
			# Only check embedding degree for non-named (explicit) curves; it's
			# a comparatively expensive test and we assume that curves in the
			# database are all cryptographically sound.
			judgements += self._judge_curve_embedding_degree(curve)

			# This isn't computationally expensive, but we also assume database
			# curves are cryptographically sound.
			judgements += self._judge_curve_cofactor(curve)

		return judgements

	def _check_explicit_curve_encoding(self, pubkey):
		param_decoding = pubkey.key.decoding_details[0]
		# TODO
#		print(param_decoding.asn1)

	def analyze(self, pubkey):
		curve = pubkey.curve
		judgements = SecurityJudgements()

		# Check that the encoded public key point is on curve first
		Q = curve.point(pubkey.x, pubkey.y)
		if not Q.on_curve():
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_PublicKeyPoint_NotOnCurve, "Public key point Q is not on the underlying curve %s." % (pubkey.curve), bits = 0)

		# Check that the encoded public key is not Gx
		if Q.x == curve.Gx:
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_PublicKeyPoint_IsGenerator, "Public key point Q_x is equal to generator G_x on curve %s." % (pubkey.curve), bits = 0)

		# We assume, completely out-of-the-blue and worst-case estimate, 32
		# automorphisms that could be present for any curve (see Duursma et
		# al., "Speeding up the discrete log computation on curves with
		# automorphisms"). Therefore, for a given order n, we estimate the
		# complexity in bits as:
		#
		# b = log2(sqrt(n / 32)) = (log2(n) / 2) - 2.5
		approx_curve_order_bits = curve.order_bits
		bits_security = (approx_curve_order_bits / 2) - 2.5

		# We then take into account anomalous binary curves (Koblitz curves) as
		# well and use the approximations of Wiener/Zuccherato ("Faster Attacks
		# on Elliptic Curve Cryptosystems")
		literature = LiteratureReference(author = [ "Michael J. Wiener", "Robert J. Zuccherato" ], title = "Faster Attacks on Elliptic Curve Cryptosystems", year = 1999, source = "Selected Areas in Cryptography 1998; LNCS 1556")
		if isinstance(curve, BinaryFieldEllipticCurve) and curve.is_koblitz:
			speedup = math.sqrt(2 * curve.m)
			bits_security -= math.log(speedup, 2)
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_KoblitzCurve, "Binary field Koblitz curves (anomalous binary curves) have more efficient attacks than their non-anomalous binary curves; in this case improving attack performance by a factor of ~%.1f." % (speedup), commonness = Commonness.UNUSUAL, literature = literature)

		if isinstance(curve, PrimeFieldEllipticCurve) and curve.is_koblitz:
			# The math here is a bit shady. Firstly, Koblitz curves over F_p
			# only mean there's an efficiently computable endomorphism (e.g.,
			# R. Gallant (1999); "Faster elliptic curve cryptography using
			# efficient endomorphisms"). We do not check for that, however, but
			# instead rely on dull "b = 0 and a is small" check.
			# Additionally, Wiener and Zuccherato describe curves of form
			# y^2 = x^3 - ax or y^2 = x^3 + b (which, for our a/b check, is not
			# the case) and, for the latter, describe a sqrt(6) speedup. We
			# just take that as is, knowing full well it's just guesswork.
			speedup = math.sqrt(6)
			bits_security -= math.log(speedup, 2)
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_KoblitzCurve, "Prime field Koblitz curves might have more efficient attacks than non-Koblitz curves. In this case, attack performance improves roughly by a factor of ~%.1f." % (speedup), commonness = Commonness.UNUSUAL, literature = literature)

		bits_security = math.floor(bits_security)
		judgements += self.algorithm("bits").analyze(JudgementCode.X509Cert_PublicKey_ECC_CurveOrderInBits, bits_security)

		# Check if the affine X/Y coordinates of the public key are about the
		# same length as the curve order. If randomly generated, both X and Y
		# should be about the same bitlength as the generator order and the
		# hamming weight should be roughly half of the bitlength of the curve
		# order.
		hweight_analysis = NumberTheory.hamming_weight_analysis(pubkey.x, min_bit_length = curve.field_bits)
		if not hweight_analysis.plausibly_random:
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_PublicKeyPoint_X_BitBiasPresent, "Hamming weight of public key field element's X coordinate is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		hweight_analysis = NumberTheory.hamming_weight_analysis(pubkey.y, min_bit_length = curve.field_bits)
		if not hweight_analysis.plausibly_random:
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_PublicKeyPoint_Y_BitBiasPresent, "Hamming weight of public key field element's Y coordinate is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		if isinstance(curve, BinaryFieldEllipticCurve):
			judgements += self._judge_binary_field_curve(curve)
		elif isinstance(curve, PrimeFieldEllipticCurve):
			judgements += self._judge_prime_field_curve(curve)

		if pubkey.curve_source == "specifiedCurve":
			judgements += SecurityJudgement(JudgementCode.X509Cert_PublicKey_ECC_DomainParameters_Name_ExplicitCurve, "Curve uses explicit encoding for domain parameters. Typically, named curves are used; explicit encoding of domain parameters is not recommended and may be rejected by implementations for simplicity reasons.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)
			judgements += self._check_explicit_curve_encoding(pubkey)
			judgements += self._check_explicit_curve_params(curve)

		result = {
			"specific":	{ },
			"security":			judgements,
		}

		if pubkey.pk_alg.value.cryptosystem == Cryptosystems.ECC_ECDSA:
			result["cryptosystem"] = "ecc/ecdsa"
		elif pubkey.pk_alg.value.cryptosystem == Cryptosystems.ECC_EdDSA:
			result["cryptosystem"] = "ecc/eddsa"
		else:
			raise NotImplementedError("ECC estimator currently not fit to analyze a %s pubkey." % (pubkey.pk_alg.value.cryptosystem.name))

		return result
