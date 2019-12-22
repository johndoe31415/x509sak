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
from x509sak.AlgorithmDB import Cryptosystems
from x509sak.NumberTheory import NumberTheory
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, LiteratureReference
from x509sak.ECCMath import PrimeFieldEllipticCurve, BinaryFieldEllipticCurve

@BaseEstimator.register
class ECCSecurityEstimator(BaseEstimator):
	_ALG_NAME = "ecc"

	def analyze(self, pubkey):
		curve = pubkey.curve
		judgements = SecurityJudgements()

		# Check that the encoded public key point is on curve first
		Q = curve.point(pubkey.x, pubkey.y)
		if not Q.on_curve():
			judgements += SecurityJudgement(JudgementCode.ECC_Pubkey_Not_On_Curve, "Public key point Q is not on the underlying curve %s." % (pubkey.curve), bits = 0)

		# Check that the encoded public key is not Gx
		if Q.x == curve.Gx:
			judgements += SecurityJudgement(JudgementCode.ECC_Pubkey_Is_G, "Public key point Q_x is equal to generator G_x on curve %s." % (pubkey.curve), bits = 0)

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
			judgements += SecurityJudgement(JudgementCode.ECC_BinaryFieldKoblitz, "Binary field Koblitz curves (anomalous binary curves) have more efficient attacks than their non-anomalous binary curves; in this case improving attack performance by a factor of ~%.1f." % (speedup), commonness = Commonness.UNUSUAL, literature = literature)

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
			judgements += SecurityJudgement(JudgementCode.ECC_PrimeFieldKoblitz, "Prime field Koblitz curves might have more efficient attacks than non-Koblitz curves. In this case, attack performance improves roughly by a factor of ~%.1f." % (speedup), commonness = Commonness.UNUSUAL, literature = literature)

		bits_security = math.floor(bits_security)
		judgements += self.algorithm("bits").analyze(JudgementCode.ECC_Pubkey_CurveOrder, bits_security)

		# Check if the affine X/Y coordinates of the public key are about the
		# same length as the curve order. If randomly generated, both X and Y
		# should be about the same bitlength as the generator order and the
		# hamming weight should be roughly half of the bitlength of the curve
		# order.
		hweight_analysis = NumberTheory.hamming_weight_analysis(pubkey.x, min_bit_length = curve.field_bits)
		if not hweight_analysis.plausibly_random:
			judgements += SecurityJudgement(JudgementCode.ECC_Pubkey_X_BitBias, "Hamming weight of public key field element's X coordinate is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		hweight_analysis = NumberTheory.hamming_weight_analysis(pubkey.y, min_bit_length = curve.field_bits)
		if not hweight_analysis.plausibly_random:
			judgements += SecurityJudgement(JudgementCode.ECC_Pubkey_Y_BitBias, "Hamming weight of public key field element's Y coordinate is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		if isinstance(curve, BinaryFieldEllipticCurve):
			literature = LiteratureReference(author = [ "Steven D. Galbraith", "Shishay W. Gebregiyorgis" ], title = "Summation polynomial algorithms for elliptic curves in characteristic two", year = 2014, source = "Progress in Cryptology -- INDOCRYPT 2014; LNCS 8885")
			judgements += SecurityJudgement(JudgementCode.ECC_BinaryField, "Binary finite field elliptic curve is used. Recent advances in cryptography show there might be efficient attacks on such curves, hence it is recommended to use prime-field curves instead.", commonness = Commonness.UNUSUAL, literature = literature)

		result = {
			"specific":	{
				"curve":		curve.name,
			},
			"security":			judgements,
		}

		if pubkey.pk_alg.value.cryptosystem == Cryptosystems.ECC_ECDSA:
			result["cryptosystem"] = "ecc/ecdsa"
		elif pubkey.pk_alg.value.cryptosystem == Cryptosystems.ECC_EdDSA:
			result["cryptosystem"] = "ecc/eddsa"
		else:
			raise NotImplementedError("ECC estimator currently not fit to analyze a %s pubkey." % (pubkey.pk_alg.value.cryptosystem.name))

		return result
