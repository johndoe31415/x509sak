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
from x509sak.NumberTheory import NumberTheory
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements

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
		approx_curve_order_bits = math.log(curve.n, 2)
		bits_security = (approx_curve_order_bits / 2) - 2.5
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

		return {
			"cryptosystem":		"ecc/ecdsa",
			"specific":	{
				"curve":		curve.name,
			},
			"security":			judgements,
		}
