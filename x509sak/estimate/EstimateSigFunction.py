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

from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, ExperimentalJudgementCodes, Verdict, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements

@BaseEstimator.register
class SignatureFunctionSecurityEstimator(BaseEstimator):
	_ALG_NAME = "sig_fnc"

	def analyze(self, sig_fnc):
		judgements = SecurityJudgements()
		if sig_fnc.value.name == "rsa-ssa-pss":
			judgements += SecurityJudgement(JudgementCode.SignatureFunction_UncommonPaddingScheme, "Not widely used padding scheme for RSA.", compatibility = Compatibility.LIMITED_SUPPORT)
		elif sig_fnc.value.name == "eddsa":
			judgements += SecurityJudgement(JudgementCode.SignatureFunction_UncommonCryptosystem, "Not widely used cryptosystem.", verdict = Verdict.BEST_IN_CLASS, compatibility = Compatibility.LIMITED_SUPPORT)
		else:
			judgements += SecurityJudgement(JudgementCode.SignatureFunction_Common, "Commonly used signature function.", commonness = Commonness.COMMON)

		return {
			"name":			sig_fnc.name,
			"pretty":		sig_fnc.value.pretty_name,
			"security":		judgements,
		}
