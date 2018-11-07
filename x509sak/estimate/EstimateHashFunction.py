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
from x509sak.estimate import JudgementCode
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements

@BaseEstimator.register
class HashFunctionSecurityEstimator(BaseEstimator):
	_ALG_NAME = "hash_fnc"

	def analyze(self, hash_fnc):
		if hash_fnc.value.derating is None:
			bits_security = hash_fnc.value.output_bits / 2
		else:
			bits_security = hash_fnc.value.derating.security_lvl_bits

		judgements = SecurityJudgements()
		judgements += self.algorithm("bits").analyze(JudgementCode.HashFunction_Length, bits_security)
		if hash_fnc.value.derating is not None:
			judgements += SecurityJudgement(JudgementCode.HashFunction_Derated, "Derated from ideal %d bits security level because of %s." % (hash_fnc.value.output_bits / 2, hash_fnc.value.derating.reason))

		result = {
			"name":			hash_fnc.value.name,
			"pretty":		hash_fnc.value.pretty_name,
			"bitlen":		hash_fnc.value.output_bits,
			"security":		judgements,
		}
		return result
