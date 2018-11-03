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

from x509sak.AlgorithmDB import Cryptosystems
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import Verdict, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement

@BaseEstimator.register
class PublicKeyEstimator(BaseEstimator):
	_ALG_NAME = "pubkey"

	def analyze(self, pubkey, analysis_options = None):
		result = {
			"pubkey_alg":	pubkey.pk_alg.value.name,
		}
		if pubkey.pk_alg.value.cryptosystem == Cryptosystems.RSA:
			result["pretty"] = "RSA with %d bit modulus" % (pubkey.n.bit_length())
			result.update(self.algorithm("rsa", analysis_options = analysis_options).analyze(pubkey))
		elif pubkey.pk_alg.value.cryptosystem == Cryptosystems.ECC_ECDSA:
			result["pretty"] = "ECC on %s" % (pubkey.curve.name)
			result.update(self.algorithm("ecc", analysis_options = analysis_options).analyze(pubkey))
		elif pubkey.pk_alg.value.cryptosystem == Cryptosystems.ECC_EdDSA:
			result["pretty"] = "EdDSA on %s" % (pubkey.curve.name)
			result.update(self.algorithm("eddsa", analysis_options = analysis_options).analyze(pubkey))
		else:
			raise LazyDeveloperException(NotImplemented, pubkey.cryptosystem)
		return result
