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
from x509sak.estimate import Verdict, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement

@BaseEstimator.register
class CertificateEstimator(BaseEstimator):
	_ALG_NAME = "certificate"

	def analyze(self, cert, analysis_options = None):
		result = {
			"subject":		self.algorithm("dn", analysis_options = analysis_options).analyze(cert.subject),
			"issuer":		self.algorithm("dn", analysis_options = analysis_options).analyze(cert.issuer),
			"validity":		self.algorithm("crt_validity", analysis_options = analysis_options).analyze(cert),
			"pubkey":		self.algorithm("pubkey", analysis_options = analysis_options).analyze(cert.pubkey),
			"extensions":	self.algorithm("crt_exts", analysis_options = analysis_options).analyze(cert),
			"signature":	self.algorithm("sig", analysis_options = analysis_options).analyze(cert.signature_alg_oid, cert.signature_alg_params, cert.signature),
			"purpose":		self.algorithm("purpose", analysis_options = analysis_options).analyze(cert),
			"misc":			self.algorithm("crt_misc", analysis_options = analysis_options).analyze(cert),
		}
		if (analysis_options is not None) and analysis_options.include_raw_data:
			result["raw"] = base64.b64encode(cert.der_data).decode("ascii")
		return result
