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

import pyasn1.codec.der.decoder
from x509sak.OID import OID
import x509sak.ASN1Models as ASN1Models
from x509sak.AlgorithmDB import SignatureAlgorithms, HashFunctions
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements

@BaseEstimator.register
class SignatureSecurityEstimator(BaseEstimator):
	_ALG_NAME = "sig"

	def analyze(self, signature_alg_oid, signature_alg_params, signature):
		judgements = SecurityJudgements()
		signature_alg = SignatureAlgorithms.lookup("oid", signature_alg_oid)
		if signature_alg is None:
			judgements += SecurityJudgement(JudgementCode.Cert_Unknown_SignatureAlgorithm, "Certificate has unknown signature algorithm with OID %s. Cannot make security determination." % (signature_alg_oid), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)
			result = {
				"name":			str(signature_alg_oid),
				"pretty":		str(signature_alg_oid),
				"security":		judgements,
			}
			return result

		if isinstance(signature_alg.value.oid, (tuple, list)):
			# Have more than one OID for this
			if signature_alg.value.oid[0] != signature_alg_oid:
				judgements += SecurityJudgement(JudgementCode.SignatureFunction_NonPreferred_OID, "Signature algorithm uses alternate OID %s for algorithm %s. Preferred OID would be %s." % (signature_alg_oid, signature_alg.name, signature_alg.value.oid[0]), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)

		if signature_alg.value.hash_fnc is not None:
			# Signature algorithm requires a particular hash function
			hash_fnc = signature_alg.value.hash_fnc
		elif signature_alg == SignatureAlgorithms.RSASSA_PSS:
			# Need to look at parameters to determine hash function
			(asn1, tail) = pyasn1.codec.der.decoder.decode(signature_alg_params, asn1Spec = ASN1Models.RSASSA_PSS_Params())
			if asn1["hashAlgorithm"].hasValue():
				hash_oid = OID.from_str(str(asn1["hashAlgorithm"]["algorithm"]))
				hash_fnc = HashFunctions.lookup("oid", hash_oid)
			else:
				# Default for RSASSA-PSS is SHA-1
				hash_fnc = HashFunctions["sha1"]

			if asn1["saltLength"].hasValue():
				saltlen = int(asn1["saltLength"])
			else:
				saltlen = 20
			judgements += self.algorithm("bits").analyze(JudgementCode.RSA_PSS_Salt_Length, saltlen * 8)
		else:
			judgements += SecurityJudgement(JudgementCode.Cert_Unknown_HashAlgorithm, "Certificate has unknown hash algorithm used in signature with OID %s. Cannot make security determination for that part." % (hash_oid), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)

		result = {
			"name":			signature_alg.name,
			"sig_fnc":		self.algorithm("sig_fnc", analysis_options = self._analysis_options).analyze(signature_alg.value.sig_fnc),
			"security":		judgements,
		}
		if hash_fnc is not None:
			result.update({
				"pretty":		signature_alg.value.sig_fnc.value.pretty_name + " with " + hash_fnc.value.pretty_name,
				"hash_fnc":		self.algorithm("hash_fnc", analysis_options = self._analysis_options).analyze(hash_fnc),
			})
		else:
			result.update({
				"pretty":		 "%s with hash function %s" % (signature_alg.value.sig_fnc.value.pretty_name, hash_oid)
			})
		return result
