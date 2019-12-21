#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
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
from pyasn1_modules import rfc3279
from x509sak.OID import OID
import x509sak.ASN1Models as ASN1Models
from x509sak.AlgorithmDB import SignatureAlgorithms, HashFunctions, SignatureFunctions, Cryptosystems
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, RFCReference
from x509sak.NumberTheory import NumberTheory

@BaseEstimator.register
class SignatureSecurityEstimator(BaseEstimator):
	_ALG_NAME = "sig"

	def analyze(self, signature_alg_oid, signature_alg_params, signature, root_cert = None):
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
			if len(tail) > 0:
				judgements += SecurityJudgement(JudgementCode.RSA_PSS_Parameters_TrailingData, "RSA/PSS parameter encoding has %d bytes of trailing data." % (len(tail)), commonness = Commonness.HIGHLY_UNUSUAL)
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

		if signature_alg.value.sig_fnc == SignatureFunctions.ecdsa:
			# Decode ECDSA signature
			try:
				(asn1, tail) = pyasn1.codec.der.decoder.decode(signature, asn1Spec = rfc3279.ECDSA_Sig_Value())
				if len(tail) > 0:
					judgements += SecurityJudgement(JudgementCode.ECDSA_Signature_TrailingData, "ECDSA signature encoding has %d bytes of trailing data." % (len(tail)), commonness = Commonness.HIGHLY_UNUSUAL)

				if root_cert is not None:
					if root_cert.pubkey.pk_alg.value.cryptosystem == Cryptosystems.ECC_ECDSA:
						# Check that this is really a potential parent CA certificate
						ca_curve = root_cert.pubkey.curve
						hweight_analysis = NumberTheory.hamming_weight_analysis(int(asn1["r"]), min_bit_length = ca_curve.field_bits)
						if not hweight_analysis.plausibly_random:
							judgements += SecurityJudgement(JudgementCode.ECDSA_Signature_R_BitBias, "Hamming weight of ECDSA signature R parameter is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)
						hweight_analysis = NumberTheory.hamming_weight_analysis(int(asn1["s"]), min_bit_length = ca_curve.field_bits)
						if not hweight_analysis.plausibly_random:
							judgements += SecurityJudgement(JudgementCode.ECDSA_Signature_S_BitBias, "Hamming weight of ECDSA signature S parameter is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)
			except pyasn1.error.PyAsn1Error:
				standard = RFCReference(rfcno = 3279, sect = "2.2.3", verb = "MUST", text = "To easily transfer these two values as one signature, they MUST be ASN.1 encoded using the following ASN.1 structure:")
				judgements += SecurityJudgement(JudgementCode.ECDSA_Signature_Undecodable, "ECDSA signature cannot be successfully decoded.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		result = {
			"name":				signature_alg.name,
			"sig_fnc":			self.algorithm("sig_fnc").analyze(signature_alg.value.sig_fnc),
			"security":			judgements,
		}
		if hash_fnc is not None:
			result.update({
				"pretty":		signature_alg.value.sig_fnc.value.pretty_name + " with " + hash_fnc.value.pretty_name,
				"hash_fnc":		self.algorithm("hash_fnc").analyze(hash_fnc),
			})
		else:
			result.update({
				"pretty":		 "%s with hash function %s" % (signature_alg.value.sig_fnc.value.pretty_name, hash_oid)
			})
		return result
