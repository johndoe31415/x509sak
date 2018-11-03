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

import pyasn1
from x509sak.OID import OID, OIDDB
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Verdict, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements

@BaseEstimator.register
class CrtMiscSecurityEstimator(BaseEstimator):
	_ALG_NAME = "crt_misc"

	def analyze(self, certificate):
		judgements = SecurityJudgements()
		if certificate.version != 3:
			judgements += SecurityJudgement(JudgementCode.Cert_Version_Not_3, "Certificate version is v%d, usually would expect a v3 certificate." % (certificate.version), commonness = Commonness.HIGHLY_UNUSUAL)

		if certificate.serial < 0:
			judgements += SecurityJudgement(JudgementCode.Cert_Serial_Negative, "Certificate serial number is a negative value. This is a direct violation of RFC5280, Sect. 4.1.2.2.", compatibility = Compatibility.STANDARDS_VIOLATION)
		elif certificate.serial == 0:
			judgements += SecurityJudgement(JudgementCode.Cert_Serial_Zero, "Certificate serial number is zero. This is a direct violation of RFC5280, Sect. 4.1.2.2.", compatibility = Compatibility.STANDARDS_VIOLATION)

		try:
			cert_reencoding = pyasn1.codec.der.encoder.encode(certificate.asn1)
			if cert_reencoding != certificate.der_data:
				judgements += SecurityJudgement(JudgementCode.Cert_Invalid_DER, "Certificate uses invalid DER encoding. Decoding and re-encoding yields %d byte blob while original was %d bytes." % (len(cert_reencoding), len(certificate.der_data)), compatibility = Compatibility.STANDARDS_VIOLATION)
		except pyasn1.error.PyAsn1Error:
			judgements += SecurityJudgement(JudgementCode.Cert_Invalid_DER, "Certificate uses invalid DER encoding. Re-encoding was not possible.", compatibility = Compatibility.STANDARDS_VIOLATION)

		try:
			pubkey_reencoding = pyasn1.codec.der.encoder.encode(certificate.pubkey.recreate().asn1)
			if pubkey_reencoding != certificate.pubkey.der_data:
				judgements += SecurityJudgement(JudgementCode.Cert_Pubkey_Invalid_DER, "Certificate public key uses invalid DER encoding. Decoding and re-encoding yields %d byte blob while original was %d bytes." % (len(pubkey_reencoding), len(certificate.pubkey.der_data)), compatibility = Compatibility.STANDARDS_VIOLATION)
		except pyasn1.error.PyAsn1Error:
			judgements += SecurityJudgement(JudgementCode.Cert_Pubkey_Invalid_DER, "Certificate public key uses invalid DER encoding. Re-encoding was not possible.", compatibility = Compatibility.STANDARDS_VIOLATION)

		oid_header = OID.from_asn1(certificate.asn1["tbsCertificate"]["signature"]["algorithm"])
		oid_sig = OID.from_asn1(certificate.asn1["signatureAlgorithm"]["algorithm"])
		if oid_header != oid_sig:
			name_header = OIDDB.SignatureAlgorithms.get(oid_header, str(oid_header))
			name_sig = OIDDB.SignatureAlgorithms.get(oid_sig, str(oid_sig))
			judgements += SecurityJudgement(JudgementCode.Cert_Signature_Algorithm_Mismatch, "Certificate indicates signature algorithm %s in header section and %s in signature section. This is a direct violation of RFC5280 Sect. 4.1.1.2." % (name_header, name_sig), compatibility = Compatibility.STANDARDS_VIOLATION)

		return {
			"security":			judgements,
		}
