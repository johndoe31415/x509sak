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

import base64
import pyasn1
from x509sak.OID import OID, OIDDB
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, RFCReference

@BaseEstimator.register
class CertificateEstimator(BaseEstimator):
	_ALG_NAME = "certificate"

	def _analyze_certificate_general_issues(self, certificate):
		judgements = SecurityJudgements()
		if certificate.version != 3:
			judgements += SecurityJudgement(JudgementCode.Cert_Version_Not_3, "Certificate version is v%d, usually would expect a v3 certificate." % (certificate.version), commonness = Commonness.HIGHLY_UNUSUAL)

		if certificate.serial < 0:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.2", verb = "MUST", text = "The serial number MUST be a positive integer assigned by the CA to each certificate.")
			judgements += SecurityJudgement(JudgementCode.Cert_Serial_Negative, "Certificate serial number is a negative value.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		elif certificate.serial == 0:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.2", verb = "MUST", text = "The serial number MUST be a positive integer assigned by the CA to each certificate.")
			judgements += SecurityJudgement(JudgementCode.Cert_Serial_Zero, "Certificate serial number is zero.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		elif certificate.serial >= (2 ** (8 * 20)):
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.2", verb = "MUST", text = "Conforming CAs MUST NOT use serialNumber values longer than 20 octets.")
			judgements += SecurityJudgement(JudgementCode.Cert_Serial_Large, "Certificate serial number is too large.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		try:
			cert_reencoding = pyasn1.codec.der.encoder.encode(certificate.asn1)
			if cert_reencoding != certificate.der_data:
				judgements += SecurityJudgement(JudgementCode.Cert_Invalid_DER, "Certificate uses invalid DER encoding. Decoding and re-encoding yields %d byte blob while original was %d bytes." % (len(cert_reencoding), len(certificate.der_data)), compatibility = Compatibility.STANDARDS_DEVIATION)
		except pyasn1.error.PyAsn1Error:
			judgements += SecurityJudgement(JudgementCode.Cert_Invalid_DER, "Certificate uses invalid DER encoding. Re-encoding was not possible.", compatibility = Compatibility.STANDARDS_DEVIATION)

		try:
			pubkey_reencoding = pyasn1.codec.der.encoder.encode(certificate.pubkey.recreate().asn1)
			if pubkey_reencoding != certificate.pubkey.der_data:
				judgements += SecurityJudgement(JudgementCode.Cert_Pubkey_Invalid_DER, "Certificate public key uses invalid DER encoding. Decoding and re-encoding yields %d byte blob while original was %d bytes." % (len(pubkey_reencoding), len(certificate.pubkey.der_data)), compatibility = Compatibility.STANDARDS_DEVIATION)
		except pyasn1.error.PyAsn1Error:
			judgements += SecurityJudgement(JudgementCode.Cert_Pubkey_Invalid_DER, "Certificate public key uses invalid DER encoding. Re-encoding was not possible.", compatibility = Compatibility.STANDARDS_DEVIATION)

		oid_header = OID.from_asn1(certificate.asn1["tbsCertificate"]["signature"]["algorithm"])
		oid_sig = OID.from_asn1(certificate.asn1["signatureAlgorithm"]["algorithm"])
		if oid_header != oid_sig:
			name_header = OIDDB.SignatureAlgorithms.get(oid_header, str(oid_header))
			name_sig = OIDDB.SignatureAlgorithms.get(oid_sig, str(oid_sig))
			standard = RFCReference(rfcno = 5280, sect = "4.1.1.2", verb = "MUST", text = "TODO")
			judgements += SecurityJudgement(JudgementCode.Cert_Signature_Algorithm_Mismatch, "Certificate indicates signature algorithm %s in header section and %s in signature section." % (name_header, name_sig), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def analyze(self, cert):
		result = {
			"subject":		self.algorithm("dn").analyze(cert.subject),
			"issuer":		self.algorithm("dn").analyze(cert.issuer),
			"validity":		self.algorithm("crt_validity").analyze(cert),
			"pubkey":		self.algorithm("pubkey").analyze(cert.pubkey),
			"extensions":	self.algorithm("crt_exts").analyze(cert),
			"signature":	self.algorithm("sig").analyze(cert.signature_alg_oid, cert.signature_alg_params, cert.signature),
			"purpose":		self.algorithm("purpose").analyze(cert),
			"security":		self._analyze_certificate_general_issues(cert),
		}
		if self._analysis_options.include_raw_data:
			result["raw"] = base64.b64encode(cert.der_data).decode("ascii")
		return result
