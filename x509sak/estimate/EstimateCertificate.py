#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2020 Johannes Bauer
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
from x509sak.OID import OID, OIDDB
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, RFCReference
from x509sak.estimate.DistinguishedNameValidator import DistinguishedNameValidator

@BaseEstimator.register
class CertificateEstimator(BaseEstimator):
	_ALG_NAME = "certificate"
	_DN_VALIDATOR_SUBJECT = DistinguishedNameValidator.create_inherited("X509Cert_Body_Subject", validation_subject = "Subject")
	_DN_VALIDATOR_ISSUER = DistinguishedNameValidator.create_inherited("X509Cert_Body_Issuer", validation_subject = "Issuer")

	def _analyze_certificate_general_issues(self, certificate):
		judgements = SecurityJudgements()
		if certificate.version != 3:
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_Version_Not3, "Certificate version is v%d, usually would expect a v3 certificate." % (certificate.version), commonness = Commonness.HIGHLY_UNUSUAL)

		if certificate.serial < 0:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.2", verb = "MUST", text = "The serial number MUST be a positive integer assigned by the CA to each certificate.")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_SerialNumber_BasicChecks_Negative, "Certificate serial number is a negative value.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		elif certificate.serial == 0:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.2", verb = "MUST", text = "The serial number MUST be a positive integer assigned by the CA to each certificate.")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_SerialNumber_BasicChecks_Zero, "Certificate serial number is zero.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		elif certificate.serial >= (2 ** (8 * 20)):
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.2", verb = "MUST", text = "Conforming CAs MUST NOT use serialNumber values longer than 20 octets.")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_SerialNumber_BasicChecks_Large, "Certificate serial number is too large.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		if "non_der" in certificate.asn1_details.flags:
			judgements += SecurityJudgement(JudgementCode.X509Cert_Malformed_NonDEREncoding, "Certificate uses invalid DER encoding. Original certificate is %d bytes; DER would be %d bytes." % (len(certificate.asn1_details.original_der), len(certificate.asn1_details.encoded_der)), compatibility = Compatibility.STANDARDS_DEVIATION)

		if "trailing_data" in certificate.asn1_details.flags:
			judgements += SecurityJudgement(JudgementCode.X509Cert_TrailingData, "Certificate contains %d bytes of trailing data." % (len(certificate.asn1_details.tail)), compatibility = Compatibility.STANDARDS_DEVIATION)

		standard = RFCReference(rfcno = 5280, sect = [ "4.1.1.2", "4.1.2.3" ], verb = "MUST", text = "This field MUST contain the same algorithm identifier as the signature field in the sequence tbsCertificate (Section 4.1.2.3).")
		oid_header = OID.from_asn1(certificate.asn1["tbsCertificate"]["signature"]["algorithm"])
		oid_sig = OID.from_asn1(certificate.asn1["signatureAlgorithm"]["algorithm"])
		if oid_header != oid_sig:
			name_header = OIDDB.SignatureAlgorithms.get(oid_header, str(oid_header))
			name_sig = OIDDB.SignatureAlgorithms.get(oid_sig, str(oid_sig))
			judgements += SecurityJudgement(JudgementCode.X509Cert_Signature_Function_BodyMismatch, "Certificate indicates signature algorithm %s in header section and %s in signature section." % (name_header, name_sig), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			# OIDs might be same, but parameters could differ (e.g., for RSA-PSS)
			header_hasvalue = certificate.asn1["tbsCertificate"]["signature"]["parameters"].hasValue()
			signature_hasvalue = certificate.asn1["signatureAlgorithm"]["parameters"].hasValue()
			if header_hasvalue and signature_hasvalue:
				name_header = OIDDB.SignatureAlgorithms.get(oid_header, str(oid_header))
				parameters_header = bytes(certificate.asn1["tbsCertificate"]["signature"]["parameters"])
				parameters_signature = bytes(certificate.asn1["signatureAlgorithm"]["parameters"])
				if parameters_header != parameters_signature:
					judgements += SecurityJudgement(JudgementCode.X509Cert_Signature_Function_BodyMismatch, "Certificate indicates same signature algorithm in both header section and signature section (%s), but parameterization of each differ." % (name_header), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			elif header_hasvalue != signature_hasvalue:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Signature_Function_BodyMismatch, "Certificate indicates same signature algorithm in both header section and signature section, but header %s while signature section %s." % ("has parameters" if header_hasvalue else "has no parameters", "does" if signature_hasvalue else "does not"), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def analyze(self, cert, root_cert = None):
		result = {
			"subject":		self.algorithm("dn").analyze(cert.subject, self._DN_VALIDATOR_SUBJECT),
			"issuer":		self.algorithm("dn").analyze(cert.issuer, self._DN_VALIDATOR_ISSUER),
			"validity":		self.algorithm("crt_validity").analyze(cert),
			"pubkey":		self.algorithm("pubkey").analyze(cert),
			"extensions":	self.algorithm("crt_exts").analyze(cert),
			"signature":	self.algorithm("sig").analyze(cert.signature_alg_oid, cert.signature_alg_params, cert.signature, root_cert),
			"purpose":		self.algorithm("purpose").analyze(cert),
			"security":		self._analyze_certificate_general_issues(cert),
		}
		if root_cert is not None:
			result["ca"] = self.algorithm("ca").analyze(cert, root_cert)
		if self._analysis_options.include_raw_data:
			result["raw"] = base64.b64encode(cert.der_data).decode("ascii")
		return result
