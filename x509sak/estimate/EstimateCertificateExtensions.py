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

import collections
import urllib.parse
import pyasn1.type.base
import pyasn1.type.univ
from x509sak.OID import OIDDB
from x509sak.AlgorithmDB import HashFunctions
from x509sak.X509Extensions import X509ExtendedKeyUsageExtension
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness, Compatibility, Verdict
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, RFCReference
from x509sak.estimate.GeneralNameValidator import GeneralNameValidator
from x509sak.estimate.NameConstraintsSubtreeValidator import NameConstraintsSubtreeValidator
from x509sak.estimate.DERValidator import DERValidator
from x509sak.estimate.Validator import ValidationJudgement, ValidationIssue
from x509sak.ASN1Wrapper import ASN1GeneralNamesWrapper
from x509sak.OtherModels import SCTVersion
from x509sak.tls.Enums import HashAlgorithm, SignatureAlgorithm
from x509sak.DistinguishedName import DistinguishedName
from x509sak.Exceptions import InvalidInputException
from x509sak.Tools import ASN1Tools, ValidationTools

@BaseEstimator.register
class CrtExtensionsSecurityEstimator(BaseEstimator):
	_ALG_NAME = "crt_exts"
	_NameError = collections.namedtuple("NameError", [ "code", "standard" ])

	_GENERAL_NAME_JUDGEMENTS = {
		"Enc_DER_Struct_GenName_DNS_Malformed":						ValidationJudgement(standard = RFCReference(rfcno = 1034, sect = "3.5", verb = "MUST", text = "The following syntax will result in fewer problems with many applications that use domain names (e.g., mail, TELNET).")),
		"Enc_DER_Struct_GenName_DNS_OnlyWhitespace":				ValidationJudgement(standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "In addition, while the string \" \" is a legal domain name, subjectAltName extensions with a dNSName of \" \" MUST NOT be used.")),
		"Enc_DER_Struct_GenName_DNS_Wildcard_InternationalLabel":	ValidationJudgement(standard = RFCReference(rfcno = 6125, sect = "6.4.3", verb = "SHOULD", text = "However, the client SHOULD NOT attempt to match a presented identifier where the wildcard character is embedded within an A-label or U-label [IDNA-DEFS] of an internationalized domain name [IDNA-PROTO].")),
		"Enc_DER_Struct_GenName_DNS_Wildcard_MulitpleWildcards":	ValidationJudgement(standard = RFCReference(rfcno = 6125, sect = "6.4.3", verb = "SHOULD", text = "If the wildcard character is the only character of the left-most label in the presented identifier, the client SHOULD NOT compare against anything but the left-most label of the reference identifier")),
		"Enc_DER_Struct_GenName_DNS_Wildcard_NotLeftmost":			ValidationJudgement(standard = RFCReference(rfcno = 6125, sect = "6.4.3", verb = "SHOULD", text = "The client SHOULD NOT attempt to match a presented identifier in which the wildcard character comprises a label other than the left-most label")),
		"Enc_DER_Struct_GenName_Email_Malformed":					ValidationJudgement(standard = RFCReference(rfcno = 822, sect = "6.1", verb = "MUST", text = "addr-spec = local-part \"@\" domain")),
		"Enc_DER_Struct_GenName_IPAddress_Malformed":				ValidationJudgement(standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "For IP version 4, as specified in [RFC791], the octet string MUST contain exactly four octets. For IP version 6, as specified in [RFC2460], the octet string MUST contain exactly sixteen octets.")),
		"Enc_DER_Struct_GenName_URI_Malformed":						ValidationJudgement(standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "The name MUST NOT be a relative URI, and it MUST follow the URI syntax and encoding rules specified in [RFC3986]. The name MUST include both a scheme (e.g., \"http\" or \"ftp\") and a scheme-specific-part. URIs that include an authority ([RFC3986], Section 3.2) MUST include a fully qualified domain name or IP address as the host.")),
	}

	_SUBJECT_ALTERNATIVE_NAME_VALIDATOR = GeneralNameValidator.create_inherited("X509Cert_Body_X509Exts_Ext_SAN_Name", specific_judgements = _GENERAL_NAME_JUDGEMENTS,
			validation_subject = "X.509 Subject Alternative Name Extension",
			allow_dnsname_wildcard_matches = True, permissible_uri_schemes = [ "http", "https" ])
	_ISSUER_ALTERNATIVE_NAME_VALIDATOR = GeneralNameValidator.create_inherited("X509Cert_Body_X509Exts_Ext_IAN_Name", specific_judgements = _GENERAL_NAME_JUDGEMENTS,
			validation_subject = "X.509 Issuer Alternative Name Extension",
			permissible_uri_schemes = [ "http", "https" ])
	_AUTHORITY_KEY_IDENTIFIER_CANAME_VALIDATOR = GeneralNameValidator.create_inherited(
			"X509Cert_Body_X509Exts_Ext_AKI_CAName", specific_judgements = _GENERAL_NAME_JUDGEMENTS,
			validation_subject = "X.509 Authority Key Identifier Extension (CA name)", permissible_uri_schemes = [ "http", "https" ])
	_CRL_DISTRIBUTION_POINT_NAME_VALIDATOR = GeneralNameValidator.create_inherited(
			"X509Cert_Body_X509Exts_Ext_CRLDP_PointName", specific_judgements = _GENERAL_NAME_JUDGEMENTS,
			validation_subject = "X.509 CRL Distribution Points Extension (distribution point name)", permissible_uri_schemes = [ "http", "https", "ftp", "ftps", "ldap" ])
	_CRL_DISTRIBUTION_POINT_ISSUER_VALIDATOR = GeneralNameValidator.create_inherited("X509Cert_Body_X509Exts_Ext_CRLDP_CRLIssuer", specific_judgements = _GENERAL_NAME_JUDGEMENTS,
			validation_subject = "X.509 CRL Distribution Points Extension (CRL issuer)", permissible_uri_schemes = [ "http", "https", "ftp", "ftps", "ldap" ])
	_NAME_CONSTRAINTS_PERMITTED_SUBTREE_VALIDATOR = NameConstraintsSubtreeValidator.create_inherited("X509Cert_Body_X509Exts_Ext_NC_PermittedSubtree", specific_judgements = _GENERAL_NAME_JUDGEMENTS,
			validation_subject = "X.509 Name Constraints Permitted Subtree")
	_NAME_CONSTRAINTS_EXCLUDED_SUBTREE_VALIDATOR = NameConstraintsSubtreeValidator.create_inherited("X509Cert_Body_X509Exts_Ext_NC_ExcludedSubtree", specific_judgements = _GENERAL_NAME_JUDGEMENTS,
			validation_subject = "X.509 Name Constraints Excluded Subtree")

	_UNKNOWN_EXTENSION_ENCODING_VALIDATOR = DERValidator.create_inherited("X509Cert_Body_X509Exts_Unknown", validation_subject = "Unknown X.509 extension")
	_EXTENSION_ENCODING_VALIDATORS = {
		"X509AuthorityInformationAccessExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_AIA", validation_subject = "X.509 Authority Information Access extension"),
		"X509AuthorityKeyIdentifierExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_AKI", validation_subject = "X.509 Authority Key Identifier extension"),
		"X509BasicConstraintsExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_BC", validation_subject = "X.509 Basic Constraints extension"),
		"X509CertificatePoliciesExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_CP", validation_subject = "X.509 Certificate Policies extension"),
		"X509CertificateTransparencyPrecertificatePoisonExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_CTPP", validation_subject = "X.509 Certificate Transparency Precertificate Poison extension"),
		"X509CertificateTransparencySCTsExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_CTSCT", validation_subject = "X.509 Certificate Transparency Signed Certificate Timestamps extension"),
		"X509CRLDistributionPointsExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_CRLDP", validation_subject = "X.509 CRL Distribution Points extension"),
		"X509ExtendedKeyUsageExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_EKU", validation_subject = "X.509 Extended Key Usage extension"),
		"X509IssuerAlternativeNameExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_IAN", validation_subject = "X.509 Issuer Alternative Name extension"),
		"X509KeyUsageExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_KU", validation_subject = "X.509 Key Usage extension"),
		"X509NetscapeCertificateTypeExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_NSCT", validation_subject = "X.509 Netscape Certificate Type extension"),
		"X509SubjectAlternativeNameExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_SAN", validation_subject = "X.509 Subject Alternative Name extension"),
		"X509SubjectKeyIdentifierExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_SKI", validation_subject = "X.509 Subject Key Identifier extension"),
		"X509NameConstraintsExtension": DERValidator.create_inherited("X509Cert_Body_X509Exts_Ext_NC", validation_subject = "X.509 Name Constraints extension"),
	}

	_DER_VALIDATOR_CERT_POLICY_USERNOTICE = DERValidator(validation_subject = "X.509 extension Certificate Policy extension User Notice qualifier", recognized_issues = {
		"Enc_DER_EncodingIssues_Malformed_NonDEREncoding":		ValidationIssue(code = JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_Malformed_NonDEREncoding),
		"Enc_DER_EncodingIssues_Malformed_UnexpectedType":		ValidationIssue(code = JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_Malformed_UnexpectedType, judgement = ValidationJudgement(standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "UserNotice ::= SEQUENCE {"))),
	})

	_DER_VALIDATOR_CERT_POLICY_CPS = DERValidator(validation_subject = "X.509 extension Certificate Policy extension CPS qualifier", recognized_issues = {
		"Enc_DER_EncodingIssues_Malformed_NonDEREncoding":		ValidationIssue(code = JudgementCode.X509Cert_Body_X509Exts_Ext_CP_CPS_Malformed_NonDEREncoding),
		"Enc_DER_EncodingIssues_Malformed_UnexpectedType":		ValidationIssue(code = JudgementCode.X509Cert_Body_X509Exts_Ext_CP_CPS_Malformed_UnexpectedType, judgement = ValidationJudgement(standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "CPSuri ::= IA5String"))),
	})

	def _analyze_extension(self, extension):
		result = {
			"name":			extension.name,
			"oid":			str(extension.oid),
			"known":		extension.known,
			"critical":		extension.critical,
		}
		if isinstance(extension, X509ExtendedKeyUsageExtension):
			result["key_usages"] = [ ]
			for oid in sorted(extension.key_usage_oids):
				result["key_usages"].append({
					"oid":		str(oid),
					"name":		OIDDB.X509ExtendedKeyUsage.get(oid),
				})
		return result

	def _judge_may_have_exts(self, certificate):
		judgements = SecurityJudgements()
		if (certificate.version < 3) and len(certificate.extensions) > 0:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.9", verb = "MUST", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Disallowed, "X.509 extension present in v%d certificate." % (certificate.version), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		if len(certificate.extensions) == 0:
			if certificate.asn1["tbsCertificate"]["extensions"].hasValue():
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_EmptySequence, "X.509 extensions are not present, but \"extensions\" attribute is present and contains an empty ASN.1 SEQUENCE.", commonness = Commonness.UNUSUAL)

		return judgements

	def _judge_extension_known(self, certificate):
		judgements = SecurityJudgements()
		for ext in certificate.extensions:
			oid_name = OIDDB.X509Extensions.get(ext.oid)
			if oid_name is None:
				if ext.critical:
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Unknown_Critical, "X.509 extension present with OID %s. This OID is unknown and the extension is marked as critical; the certificate would be rejected under normal circumstances." % (ext.oid), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)
				else:
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Unknown_NotCritical, "X.509 extension present with OID %s. This OID is unknown and the extension is marked as non-critical; the extension would be ignored under normal circumstances." % (ext.oid), commonness = Commonness.UNUSUAL)
		return judgements

	def _judge_unique_id(self, certificate):
		judgements = SecurityJudgements()
		if certificate.version not in [ 2, 3 ]:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.8", verb = "MUST", text = "These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1). These fields MUST NOT appear if the version is 1.")
			if certificate.issuer_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_IssuerUniqueID_NotAllowedV1, "Issuer unique IDs is present in v%d certificate." % (certificate.version), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if certificate.subject_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_SubjectUniqueID_NotAllowedV1, "Subject unique IDs is present in v%d certificate." % (certificate.version), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		if certificate.is_ca_certificate:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.8", verb = "MUST", text = "CAs conforming to this profile MUST NOT generate certificates with unique identifiers.")
			if certificate.issuer_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_IssuerUniqueID_NotAllowedCA, "Issuer unique IDs is present in CA certificate.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if certificate.subject_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_SubjectUniqueID_NotAllowedCA, "Subject unique IDs is present in CA certificate.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		if (len(certificate.extensions) == 0) and (any(unique_id is not None for unique_id in (certificate.issuer_unique_id, certificate.subject_unique_id))) and (certificate.version != 2):
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.1", verb = "SHOULD", text = "If no extensions are present, but a UniqueIdentifier is present, the version SHOULD be 2 (value is 1); however, the version MAY be 3.")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_Version_Not2, "Certificate version is %d, but without X.509 extensions and a unique identifier present, it should be version 2." % (certificate.version), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_uniqueness(self, certificate):
		have_oids = set()

		for extension in certificate.extensions:
			if extension.oid in have_oids:
				standard = RFCReference(rfcno = 5280, sect = "4.2", verb = "MUST", text = "A certificate MUST NOT include more than one instance of a particular extension.")
				judgement = SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_DuplicatesPresent, "X.509 extension %s (OID %s) is present at least twice." % (extension.name, str(extension.oid)), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				break
			have_oids.add(extension.oid)
		else:
			judgement = SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_AllUnique, "All X.509 extensions are unique.", commonness = Commonness.COMMON)
		return judgement

	def _judge_basic_constraints(self, certificate):
		bc = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("BasicConstraints"))
		judgements = SecurityJudgements()
		if bc is None:
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_BC_Missing, "BasicConstraints extension is missing.", commonness = Commonness.HIGHLY_UNUSUAL)
		else:
			if not bc.critical:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_BC_NotCritical, "BasicConstraints extension is present, but not marked as critical.", commonness = Commonness.UNUSUAL)
			else:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_BC_Critical, "BasicConstraints extension is present and marked as critical.", commonness = Commonness.COMMON)

			if bc.pathlen is not None:
				if not bc.is_ca:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.9", verb = "MUST", text = "CAs MUST NOT include the pathLenConstraint field unless the cA boolean is asserted")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_BC_PathLenWithoutCA, "BasicConstraints extension contains a pathLen constraint, but does not assert the \"CA\" attribute.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

				ku_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("KeyUsage"))
				if ku_ext is None:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.9", verb = "MUST", text = "CAs MUST NOT include the pathLenConstraint field unless the cA boolean is asserted and the key usage extension asserts the keyCertSign bit.")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_BC_PathLenWithoutKeyCertSign, "BasicConstraints extension contains a pathLen constraint, but does not have a key usage extension.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				elif "keyCertSign" not in ku_ext.flags:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.9", verb = "MUST", text = "CAs MUST NOT include the pathLenConstraint field unless the cA boolean is asserted and the key usage extension asserts the keyCertSign bit.")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_BC_PathLenWithoutKeyCertSign, "BasicConstraints extension contains a pathLen constraint, but its key usage extension does not contain the \"keyCertsign\" bit.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_subject_key_identifier(self, certificate):
		judgements = SecurityJudgements()
		ski = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
		if ski is None:
			if not certificate.is_ca_certificate:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SKI_Missing, "SubjectKeyIdentifier extension is missing.", commonness = Commonness.UNUSUAL)
			else:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.2", verb = "MUST", text = "To facilitate certification path construction, this extension MUST appear in all conforming CA certificates")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SKI_Missing, "SubjectKeyIdentifier extension is missing, but required for compliant CA certificate.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			if ski.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.2", verb = "MUST", text = "Conforming CAs MUST mark this extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SKI_Critical, "SubjectKeyIdentifier extension is marked as critical.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

			check_hashfncs = [ HashFunctions.sha1, HashFunctions.sha256, HashFunctions.sha224, HashFunctions.sha384, HashFunctions.sha512, HashFunctions.md5, HashFunctions.sha3_256, HashFunctions.sha3_384, HashFunctions.sha3_512 ]
			tried_hashfncs = [ ]
			cert_ski = ski.keyid
			for hashfnc in check_hashfncs:
				try:
					computed_ski = certificate.pubkey.keyid(hashfnc = hashfnc.name)
					if cert_ski == computed_ski:
						if hashfnc == HashFunctions.sha1:
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SKI_Hashfunction_SHA1, "SubjectKeyIdentifier present and matches SHA-1 of contained public key.", commonness = Commonness.COMMON)
						else:
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SKI_Hashfunction_Other, "SubjectKeyIdentifier present and matches %s of contained public key." % (hashfnc.value.pretty_name), commonness = Commonness.UNUSUAL)
						break
					tried_hashfncs.append(hashfnc)
				except ValueError:
					# Hash algorithm not supported in this Python version.
					pass
			else:
				if not certificate.is_ca_certificate:
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SKI_Hashfunction_Arbitrary, "SubjectKeyIdentifier key ID (%s) does not match any tested cryptographic hash function (%s) over the contained public key." % (ski.format_value, ", ".join(hashfnc.value.pretty_name for hashfnc in tried_hashfncs)), commonness = Commonness.HIGHLY_UNUSUAL)
				else:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.2", verb = "SHOULD", text = "For CA certificates, subject key identifiers SHOULD be derived from the public key or a method that generates unique values. ")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SKI_Hashfunction_Arbitrary, "SubjectKeyIdentifier key ID (%s) does not match any tested cryptographic hash function (%s) over the contained public key." % (ski.keyid.hex(), ", ".join(hashfnc.value.pretty_name for hashfnc in tried_hashfncs)), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		return judgements

	def _judge_authority_key_identifier(self, certificate):
		judgements = SecurityJudgements()
		aki = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("AuthorityKeyIdentifier"))
		if aki is None:
			if not certificate.is_selfsigned:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "MUST", text = "The keyIdentifier field of the authorityKeyIdentifier extension MUST be included in all certificates generated by conforming CAs to facilitate certification path construction.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_Missing, "AuthorityKeyIdentifier extension is missing.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			else:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "SHOULD", text = "where a CA distributes its public key in the form of a \"self-signed\" certificate, the authority key identifier MAY be omitted.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_Missing, "AuthorityKeyIdentifier extension is missing.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			if aki.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "MUST", text = "Conforming CAs MUST mark this extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_Critical, "AuthorityKeyIdentifier X.509 extension is marked critical.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if aki.keyid is None:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_NoKeyID, "AuthorityKeyIdentifier X.509 extension contains no key ID.", commonness = Commonness.UNUSUAL)
			elif len(aki.keyid) == 0:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_EmptyKeyID, "AuthorityKeyIdentifier X.509 extension contains empty key ID.", commonness = Commonness.HIGHLY_UNUSUAL)
			elif len(aki.keyid) > 32:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_LongKeyID, "AuthorityKeyIdentifier X.509 extension contains long key ID (%d bytes)." % (len(aki.keyid)), commonness = Commonness.HIGHLY_UNUSUAL)

			if aki.malformed:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_Malformed_Undecodable, "AuthorityKeyIdentifier X.509 extension is malformed, cannot decode it.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)

			if (aki.keyid is None) and (aki.ca_names is None) and (aki.serial is None):
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_Empty, "AuthorityKeyIdentifier X.509 extension contains neither Key ID nor CA names nor a serial number.", commonness = Commonness.HIGHLY_UNUSUAL)

			if aki.ca_names is not None:
				if len(aki.ca_names) == 0:
					standard = RFCReference(rfcno = 5280, sect = [ "4.2.1.1", "4.2.1.6" ], verb = "MUST", text = "GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_CAName_Empty, "AuthorityKeyIdentifier X.509 extension contains CA names field of length zero.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				for general_name in aki.ca_names:
					judgements += self._AUTHORITY_KEY_IDENTIFIER_CANAME_VALIDATOR.validate(general_name)

			if (aki.ca_names is None) and (aki.serial is not None):
				standard = RFCReference(rfcno = 5280, sect = "A.2", verb = "MUST", text = "authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_SerialWithoutCAName, "AuthorityKeyIdentifier X.509 extension contains CA serial number, but no CA issuer.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			elif (aki.ca_names is not None) and (aki.serial is None):
				standard = RFCReference(rfcno = 5280, sect = "A.2", verb = "MUST", text = "authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AKI_CAnameWithoutSerial, "AuthorityKeyIdentifier X.509 extension contains CA issuer, but no CA serial number.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

# TODO this code seems to be duplicate with EstimateCARelation.py
#			if root_cert is not None:
#				root_ski = root_cert.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
#				if root_ski is None:
#					judgements += SecurityJudgement(JudgementCode.CertUsage_CARelationship_AKI_KeyID_Uncheckable, "AuthorityKeyIdentifier X.509 extension present, but given root certificate does not contain any subject key identifier.", commonness = Commonness.HIGHLY_UNUSUAL)
#				else:
#					if (aki.keyid is not None) and (aki.keyid != root_ski.keyid):
#						standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "MUST", text = "The authority key identifier extension provides a means of identifying the public key corresponding to the private key used to sign a certificate.")
#						judgements += SecurityJudgement(JudgementCode.CertUsage_CARelationship_AKI_KeyID_Mismatch, "AuthorityKeyIdentifier X.509 extension refers to authority key ID %s, but CA has key ID %s as their SubjectKeyIdentifier." % (aki.keyid.hex(), root_ski.keyid.hex()), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
#					if (aki.serial is not None) and (aki.serial != root_cert.serial):
#						standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "MUST", text = "The authority key identifier extension provides a means of identifying the public key corresponding to the private key used to sign a certificate.")
#						judgements += SecurityJudgement(JudgementCode.CertUsage_CARelationship_AKI_Serial_Mismatch, "AuthorityKeyIdentifier X.509 extension refers to CA certificate with serial number 0x%x, but given CA has serial number 0x%x." % (aki.serial, root_cert.serial), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
		return judgements

	def _judge_name_constraints(self, certificate):
		judgements = SecurityJudgements()
		nc = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("NameConstraints"))
		if nc is not None:
			if not nc.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.10", verb = "MUST", text = "Conforming CAs MUST mark this extension as critical")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_NC_NotCritical, "NameConstraints X.509 extension present, but not marked critical.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if not certificate.is_ca_certificate:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.10", verb = "MUST", text = "The name constraints extension, which MUST be used only in a CA certificate, indicates a name space within which all subject names in subsequent certificates in a certification path MUST be located.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_NC_NoCA, "NameConstraints X.509 extension present, but certificate is not a CA certificate.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

			if nc.asn1 is not None:
				if (len(nc.permitted_subtrees) == 0) and (len(nc.excluded_subtrees) == 0):
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.10", verb = "MUST", text = "Conforming CAs MUST NOT issue certificates where name constraints is an empty sequence. That is, either the permittedSubtrees field or the excludedSubtrees MUST be present.")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_NC_Empty, "NameConstraints X.509 extension present, but contains neither excluded nor permitted subtrees.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

				judgements += self._NAME_CONSTRAINTS_PERMITTED_SUBTREE_VALIDATOR.validate(nc.permitted_subtrees)
				judgements += self._NAME_CONSTRAINTS_EXCLUDED_SUBTREE_VALIDATOR.validate(nc.excluded_subtrees)

		return judgements


	def _judge_key_usage(self, certificate):
		judgements = SecurityJudgements()
		ku_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("KeyUsage"))
		if ku_ext is not None:
			if not ku_ext.malformed:
				if ku_ext.has_trailing_zero:
					# TODO: Possible standards violation?
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_TrailingZeros, "KeyUsage extension present, but contains trailing zero.", commonness = Commonness.HIGHLY_UNUSUAL)

				if ku_ext.all_bits_zero:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "When the keyUsage extension appears in a certificate, at least one of the bits MUST be set to 1.")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_Empty, "KeyUsage extension present, but contains empty bitlist.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

				if ku_ext.unknown_flags_set:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "decipherOnly (8) }")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_TooLong, "KeyUsage extension present, but contains too many bits (highest bit value %d, but %d expected as maximum)." % (ku_ext.highest_set_bit_value, ku_ext.highest_permissible_bit_value), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

				if not ku_ext.critical:
					if certificate.is_ca_certificate:
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "SHOULD", text = "When present, conforming CAs SHOULD mark this extension as critical.")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_NotCritical, "CA certificate contains KeyUsage X.509 extension, but it is not marked as critical.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
					else:
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_NotCritical, "CA certificate contains KeyUsage X.509 extension, but it is not marked as critical.", commonness = Commonness.UNUSUAL)

				if ("encipherOnly" in ku_ext.flags) and ("keyAgreement" not in ku_ext.flags):
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "SHOULD", text = "The meaning of the encipherOnly bit is undefined in the absence of the keyAgreement bit.")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_UndefinedBitCombination, "KeyUsage extension contains encipherOnly bit without keyAgreement bit set. The semantic of this is undefined.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				if ("decipherOnly" in ku_ext.flags) and ("keyAgreement" not in ku_ext.flags):
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "SHOULD", text = "The meaning of the decipherOnly bit is undefined in the absence of the keyAgreement bit.")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_UndefinedBitCombination, "KeyUsage extension contains decipherOnly bit without keyAgreement bit set. The semantic of this is undefined.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

				if ("keyEncipherment" in ku_ext.flags) and ("keyAgreement" not in ku_ext.flags):
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_NoPerfectForwardSecrecy, "KeyUsage extension allows keyEncipherment but no keyAgreement. This disallows perfect forward secrecy, an important security property of communication channels.", commonness = Commonness.HIGHLY_UNUSUAL, verdict = Verdict.WEAK)

				if "keyCertSign" in ku_ext.flags:
					bc = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("BasicConstraints"))
					if bc is None:
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension (Section 4.2.1.9) MUST also be asserted.")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_SignCertButNoBasicConstraints, "KeyUsage extension contains the keyCertSign flag, but no BasicConstraints extension.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
					elif not bc.is_ca:
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension (Section 4.2.1.9) MUST also be asserted.")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_SignCertButNoCA, "KeyUsage extension contains the keyCertSign flag, but BasicConstraints extension do not mark as a CA certificate.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			else:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "KeyUsage ::= BIT STRING {")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_Malformed_Undecodable, "KeyUsage extension is malformed and cannot be decoded.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			if certificate.is_ca_certificate:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "Conforming CAs MUST include this extension in certificates that contain public keys that are used to validate digital signatures on other public key certificates or CRLs.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_KU_Missing, "CA certificate must contain a KeyUsage X.509 extension, but it is missing.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		return judgements

	def _judge_extended_key_usage(self, certificate):
		judgements = SecurityJudgements()
		eku_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("ExtendedKeyUsage"))
		if eku_ext is not None:
			number_oids = len(list(eku_ext.key_usage_oids))
			number_unique_oids = len(set(eku_ext.key_usage_oids))
			if number_oids == 0:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.12", verb = "MUST", text = "ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_EKU_Empty, "ExtendedKeyUsage extension present, but contains no OIDs.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if number_oids != number_unique_oids:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_EKU_Duplicate, "ExtendedKeyUsage extension present, but contains duplicate OIDs. There are %d OIDs present, but only %d are unique." % (number_oids, number_unique_oids), commonness = Commonness.HIGHLY_UNUSUAL)
			if eku_ext.any_key_usage and eku_ext.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.12", verb = "SHOULD", text = "Conforming CAs SHOULD NOT mark this extension as critical if the anyExtendedKeyUsage KeyPurposeId is present.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_EKU_AnyUsageCriticial, "ExtendedKeyUsage extension contains the anyKeyUsage OID, but is also marked as critical.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_subject_alternative_name(self, certificate):
		judgements = SecurityJudgements()
		san = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectAlternativeName"))
		if san is not None:
			if san.name_count == 0:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "If the subjectAltName extension is present, the sequence MUST contain at least one entry.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SAN_Empty, "Subject Alternative Name X.509 extension with no contained names.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			for general_name in san:
				judgements += self._SUBJECT_ALTERNATIVE_NAME_VALIDATOR.validate(general_name)
			if (not certificate.subject.empty) and san.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "SHOULD", text = "When including the subjectAltName extension in a certificate that has a non-empty subject distinguished name, conforming CAs SHOULD mark the subjectAltName extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SAN_Critical, "Subject Alternative Name X.509 extension should not be critical when a subject is present.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			elif certificate.subject.empty and (not san.critical):
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "If the subject field contains an empty sequence, then the issuing CA MUST include a subjectAltName extension that is marked as critical.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SAN_NotCritical, "Subject Alternative Name X.509 extension should be critical when no subject is present.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

			if (not certificate.subject.empty) and (set(santuple.name for santuple in san) == set([ "rfc822Name" ])):
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "Further, if the only subject identity included in the certificate is an alternative name form (e.g., an electronic mail address), then the subject distinguished name MUST be empty (an empty sequence), and the subjectAltName extension MUST be present.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SAN_EmailOnly, "Subject Alternative Name X.509 extension only contains email addresses even though subject is non-empty.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			if not certificate.subject.empty:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SAN_Missing, "No Subject Alternative Name X.509 extension present in the certificate.", commonness = Commonness.UNUSUAL)
			else:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "If the subject field contains an empty sequence, then the issuing CA MUST include a subjectAltName extension that is marked as critical.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_SAN_Missing, "Subject Alternative Name X.509 missing although subject is empty.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_issuer_alternative_name(self, certificate):
		judgements = SecurityJudgements()
		ian = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("IssuerAlternativeName"))
		if ian is not None:
			if ian.name_count == 0:
				standard = RFCReference(rfcno = 5280, sect = [ "4.2.1.7", "4.2.1.6" ], verb = "MUST", text = "If the subjectAltName extension is present, the sequence MUST contain at least one entry.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_IAN_Empty, "Issuer Alternative Name X.509 extension with no contained names.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			for general_name in ian:
				judgements += self._ISSUER_ALTERNATIVE_NAME_VALIDATOR.validate(general_name)
			if ian.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.7", verb = "SHOULD", text = "Where present, conforming CAs SHOULD mark this extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_IAN_Critical, "Issuer Alternative Name X.509 extension should not be critical.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			if certificate.issuer.empty:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_IAN_Missing, "Issuer Alternative Name X.509 missing although issuer in header is empty.", commonness = Commonness.HIGHLY_UNUSUAL)

		return judgements

	def _judge_authority_information_access(self, certificate):
		judgements = SecurityJudgements()
		aia = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("id-pe-authorityInfoAccess"))
		if aia is not None:
			if aia.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.2.1", verb = "MUST", text = "Conforming CAs MUST mark this extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AIA_Critical, "Authority Information Access X.509 extension is marked critical.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if aia.method_count == 0:
				standard = RFCReference(rfcno = 5280, sect = "4.2.2.1", verb = "MUST", text = "SEQUENCE SIZE (1..MAX) OF AccessDescription")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_AIA_Empty, "Authority Information Access X.509 extension contains no access methods.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

#### TODO END OF CODE REVIEW
	def _judge_certificate_policy(self, certificate):
		judgements = SecurityJudgements()

		old_oid = OIDDB.X509Extensions.inverse("oldCertificatePolicies")
		old_policies = certificate.extensions.get_first(old_oid)
		if old_policies is not None:
			standard = RFCReference(rfcno = 5280, sect = "A.2", verb = "MUST", text = "id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_DeprecatedOID, "Deprecated OID %s used to encode certificate policies." % (old_oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)

		policies_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("CertificatePolicies"))
		if policies_ext is not None:
			policies = list(policies_ext.policies)
			seen_oids = { }
			for (policy_number, policy) in enumerate(policies, 1):
				if policy.oid in seen_oids:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "A certificate policy OID MUST NOT appear more than once in a certificate policies extension.")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_DuplicateOID, "OID %s used as certificate policy #%d has already been used in policy #%d and thus is an illegal duplicate." % (policy.oid, policy_number, seen_oids[policy.oid]), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
				else:
					seen_oids[policy.oid] = policy_number

			any_policy = policies_ext.get_policy(OIDDB.X509ExtensionCertificatePolicy.inverse("anyPolicy"))
			if any_policy is not None:
				for qualifier in any_policy.qualifiers:
					if qualifier.oid not in OIDDB.X509ExtensionCertificatePolicyQualifierOIDs:
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "When qualifiers are used with the special policy anyPolicy, they MUST be limited to the qualifiers identified in this section.")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_Qualifier_AnyPolicyWithUnknownQualifier, "Unknown OID %s used in a qualification of an anyPolicy certificate policy." % (qualifier.oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)

			if policies_ext.policy_count > 1:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "RECOMMEND", text = "To promote interoperability, this profile RECOMMENDS that policy information terms consist of only an OID.")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_MoreThanOnePolicy, "%d policies present in certificate, but only one is recommended." % (policies_ext.policy_count), compatibility = Compatibility.LIMITED_SUPPORT, standard = standard)

			# Check if qualifier is used twice. Not technically forbidden, but definitely weird.
			for policy in policies:
				seen_oids = { }
				for (qualifier_no, qualifier) in enumerate(policy.qualifiers, 1):
					if qualifier.oid in seen_oids:
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_Qualifier_Duplicate, "Qualifier #%d (OID %s) has been used previously in policy %s as #%d." % (qualifier_no, qualifier.oid, policy.oid, seen_oids[qualifier.oid]), commonness = Commonness.UNUSUAL)
					else:
						seen_oids[qualifier.oid] = qualifier_no

			# Check for use of noticeRef
			for policy in policies:
				for qualifier in policy.qualifiers:

					if qualifier.oid == OIDDB.X509ExtensionCertificatePolicyQualifierOIDs.inverse("id-qt-unotice"):
						# User notice field is present
						judgements += self._DER_VALIDATOR_CERT_POLICY_USERNOTICE.validate(qualifier.decoded_qualifier)

						if "fallback" in qualifier.decoded_qualifier.flags:
							standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "While the explicitText has a maximum size of 200 characters, some non-conforming CAs exceed this limit. Therefore, certificate users SHOULD gracefully handle explicitText with more than 200 characters.")
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_ConstraintViolation, "User notice qualifier of policy %s contains a qualifier which breaks the ASN.1 length constraint of 200 characters." % (policy.oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

						if qualifier.decoded_qualifier.asn1 is not None:
							if (len(qualifier.decoded_qualifier.asn1) == 0) or (not qualifier.decoded_qualifier.asn1[0].hasValue()):
								judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_Empty, "User notice qualifier of policy %s contains empty sequence, no noticeRef or explicitText are present." % (policy.oid), commonness = Commonness.UNUSUAL)

							# Check if noticeRef is present
							# TODO: Is this correct? See https://github.com/etingof/pyasn1/issues/189
							notice_ref = qualifier.decoded_qualifier.asn1.getComponentByName("noticeRef", instantiate = False)
							if not isinstance(notice_ref, pyasn1.type.base.NoValue):
								standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "Conforming CAs SHOULD NOT use the noticeRef option.")
								judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_NoticeRefPresent, "User notice qualifier of policy %s contains a noticeRef in the qualifier body." % (policy.oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

							# Check if encoding of explicitText is UTF8String or IA5String
							explicit_text = qualifier.decoded_qualifier.asn1.getComponentByName("explicitText", instantiate = False)
							if isinstance(explicit_text, pyasn1.type.base.NoValue):
								# No explicit_text set?
								judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_Absent, "User notice qualifier of policy %s does not contain an explicitText element in the qualifier body." % (policy.oid), compatibility = Compatibility.LIMITED_SUPPORT)
							else:
								explicit_text = explicit_text.getComponent()
								if isinstance(explicit_text, pyasn1.type.char.UTF8String):
									# Recommendation fulfilled, don't do anything
									pass
								elif isinstance(explicit_text, pyasn1.type.char.IA5String):
									standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MAY", text = "Conforming CAs SHOULD use the UTF8String encoding for explicitText, but MAY use IA5String.")
									judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_IA5String, "User notice qualifier of policy %s does not contain an explicitText element of type IA5String, although UTF8String is the preferred one." % (policy.oid), compatibility = Compatibility.LIMITED_SUPPORT, standard = standard)
								else:
									standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "Conforming CAs SHOULD use the UTF8String encoding for explicitText, but MAY use IA5String.")
									judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_InvalidStringType, "User notice qualifier of policy %s does not contain an explicitText element of type %s, but only UTF8String or IA5String are permitted." % (policy.oid, type(explicit_text).__name__), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

								contained_chars = set(ord(char) for char in str(explicit_text))
								for char in sorted(contained_chars):
									if (0 <= char <= 0x1f) or (0x7f <= char <= 0x9f):
										standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "SHOULD", text = "The explicitText string SHOULD NOT include any control characters (e.g., U+0000 to U+001F and U+007F to U+009F).")
										judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_ControlCharacter, "User notice qualifier of policy %s does not contains control character 0x%x in its explicitText element." % (policy.oid, char), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
										break

					elif qualifier.oid == OIDDB.X509ExtensionCertificatePolicyQualifierOIDs.inverse("id-qt-cps"):
						# CPS field is present
						judgements += self._DER_VALIDATOR_CERT_POLICY_CPS.validate(qualifier.decoded_qualifier)

						if "fallback" in qualifier.decoded_qualifier.flags:
							standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "CPSuri ::= IA5String")
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_CPS_ConstraintViolation, "CPS qualifier in X.509 Certificate Policies extension violates IA5String constraint, actual type is %s." % (type(qualifier.decoded_qualifier.asn1.getComponent()).__name__), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
							uri = str(qualifier.decoded_qualifier.asn1.getComponent())

						if qualifier.decoded_qualifier.asn1 is not None:
							if qualifier.decoded_qualifier.model_index == 0:
								# Standard IA5String, take as-is
								uri = str(qualifier.decoded_qualifier.asn1)
							elif qualifier.decoded_qualifier.model_index == 1:
								# Could be some other string (e.g., UTF8String), i.e., it's a choice.
								uri = str(qualifier.decoded_qualifier.asn1.getComponent())
							else:
								raise NotImplementedError(qualifier.decoded_qualifier.model_index)

							if not ValidationTools.validate_uri(uri):
								judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_CPS_URI_Malformed, "CPS URI of policy %s is malformed: %s" % (policy.oid, uri), compatibility = Compatibility.STANDARDS_DEVIATION, commonness = Commonness.HIGHLY_UNUSUAL)
							elif (not uri.startswith("http://")) and (not uri.startswith("https://")):
								judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_CPS_URI_UncommonURIScheme, "CPS URI of policy %s does not follow http/https scheme: %s" % (policy.oid, uri), compatibility = Compatibility.LIMITED_SUPPORT, commonness = Commonness.UNUSUAL)
					else:
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CP_Qualifier_Unknown, "X.509 Certificate policy with OID %s has unknown qualifier (OID %s)." % (policy.oid, qualifier.oid), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_netscape_certificate_type(self, certificate):
		judgements = SecurityJudgements()
		ns_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("NetscapeCertificateType"))
		if ns_ext is not None:
			if ns_ext.asn1 is None:
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_NSCT_Malformed_Undecodable, "Cannot parse the Netscape Certificate Types X.509 extension, it is malformed.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
			else:
				bitlist = list(ns_ext.asn1)
				if (len(bitlist) == 0) or (set(bitlist) == set([ 0 ])):
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_NSCT_Empty, "Netscape Certificate Types X.509 extension contains no set bits.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
				elif (len(bitlist) >= 5) and (bitlist[4] == 1):
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_NSCT_UnusedBitSet, "Netscape Certificate Types X.509 extension has an invalid/unused bit set.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)

				if ASN1Tools.bitstring_has_trailing_zeros(ns_ext.asn1):
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_NSCT_TrailingZeros, "Netscape Certificate Types X.509 extension has trailing zeros in bit string.", commonness = Commonness.HIGHLY_UNUSUAL)

		return judgements

	def _judge_crl_distribution_points_point_general_name(self, pointno, nameno, general_name):
		judgements = SecurityJudgements()

		judgements += self._CRL_DISTRIBUTION_POINT_NAME_VALIDATOR.validate(general_name)
		if general_name.name == "uniformResourceIdentifier":
			uri = general_name.uri

			if uri.scheme.lower() in ("http", "ftp"):
				if uri.path.endswith("/"):
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "When the HTTP or FTP URI scheme is used, the URI MUST point to a single DER encoded CRL as specified in [RFC2585].")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_PossiblyNoDERCRLServed, "CRL Distribution Points X.509 extension contains distribution point #%d (name #%d) which points to a HTTP or FTP URI of which the filetype cannot be deduced. The endpoint could be serving non-DER data." % (pointno, nameno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				elif not uri.path.lower().endswith(".crl"):
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "When the HTTP or FTP URI scheme is used, the URI MUST point to a single DER encoded CRL as specified in [RFC2585].")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_PossiblyNoDERCRLServed, "CRL Distribution Points X.509 extension contains distribution point #%d (name #%d) which points to a HTTP or FTP URI of which the filetype indicates it could be a non-DER-encoded CRL. The endpoint could be serving non-DER data." % (pointno, nameno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			elif uri.scheme.lower() == "ldap":
				uri_path = uri.path.strip()
				if uri_path.startswith("/"):
					uri_path = uri_path[1:]

				try:
					parsed_dn = DistinguishedName.from_rfc2253_str(urllib.parse.unquote(uri_path))
					if parsed_dn.rdn_count == 0:
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "When the LDAP URI scheme [RFC4516] is used, the URI MUST include a <dn> field containing the distinguished name of the entry holding the CRL")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_NoDN, "CRL Distribution Points X.509 extension contains distribution point #%d (name #%d) which points to an LDAP URI which does not contain a Distinguished Name." % (pointno, nameno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				except InvalidInputException:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "When the LDAP URI scheme [RFC4516] is used, the URI MUST include a <dn> field containing the distinguished name of the entry holding the CRL")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_MalformedDN, "CRL Distribution Points X.509 extension contains distribution point #%d (name #%d) which points to an LDAP URI which contain an unparsable Distinguished Name (\"%s\")." % (pointno, nameno, uri.path), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

				if uri.query == "":
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "When the LDAP URI scheme [RFC4516] is used, the URI MUST include a <dn> field containing the distinguished name of the entry holding the CRL, MUST include a single <attrdesc> that contains an appropriate attribute description for the attribute that holds the CRL [RFC4523]")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_NoAttrdesc, "CRL Distribution Points X.509 extension contains distribution point #%d (name #%d) which points to an LDAP URI which does not contain an attrdesc element describing the attribute under which the CRL can be looked up." % (pointno, nameno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

				if uri.netloc == "":
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "SHOULD", text = "When the LDAP URI scheme [RFC4516] is used, the URI MUST include a <dn> field containing the distinguished name of the entry holding the CRL, MUST include a single <attrdesc> that contains an appropriate attribute description for the attribute that holds the CRL [RFC4523], and SHOULD include a <host>")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_NoHostname, "CRL Distribution Points X.509 extension contains distribution point #%d (name #%d) which points to an LDAP URI which does not contain a hostname." % (pointno, nameno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements


	def _judge_crl_distribution_points(self, certificate):
		judgements = SecurityJudgements()
		cdp_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("CRLDistributionPoints"))
		if cdp_ext is not None:
			if cdp_ext.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "SHOULD", text = "The extension SHOULD be non-critical")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_Critical, "CRL Distribution Points X.509 extension is present, but marked critical.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

			if cdp_ext.malformed:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_Malformed_Undecodable, "CRL Distribution Points X.509 extension is malformed and cannot be decoded.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			else:
				has_all_reasons = False
				for (pointno, point) in enumerate(cdp_ext.points, 1):
					if (point.point_name is None) and (point.reasons is None) and (point.crl_issuer is None):
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "either distributionPoint or cRLIssuer MUST be present.")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_Empty, "CRL Distribution Points X.509 extension contains distribution point #%d which is entirely empty." % (pointno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
					elif (point.point_name is None) and (point.reasons is not None) and (point.crl_issuer is None):
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "While each of these fields is optional, a DistributionPoint MUST NOT consist of only the reasons field")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointWithOnlyReasons, "CRL Distribution Points X.509 extension contains distribution point #%d which contains only the reasons field." % (pointno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

					if point.crl_issuer is not None:
						for issuer_name in point.crl_issuer:
							judgements += self._CRL_DISTRIBUTION_POINT_ISSUER_VALIDATOR.validate(issuer_name)
						if any(certificate.issuer == crl_issuer.directory_name for crl_issuer in point.crl_issuer.filter_by_type("directoryName")):
							standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "If the certificate issuer is also the CRL issuer, then conforming CAs MUST omit the cRLIssuer field and MUST include the distributionPoint field.")
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_CRLIssuer_Redundant, "CRL Distribution Points X.509 extension contains distribution point #%d which contains only the reasons field." % (pointno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

					if point.point_name is not None:
						if isinstance(point.point_name, ASN1GeneralNamesWrapper):
							# List of distributionPoints is GeneralNames: Where
							# to get the CRL from

							for (nameno, general_name) in enumerate(point.point_name, 1):
								judgements += self._judge_crl_distribution_points_point_general_name(pointno, nameno, general_name)

							if not any(known_scheme in point.point_name.get_contained_uri_scheme_set() for known_scheme in ("ldap", "http")):
								standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "SHOULD", text = "When present, DistributionPointName SHOULD include at least one LDAP or HTTP URI.")
								judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_NoLDAPorHTTPURI, "CRL Distribution Points X.509 extension contains no distribution point name that contains either an LDAP or HTTP URI.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

						else:
							# DistributionPoint is a single RDN
							standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "SHOULD", text = "Conforming CAs SHOULD NOT use nameRelativeToCRLIssuer to specify distribution point names.")
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_RDN_Present, "CRL Distribution Points X.509 extension contains distribution point #%d which points to the CRL using a RDN." % (pointno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

							if point.crl_issuer is not None:
								crl_issuer_distinguished_names = point.crl_issuer.filter_by_type("directoryName")
								if len(crl_issuer_distinguished_names) > 1:
									standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "The DistributionPointName MUST NOT use the nameRelativeToCRLIssuer alternative when cRLIssuer contains more than one distinguished name.")
									judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_RDN_Ambiguous, "CRL Distribution Points X.509 extension contains distribution point #%d which points to the CRL using a RDN, but the DN it is relative to is ambiguous (%d different CRL issuer DNs given)." % (pointno, len(crl_issuer_distinguished_names)), commonness = Commonness.HIGHLY_UNUSUAL)

					elif point.point_name_rdn_malformed:
						standard = RFCReference(rfcno = 5280, sect = "A.1", verb = "MUST", text = "RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue")
						judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_PointName_RDN_Malformed, "CRL Distribution Points X.509 extension contains distribution point #%d which points to the CRL using a malformed RDN." % (pointno), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

					if point.reasons is not None:
						missing_reasons = set(cdp_ext.all_used_reasons()) - point.reasons
						if len(missing_reasons) > 0:
							standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "RECOMMEND", text = "This profile RECOMMENDS against segmenting CRLs by reason code.")
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_SegmentationUsed, "CRL Distribution Points X.509 extension contains distribution point #%d which does not have CRLs for all possible reasons (%s are missing)." % (pointno, ", ".join(sorted(missing_reasons))), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
						else:
							has_all_reasons = True

						if "unused" in point.reasons:
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_Reasons_UnusedBitsAsserted, "CRL Distribution Points X.509 extension contains distribution point #%d which asserts an unused bit for CRL reason." % (pointno), commonness = Commonness.UNUSUAL)

						undefined_bits = [ bitno for bitno in point.reasons if isinstance(bitno, int) ]
						if len(undefined_bits) > 0:
							standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "ReasonFlags ::= BIT STRING {")
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_Reasons_UndefinedBitsAsserted, "CRL Distribution Points X.509 extension contains distribution point #%d which asserts undefined bit(s) %s." % (pointno, ", ".join(str(bit) for bit in sorted(undefined_bits))), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

						if point.reasons_trailing_zero:
							judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_Reasons_TrailingZeros, "CRL Distribution Points X.509 extension contains distribution point #%d which has traililng bit(s)." % (pointno), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
					else:
						has_all_reasons = True

				if not has_all_reasons:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.13", verb = "MUST", text = "When a conforming CA includes a cRLDistributionPoints extension in a certificate, it MUST include at least one DistributionPoint that points to a CRL that covers the certificate for all reasons.")
					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CRLDP_NoPointWithAllReasonBits, "CRL Distribution Points X.509 extension contains no distribution point which asserts all reason bits.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		return judgements

	def _judge_certificate_transparency_sct(self, timestamp_no, sct):
		judgements = SecurityJudgements()
		if not isinstance(sct["sct_version"], SCTVersion):
			standard = RFCReference(rfcno = 6962, sect = "3.2", verb = "MUST", text = "enum { v1(0), (255) } Version;")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTSCT_SCT_UnknownVersion, "Certificate Transparency Signed Certificate Timestamp X.509 contains timestamp #%d with unknown version %d." % (timestamp_no, sct["sct_version"]), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		if not (1262304000000 <= sct["timestamp"] <= 4102444799000):
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTSCT_SCT_ImplausibleTimestamp, "Certificate Transparency Signed Certificate Timestamp X.509 contains implausible timestamp #%d that dates either before 2010 or after 2099 (time_t is %d)." % (timestamp_no, sct["timestamp"] // 1000), commonness = Commonness.UNUSUAL)

		if sct["DigitalSignature"]["hash_algorithm"] not in (HashAlgorithm.sha256, ):
			standard = RFCReference(rfcno = 6962, sect = "2.1.4", verb = "MUST", text = "A log MUST use either elliptic curve signatures using the NIST P-256 curve (Section D.1.2.3 of the Digital Signature Standard [DSS]) or RSA signatures (RSASSA-PKCS1-V1_5 with SHA-256")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTSCT_SCT_InvalidHashFunction, "Certificate Transparency Signed Certificate Timestamp X.509 contains timestamp #%d with disallowed hash algorithm %s." % (timestamp_no, str(sct["DigitalSignature"]["hash_algorithm"])), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		if sct["DigitalSignature"]["sig_algorithm"] not in (SignatureAlgorithm.ECDSA, SignatureAlgorithm.RSA):
			standard = RFCReference(rfcno = 6962, sect = "2.1.4", verb = "MUST", text = "A log MUST use either elliptic curve signatures using the NIST P-256 curve (Section D.1.2.3 of the Digital Signature Standard [DSS]) or RSA signatures (RSASSA-PKCS1-V1_5 with SHA-256")
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTSCT_SCT_InvalidSignatureFunction, "Certificate Transparency Signed Certificate Timestamp X.509 contains timestamp #%d with disallowed signature algorithm %s." % (timestamp_no, str(sct["DigitalSignature"]["sig_algorithm"])), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_certificate_transparency_scts(self, certificate):
		judgements = SecurityJudgements()

		scts_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("CertificateTransparency"))
		if scts_ext is not None:
			if scts_ext.malformed_asn1:
				standard = RFCReference(rfcno = 6962, sect = "3.3", verb = "MUST", text = "SignedCertificateTimestampList ::= OCTET STRING")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTSCT_Malformed_Undecodable, "Certificate Transparency Signed Certificate Timestamp X.509 extension cannot be decoded on ASN.1 layer.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			elif scts_ext.malformed_payload:
				standard = RFCReference(rfcno = 6962, sect = "3.2", verb = "MUST", text = "struct { ... } SignedCertificateTimestamp;")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTSCT_Malformed_Content, "Certificate Transparency Signed Certificate Timestamp X.509 extension cannot be decoded on payload layer.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			else:
				for (timestamp_no, scts) in enumerate(scts_ext.payload["payload"], 1):
					sct = scts["sct"]
					judgements += self._judge_certificate_transparency_sct(timestamp_no, sct)
		return judgements

	def _judge_certificate_transparency_poison(self, certificate):
		judgements = SecurityJudgements()
		poison_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("CertificateTransparencyPrecertificatePoison"))
		if poison_ext is not None:
			judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTPP_IsPrecertificate, "The Certificate Transparency Precertificate Poison X.509 extension is present in the certificate, making it a precertificate.", commonness = Commonness.HIGHLY_UNUSUAL, bits = 0)

			if not poison_ext.critical:
				standard = RFCReference(rfcno = 6962, sect = "3.1", verb = "MUST", text = "The Precertificate is constructed from the certificate to be issued by adding a special critical poison extension")
				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTPP_NotCritical, "The Certificate Transparency Precertificate Poison X.509 extension is not marked as critical, turning it into an invalid precertificate.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

# TODO PROPERLY REFACTOR THIS
#			if poison_ext.malformed:
#				standard = RFCReference(rfcno = 6962, sect = "3.1", verb = "MUST", text = "whose extnValue OCTET STRING contains ASN.1 NULL data (0x05 0x00))")
#				judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTPP_Malformed_Undecodable, "The Certificate Transparency Precertificate Poison X.509 extension needs to contain an ASN.1 NULL value, but instead is not decodable.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
#			else:
#				if not isinstance(poison_ext.asn1, pyasn1.type.univ.Null):
#					standard = RFCReference(rfcno = 6962, sect = "3.1", verb = "MUST", text = "whose extnValue OCTET STRING contains ASN.1 NULL data (0x05 0x00))")
#					judgements += SecurityJudgement(JudgementCode.X509Cert_Body_X509Exts_Ext_CTPP_InvalidPayload, "The Certificate Transparency Precertificate Poison X.509 extension needs to contain an ASN.1 NULL value, but instead contains %s." % (type(poison_ext.asn1).__name__), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_certificate_extension_encoding(self, certificate):
		judgements = SecurityJudgements()
		for extension in certificate.extensions:
			if extension.asn1_model is None:
				validator = self._UNKNOWN_EXTENSION_ENCODING_VALIDATOR
			else:
				ext_class_name = extension.__class__.__name__
				validator = self._EXTENSION_ENCODING_VALIDATORS[ext_class_name]
			judgements += validator.validate(extension.detailed_asn1)
		return judgements

	def analyze(self, certificate):
		individual = [ ]
		for extension in certificate.extensions:
			individual.append(self._analyze_extension(extension))

		judgements = SecurityJudgements()
		judgements += self._judge_certificate_extension_encoding(certificate)
		judgements += self._judge_may_have_exts(certificate)
		judgements += self._judge_extension_known(certificate)
		judgements += self._judge_unique_id(certificate)
		judgements += self._judge_uniqueness(certificate)
		judgements += self._judge_basic_constraints(certificate)
		judgements += self._judge_subject_key_identifier(certificate)
		judgements += self._judge_authority_key_identifier(certificate)
		judgements += self._judge_name_constraints(certificate)
		judgements += self._judge_key_usage(certificate)
		judgements += self._judge_extended_key_usage(certificate)
		judgements += self._judge_subject_alternative_name(certificate)
		judgements += self._judge_issuer_alternative_name(certificate)
		judgements += self._judge_authority_information_access(certificate)
		judgements += self._judge_certificate_policy(certificate)
		judgements += self._judge_netscape_certificate_type(certificate)
		judgements += self._judge_crl_distribution_points(certificate)
		judgements += self._judge_certificate_transparency_scts(certificate)
		judgements += self._judge_certificate_transparency_poison(certificate)

		return {
			"individual":	individual,
			"security":		judgements,
		}
