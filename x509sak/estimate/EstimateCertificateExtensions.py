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

import collections
import pyasn1.type.base
from x509sak.OID import OID, OIDDB
from x509sak.AlgorithmDB import HashFunctions
from x509sak.X509Extensions import X509ExtendedKeyUsageExtension
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, RFCReference
from x509sak.Tools import ValidationTools

@BaseEstimator.register
class CrtExtensionsSecurityEstimator(BaseEstimator):
	_ALG_NAME = "crt_exts"
	_NameError = collections.namedtuple("NameError", [ "code", "standard" ])

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
		if (certificate.version < 3) and len(certificate.extensions) > 0:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.9", verb = "MUST", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
			return SecurityJudgement(JudgementCode.Cert_X509Ext_NotAllowed, "X.509 extension present in v%d certificate." % (certificate.version), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			return None

	def _judge_extension_known(self, certificate):
		judgements = SecurityJudgements()
		for ext in certificate.extensions:
			oid_name = OIDDB.X509Extensions.get(ext.oid)
			if oid_name is None:
				if ext.critical:
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_Unknown_Critical, "X.509 extension present with OID %s. This OID is not known and marked as critical; the certificate would be rejected under normal circumstances." % (ext.oid), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)
				else:
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_Unknown_NonCritical, "X.509 extension present with OID %s. This OID is not known and marked as non-critical; the extension would be ignored under normal circumstances." % (ext.oid), commonness = Commonness.UNUSUAL)
		return judgements

	def _judge_undecodable_extensions(self, certificate):
		judgements = SecurityJudgements()
		for ext in certificate.extensions:
			if (ext.asn1_model is not None) and (ext.asn1 is None):
				oid_name = OIDDB.X509Extensions.get(ext.oid)
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_Malformed, "X.509 extension %s was not decodable; it appears to be malformed." % (oid_name), compatibility = Compatibility.STANDARDS_DEVIATION, commonness = Commonness.HIGHLY_UNUSUAL)
		return judgements

	def _judge_unique_id(self, certificate):
		judgements = SecurityJudgements()
		if certificate.version not in [ 2, 3 ]:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.8", verb = "MUST", text = "These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1). These fields MUST NOT appear if the version is 1.")
			if certificate.issuer_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.Cert_UniqueID_NotAllowed, "Issuer unique IDs is present in v%d certificate." % (certificate.version), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if certificate.subject_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.Cert_UniqueID_NotAllowed, "Subject unique IDs is present in v%d certificate." % (certificate.version), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		elif certificate.is_ca_certificate:
			standard = RFCReference(rfcno = 5280, sect = "4.1.2.8", verb = "MUST", text = "CAs conforming to this profile MUST NOT generate certificates with unique identifiers.")
			if certificate.issuer_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.Cert_UniqueID_NotAllowedForCA, "Issuer unique IDs is present in CA certificate.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if certificate.subject_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.Cert_UniqueID_NotAllowedForCA, "Subject unique IDs is present in CA certificate.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_uniqueness(self, certificate):
		have_oids = set()

		for extension in certificate.extensions:
			if extension.oid in have_oids:
				standard = RFCReference(rfcno = 5280, sect = "4.2", verb = "MUST", text = "A certificate MUST NOT include more than one instance of a particular extension.")
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_Duplicate, "X.509 extension %s (OID %s) is present at least twice." % (extension.name, str(extension.oid)), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				break
			have_oids.add(extension.oid)
		else:
			judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_All_Unique, "All X.509 extensions are unique.", commonness = Commonness.COMMON)
		return judgement

	def _judge_basic_constraints(self, certificate):
		bc = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("BasicConstraints"))
		if bc is None:
			judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_BasicConstraints_Missing, "BasicConstraints extension is missing.", commonness = Commonness.HIGHLY_UNUSUAL)
		else:
			if not bc.critical:
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_BasicConstraints_PresentButNotCritical, "BasicConstraints extension is present, but not marked as critical.", commonness = Commonness.UNUSUAL)
			else:
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_BasicConstraints_PresentAndCritical, "BasicConstraints extension is present and marked as critical.", commonness = Commonness.COMMON)
		return judgement

	def _judge_subject_key_identifier(self, certificate):
		ski = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
		if ski is None:
			judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectKeyIdentifier_Missing, "SubjectKeyIdentifier extension is missing.", commonness = Commonness.UNUSUAL)
		else:
			check_hashfncs = [ HashFunctions.sha1, HashFunctions.sha256, HashFunctions.sha224, HashFunctions.sha384, HashFunctions.sha512, HashFunctions.md5, HashFunctions.sha3_256, HashFunctions.sha3_384, HashFunctions.sha3_512 ]
			tried_hashfncs = [ ]
			cert_ski = ski.keyid
			for hashfnc in check_hashfncs:
				try:
					computed_ski = certificate.pubkey.keyid(hashfnc = hashfnc.name)
					if cert_ski == computed_ski:
						if hashfnc == HashFunctions.sha1:
							judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectKeyIdentifier_SHA1, "SubjectKeyIdentifier present and matches SHA-1 of contained public key.", commonness = Commonness.COMMON)
						else:
							judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectKeyIdentifier_OtherHash, "SubjectKeyIdentifier present and matches %s of contained public key." % (hashfnc.value.pretty_name), commonness = Commonness.UNUSUAL)
						break
					tried_hashfncs.append(hashfnc)
				except ValueError:
					pass
			else:
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectKeyIdentifier_Arbitrary, "SubjectKeyIdentifier key ID (%s) does not match any tested cryptographic hash function (%s) over the contained public key." % (ski.keyid.hex(), ", ".join(hashfnc.value.pretty_name for hashfnc in tried_hashfncs)), commonness = Commonness.HIGHLY_UNUSUAL)
		return judgement

	def _judge_single_authority_key_identifier_ca_name(self, entity_name):
		return self._judge_single_general_name(entity_name, allow_dnsname_wildcard_matches = True, extension_str = "Authority Key Identifier X.509 extension", name_errors = {
			"empty":				self._NameError(code = JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CAName_EmptyValue, standard = RFCReference(rfcno = 5280, sect = [ "4.2.1.1", "4.2.1.6" ], verb = "MUST", text = "GeneralName ::= CHOICE {")),
			"bad_domain":			self._NameError(code = JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadDomain, standard = RFCReference(rfcno = 1034, sect = "3.5", verb = "MUST", text = "The following syntax will result in fewer problems with many applications that use domain names (e.g., mail, TELNET).")),
			"bad_ip":				self._NameError(code = JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadIP, standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "For IP version 4, as specified in [RFC791], the octet string MUST contain exactly four octets. For IP version 6, as specified in [RFC2460], the octet string MUST contain exactly sixteen octets.")),
			"bad_email":			self._NameError(code = JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadEmail, standard = RFCReference(rfcno = 822, sect = "6.1", verb = "MUST", text = "addr-spec = local-part \"@\" domain")),
			"bad_uri":				self._NameError(code = JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadURI, standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "The name MUST NOT be a relative URI, and it MUST follow the URI syntax and encoding rules specified in [RFC3986]. The name MUST include both a scheme (e.g., \"http\" or \"ftp\") and a scheme-specific-part. URIs that include an authority ([RFC3986], Section 3.2) MUST include a fully qualified domain name or IP address as the host.")),
		})

	def _judge_authority_key_identifier(self, certificate, root_cert = None):
		judgements = SecurityJudgements()
		aki = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("AuthorityKeyIdentifier"))
		if aki is None:
			if not certificate.is_selfsigned:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "MUST", text = "The keyIdentifier field of the authorityKeyIdentifier extension MUST be included in all certificates generated by conforming CAs to facilitate certification path construction.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_Missing, "AuthorityKeyIdentifier extension is missing.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			else:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "SHOULD", text = "where a CA distributes its public key in the form of a \"self-signed\" certificate, the authority key identifier MAY be omitted.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_Missing, "AuthorityKeyIdentifier extension is missing.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			if aki.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "MUST", text = "Conforming CAs MUST mark this extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_Critical, "AuthorityKeyIdentifier X.509 extension is marked critical.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if aki.keyid is None:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_NoKeyIDPresent, "AuthorityKeyIdentifier X.509 extension contains no key ID.", commonness = Commonness.UNUSUAL)
			elif len(aki.keyid) == 0:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_KeyIDEmpty, "AuthorityKeyIdentifier X.509 extension contains empty key ID.", commonness = Commonness.HIGHLY_UNUSUAL)
			elif len(aki.keyid) > 64:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_KeyIDLong, "AuthorityKeyIdentifier X.509 extension contains long key ID (%d bytes)." % (len(aki.keyid)), commonness = Commonness.HIGHLY_UNUSUAL)

			if aki.ca_names is not None:
				if aki.ca_names == 0:
					standard = RFCReference(rfcno = 5280, sect = [ "4.2.1.1", "4.2.1.6" ], verb = "MUST", text = "GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName")
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CAName_Empty, "AuthorityKeyIdentifier X.509 extension contains CA names field of length zero.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				for entity_name in aki.ca_names:
					judgements += self._judge_single_authority_key_identifier_ca_name(entity_name)

			if (aki.ca_names is None) and (aki.serial is not None):
				standard = RFCReference(rfcno = 5280, sect = "A.2", verb = "MUST", text = "authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_SerialWithoutName, "AuthorityKeyIdentifier X.509 extension contains CA serial number, but no CA issuer.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			elif (aki.ca_names is not None) and (aki.serial is None):
				standard = RFCReference(rfcno = 5280, sect = "A.2", verb = "MUST", text = "authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_NameWithoutSerial, "AuthorityKeyIdentifier X.509 extension contains CA issuer, but no CA serial number.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

			if root_cert is not None:
				root_ski = root_cert.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
				if root_ski is None:
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CA_NoSKI, "AuthorityKeyIdentifier X.509 extension present, but given root certificate does not contain any subject key identifier.", commonness = Commonness.HIGHLY_UNUSUAL)
				else:
					if (aki.keyid is not None) and (aki.keyid != root_ski.keyid):
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "MUST", text = "The authority key identifier extension provides a means of identifying the public key corresponding to the private key used to sign a certificate.")
						judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CA_KeyIDMismatch, "AuthorityKeyIdentifier X.509 extension refers to authority key ID %s, but CA has key ID %s as their SubjectKeyIdentifier." % (aki.keyid.hex(), root_ski.keyid.hex()), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
					if (aki.serial is not None) and (aki.serial != root_cert.serial):
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.1", verb = "MUST", text = "The authority key identifier extension provides a means of identifying the public key corresponding to the private key used to sign a certificate.")
						judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_CA_SerialMismatch, "AuthorityKeyIdentifier X.509 extension refers to CA certificate with serial number 0x%x, but given CA has serial number 0x%x." % (aki.serial, root_cert.serial), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
		return judgements

	def _judge_name_constraints(self, certificate):
		judgements = SecurityJudgements()
		nc = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("NameConstraints"))
		if nc is not None:
			if not nc.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.10", verb = "MUST", text = "Conforming CAs MUST mark this extension as critical")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_NameConstraints_PresentButNotCritical, "NameConstraints X.509 extension present, but not marked critical.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if not certificate.is_ca_certificate:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.10", verb = "MUST", text = "The name constraints extension, which MUST be used only in a CA certificate, indicates a name space within which all subject names in subsequent certificates in a certification path MUST be located.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_NameConstraints_PresentButNotCA, "NameConstraints X.509 extension present, but certificate is not a CA certificate.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		return judgements


	def _judge_key_usage(self, certificate):
		judgements = SecurityJudgements()
		ku_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("KeyUsage"))
		if ku_ext is not None:
			highest_bit_value = len(ku_ext.asn1) - 1
			highest_allowed_bit_value = 8
			if len(ku_ext.asn1) == 0:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "When the keyUsage extension appears in a certificate, at least one of the bits MUST be set to 1.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_Empty, "KeyUsage extension present, but contains empty bitlist.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			elif highest_bit_value > highest_allowed_bit_value:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "decipherOnly (8) }")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_TooLong, "KeyUsage extension present, but contains too many bits (highest bit value %d, but %d expected as maximum)." % (highest_bit_value, highest_allowed_bit_value), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

			if not ku_ext.critical:
				if certificate.is_ca_certificate:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "SHOULD", text = "When present, conforming CAs SHOULD mark this extension as critical.")
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_NonCritical, "CA certificate contains KeyUsage X.509 extension, but it is not marked as critical.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				else:
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_NonCritical, "CA certificate contains KeyUsage X.509 extension, but it is not marked as critical.", commonness = Commonness.UNUSUAL)

			if "keyCertSign" in ku_ext.flags:
				bc = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("BasicConstraints"))
				if bc is None:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension (Section 4.2.1.9) MUST also be asserted.")
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_SignCertNoBasicConstraints, "KeyUsage extension contains the keyCertSign flag, but no BasicConstraints extension.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
				elif not bc.is_ca:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension (Section 4.2.1.9) MUST also be asserted.")
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_SignCertNoCA, "KeyUsage extension contains the keyCertSign flag, but BasicConstraints extension do not mark as a CA certificate.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			if certificate.is_ca_certificate:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.3", verb = "MUST", text = "Conforming CAs MUST include this extension in certificates that contain public keys that are used to validate digital signatures on other public key certificates or CRLs.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_Missing, "CA certificate must contain a KeyUsage X.509 extension, but it is missing.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)


		return judgements

	def _judge_extended_key_usage(self, certificate):
		judgements = SecurityJudgements()
		eku_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("ExtendedKeyUsage"))
		if eku_ext is not None:
			number_oids = len(list(eku_ext.key_usage_oids))
			number_unique_oids = len(set(eku_ext.key_usage_oids))
			if number_oids == 0:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.12", verb = "MUST", text = "ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_ExtKeyUsage_Empty, "ExtendedKeyUsage extension present, but contains no OIDs.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if number_oids != number_unique_oids:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_ExtKeyUsage_Duplicate, "ExtendedKeyUsage extension present, but contains duplicate OIDs. There are %d OIDs present, but only %d are unique." % (number_oids, number_unique_oids), commonness = Commonness.HIGHLY_UNUSUAL)
			if eku_ext.any_key_usage and eku_ext.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.12", verb = "SHOULD", text = "Conforming CAs SHOULD NOT mark this extension as critical if the anyExtendedKeyUsage KeyPurposeId is present.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_ExtKeyUsage_AnyUsageCritical, "ExtendedKeyUsage extension contains the anyKeyUsage OID, but is also marked as critical.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_single_general_name(self, entity_name, allow_dnsname_wildcard_matches, extension_str, name_errors):
		if entity_name.str_value == "":
			return SecurityJudgement(name_errors["empty"].code, "%s of type %s has empty value." % (extension_str, entity_name.name), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["empty"].standard)

		if entity_name.name == "dNSName":
			if entity_name.str_value == " ":
				return SecurityJudgement(name_errors["bad_domain_space"].code, "%s of type %s got invalid domain name \"%s\"." % (extension_str, entity_name.name, entity_name.str_value), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_domain_space"].standard)

			if allow_dnsname_wildcard_matches:
				(result, label) = ValidationTools.validate_domainname_template(entity_name.str_value)
				if result != ValidationTools.DomainnameTemplateValidationResult.Valid:
					if result == ValidationTools.DomainnameTemplateValidationResult.InvalidCharacter:
						return SecurityJudgement(name_errors["bad_domain"].code, "%s of type %s got invalid domain name \"%s\", error at label \"%s\"." % (extension_str, entity_name.name, entity_name.str_value, label), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_domain"].standard)
					elif result == ValidationTools.DomainnameTemplateValidationResult.FullWildcardNotLeftmost:
						return SecurityJudgement(name_errors["bad_wc_notleftmost"].code, "%s of type %s got invalid domain name \"%s\". Full wildcard appears not as leftmost element." % (extension_str, entity_name.name, entity_name.str_value), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_wc_notleftmost"].standard)
					elif result == ValidationTools.DomainnameTemplateValidationResult.MoreThanOneWildcard:
						return SecurityJudgement(name_errors["bad_wc_morethanone"].code, "%s of type %s got invalid domain name \"%s\". More than one wildcard label present." % (extension_str, entity_name.name, entity_name.str_value), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_wc_morethanone"].standard)
					elif result == ValidationTools.DomainnameTemplateValidationResult.WildcardInInternationalDomain:
						return SecurityJudgement(name_errors["bad_wc_international"].code, "%s of type %s got invalid domain name \"%s\". Wildcard in international domain label \"%s\"." % (extension_str, entity_name.name, entity_name.str_value, label), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_wc_international"].standard)
					else:
						raise NotImplementedError(result)

				if "*" in entity_name.str_value:
					# Wildcard match
					labels = entity_name.str_value.split(".")
					if len(labels) <= 2:
						return SecurityJudgement(name_errors["bad_wc_broad"].code, "%s of type %s and wildcard value \"%s\" has very broad domain match." % (extension_str, entity_name.name, entity_name.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

			validation_name = entity_name.str_value
			if allow_dnsname_wildcard_matches:
				validation_name = validation_name.replace("*", "a")
			result = ValidationTools.validate_domainname(validation_name)
			if not result:
				return SecurityJudgement(name_errors["bad_domain"].code, "%s of type %s got invalid domain name \"%s\" (wildcard matches %s)." % (extension_str, entity_name.name, entity_name.str_value, "permitted" if allow_dnsname_wildcard_matches else "forbidden"), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_domain"].standard)

		elif entity_name.name == "iPAddress":
			if len(entity_name.asn1_value) not in [ 4, 16 ]:
				return SecurityJudgement(name_errors["bad_ip"].code, "%s of type ipAddress expects either 4 or 16 bytes of data for IPv4/IPv6, but saw %d bytes." % (extension_str, len(entity_name.str_value)), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_ip"].standard)
		elif entity_name.name == "rfc822Name":
			if not ValidationTools.validate_email_address(entity_name.str_value):
				return SecurityJudgement(name_errors["bad_email"].code, "%s of type %s got invalid email address \"%s\"." % (extension_str, entity_name.name, entity_name.str_value), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_email"].standard)
		elif entity_name.name == "uniformResourceIdentifier":
			if not ValidationTools.validate_uri(str(entity_name.str_value)):
				return SecurityJudgement(name_errors["bad_uri"].code, "%s of type %s got invalid URI \"%s\"." % (extension_str, entity_name.name, str(entity_name.str_value)), compatibility = Compatibility.STANDARDS_DEVIATION, standard = name_errors["bad_uri"].standard)

		return None

	def _judge_single_subject_alternative_name(self, entity_name):
		return self._judge_single_general_name(entity_name, allow_dnsname_wildcard_matches = True, extension_str = "Subject Alternative X.509 extension", name_errors = {
			"empty":				self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_EmptyValue, standard = RFCReference(rfcno = 5280, sect = [ "4.2.1.1", "4.2.1.6" ], verb = "MUST", text = "GeneralName ::= CHOICE {")),
			"bad_domain":			self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadDomain, standard = RFCReference(rfcno = 1034, sect = "3.5", verb = "MUST", text = "The following syntax will result in fewer problems with many applications that use domain names (e.g., mail, TELNET).")),
			"bad_domain_space":		self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadDomain_Space, standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "In addition, while the string \" \" is a legal domain name, subjectAltName extensions with a dNSName of \" \" MUST NOT be used.")),
			"bad_wc_notleftmost":	self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_NotLeftmost, standard = RFCReference(rfcno = 6125, sect = "6.4.3", verb = "SHOULD", text = "The client SHOULD NOT attempt to match a presented identifier in which the wildcard character comprises a label other than the left-most label")),
			"bad_wc_morethanone":	self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_MoreThanOneWildcard, standard = RFCReference(rfcno = 6125, sect = "6.4.3", verb = "SHOULD", text = "If the wildcard character is the only character of the left-most label in the presented identifier, the client SHOULD NOT compare against anything but the left-most label of the reference identifier")),
			"bad_wc_international":	self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_InternationalLabel, standard = RFCReference(rfcno = 6125, sect = "6.4.3", verb = "SHOULD", text = "However, the client SHOULD NOT attempt to match a presented identifier where the wildcard character is embedded within an A-label or U-label [IDNA-DEFS] of an internationalized domain name [IDNA-PROTO].")),
			"bad_wc_broad":			self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_BroadMatch, standard = None),
			"bad_ip":				self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP, standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "For IP version 4, as specified in [RFC791], the octet string MUST contain exactly four octets. For IP version 6, as specified in [RFC2460], the octet string MUST contain exactly sixteen octets.")),
			"bad_email":			self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadEmail, standard = RFCReference(rfcno = 822, sect = "6.1", verb = "MUST", text = "addr-spec = local-part \"@\" domain")),
			"bad_uri":				self._NameError(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadURI, standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "The name MUST NOT be a relative URI, and it MUST follow the URI syntax and encoding rules specified in [RFC3986]. The name MUST include both a scheme (e.g., \"http\" or \"ftp\") and a scheme-specific-part. URIs that include an authority ([RFC3986], Section 3.2) MUST include a fully qualified domain name or IP address as the host.")),
		})

	def _judge_subject_alternative_name(self, certificate):
		judgements = SecurityJudgements()
		san = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectAlternativeName"))
		if san is not None:
			if san.name_count == 0:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "If the subjectAltName extension is present, the sequence MUST contain at least one entry.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_Empty, "Subject Alternative Name X.509 extension with no contained names.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			for entity_name in san:
				judgements += self._judge_single_subject_alternative_name(entity_name)
			if (not certificate.subject.empty) and san.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "SHOULD", text = "When including the subjectAltName extension in a certificate that has a non-empty subject distinguished name, conforming CAs SHOULD mark the subjectAltName extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_Critical, "Subject Alternative Name X.509 extension should not be critical when a subject is present.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			elif certificate.subject.empty and (not san.critical):
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "If the subject field contains an empty sequence, then the issuing CA MUST include a subjectAltName extension that is marked as critical.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_NotCritical, "Subject Alternative Name X.509 extension should be critical when no subject is present.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

			if (not certificate.subject.empty) and (set(santuple.name for santuple in san) == set([ "rfc822Name" ])):
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "Further, if the only subject identity included in the certificate is an alternative name form (e.g., an electronic mail address), then the subject distinguished name MUST be empty (an empty sequence), and the subjectAltName extension MUST be present.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_EmailOnly, "Subject Alternative Name X.509 extension only contains email addresses even though subject is non-empty.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			judgements += SecurityJudgement(JudgementCode.Cert_No_SAN_Present, "No Subject Alternative Name X.509 extension present in the certificate.", commonness = Commonness.UNUSUAL)

			if certificate.subject.empty:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "If the subject field contains an empty sequence, then the issuing CA MUST include a subjectAltName extension that is marked as critical.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_Missing, "Subject Alternative Name X.509 missing although subject is empty.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_single_issuer_alternative_name(self, entity_name):
		return self._judge_single_general_name(entity_name, allow_dnsname_wildcard_matches = False, extension_str = "Issuer Alternative X.509 extension", name_errors = {
			"empty":				self._NameError(code = JudgementCode.Cert_X509Ext_IssuerAltName_EmptyValue, standard = RFCReference(rfcno = 5280, sect = [ "4.2.1.1", "4.2.1.6" ], verb = "MUST", text = "GeneralName ::= CHOICE {")),
			"bad_domain":			self._NameError(code = JudgementCode.Cert_X509Ext_IssuerAltName_BadDomain, standard = RFCReference(rfcno = 1034, sect = "3.5", verb = "MUST", text = "The following syntax will result in fewer problems with many applications that use domain names (e.g., mail, TELNET).")),
			"bad_ip":				self._NameError(code = JudgementCode.Cert_X509Ext_IssuerAltName_BadIP, standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "For IP version 4, as specified in [RFC791], the octet string MUST contain exactly four octets. For IP version 6, as specified in [RFC2460], the octet string MUST contain exactly sixteen octets.")),
			"bad_email":			self._NameError(code = JudgementCode.Cert_X509Ext_IssuerAltName_BadEmail, standard = RFCReference(rfcno = 822, sect = "6.1", verb = "MUST", text = "addr-spec = local-part \"@\" domain")),
			"bad_uri":				self._NameError(code = JudgementCode.Cert_X509Ext_IssuerAltName_BadURI, standard = RFCReference(rfcno = 5280, sect = "4.2.1.6", verb = "MUST", text = "The name MUST NOT be a relative URI, and it MUST follow the URI syntax and encoding rules specified in [RFC3986]. The name MUST include both a scheme (e.g., \"http\" or \"ftp\") and a scheme-specific-part. URIs that include an authority ([RFC3986], Section 3.2) MUST include a fully qualified domain name or IP address as the host.")),
		})

	def _judge_issuer_alternative_name(self, certificate):
		judgements = SecurityJudgements()
		ian = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("IssuerAlternativeName"))
		if ian is not None:
			if ian.name_count == 0:
				standard = RFCReference(rfcno = 5280, sect = [ "4.2.1.7", "4.2.1.6" ], verb = "MUST", text = "If the subjectAltName extension is present, the sequence MUST contain at least one entry.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_IssuerAltName_Empty, "Issuer Alternative Name X.509 extension with no contained names.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			for entity_name in ian:
				judgements += self._judge_single_issuer_alternative_name(entity_name)
			if ian.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.7", verb = "SHOULD", text = "Where present, conforming CAs SHOULD mark this extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_IssuerAltName_Critical, "Issuer Alternative Name X.509 extension should not be critical.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
		else:
			if certificate.subject.empty:
				standard = RFCReference(rfcno = 5280, sect = [ "4.2.1.7", "4.2.1.6" ], verb = "MUST", text = "If the subject field contains an empty sequence, then the issuing CA MUST include a subjectAltName extension that is marked as critical.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_IssuerAltName_Missing, "Issuer Alternative Name X.509 missing although subject is empty.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_authority_information_access(self, certificate):
		judgements = SecurityJudgements()
		aia = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("id-pe-authorityInfoAccess"))
		if aia is not None:
			if aia.critical:
				standard = RFCReference(rfcno = 5280, sect = "4.2.2.1", verb = "MUST", text = "Conforming CAs MUST mark this extension as non-critical.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityInformationAccess_Critical, "Authority Information Access X.509 extension is marked critical.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
			if aia.method_count == 0:
				standard = RFCReference(rfcno = 5280, sect = "4.2.2.1", verb = "MUST", text = "SEQUENCE SIZE (1..MAX) OF AccessDescription")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityInformationAccess_Empty, "Authority Information Access X.509 extension contains no access methods.", compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def _judge_certificate_policy(self, certificate):
		judgements = SecurityJudgements()

		old_oid = OIDDB.X509Extensions.inverse("oldCertificatePolicies")
		old_policies = certificate.extensions.get_first(old_oid)
		if old_policies is not None:
			standard = RFCReference(rfcno = 5280, sect = "A.2", verb = "MUST", text = "id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }")
			judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_DeprecatedOID, "Deprecated OID %s used to encode certificate policies." % (old_oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)

		policies_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("CertificatePolicies"))
		if policies_ext is not None:
			policies = list(policies_ext.policies)
			seen_oids = { }
			for (policy_number, policy) in enumerate(policies, 1):
				if policy.oid in seen_oids:
					standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "A certificate policy OID MUST NOT appear more than once in a certificate policies extension.")
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_DuplicateOID, "OID %s used as certificate policy #%d has already been used in policy #%d and thus is an illegal duplicate." % (policy.oid, policy_number, seen_oids[policy.oid]), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
				else:
					seen_oids[policy.oid] = policy_number

			any_policy = policies_ext.get_policy(OIDDB.X509ExtensionCertificatePolicy.inverse("anyPolicy"))
			if any_policy is not None:
				for qualifier in any_policy.qualifiers:
					if qualifier.oid not in OIDDB.X509ExtensionCertificatePolicyQualifierOIDs:
						standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "When qualifiers are used with the special policy anyPolicy, they MUST be limited to the qualifiers identified in this section.")
						judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_AnyPolicyUnknownQualifier, "Unknown OID %s used in a qualification of an anyPolicy certificate policy." % (qualifier.oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)

			if policies_ext.policy_count > 1:
				standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "RECOMMEND", text = "To promote interoperability, this profile RECOMMENDS that policy information terms consist of only an OID.")
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_MoreThanOnePolicy, "%d policies present in certificate, but only one is recommended." % (policies_ext.policy_count), compatibility = Compatibility.LIMITED_SUPPORT, standard = standard)

			# Check if qualifier is used twice. Not technically forbidden, but definitely weird.
			for policy in policies:
				qualifier_oids = [ qualifier.oid for qualifier in policy.qualifiers ]
				seen_oids = { }
				for (qualifier_no, qualifier) in enumerate(policy.qualifiers, 1):
					if qualifier.oid in seen_oids:
						judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_DuplicateQualifierOID, "Qualifier #%d (OID %s) has been used previously in policy %s as #%d." % (qualifier_no, qualifier.oid, policy.oid, seen_oids[qualifier.oid]), commonness = Commonness.UNUSUAL)
					else:
						seen_oids[qualifier.oid] = qualifier_no

			# Check for use of noticeRef
			for policy in policies:
				for qualifier in policy.qualifiers:

					if qualifier.oid == OIDDB.X509ExtensionCertificatePolicyQualifierOIDs.inverse("id-qt-unotice"):
						# User notice field is present
						if qualifier.decoded_qualifier is None:
							standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "UserNotice ::= SEQUENCE {")
							judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_UserNoticeDecodeError, "Could not decode user notice qualifier in X.509 Certificate Policies extension of policy %s." % (policy.oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
						else:
							if qualifier.decoded_qualifier.constraint_violation:
								standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "While the explicitText has a maximum size of 200 characters, some non-conforming CAs exceed this limit. Therefore, certificate users SHOULD gracefully handle explicitText with more than 200 characters.")
								judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_UserNoticeConstraintViolation, "User notice qualifier of policy %s contains a qualifier which breaks the ASN.1 length constraint of 200 characters." % (policy.oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

							# Check if noticeRef is present
							# TODO: Is this correct? See https://github.com/etingof/pyasn1/issues/189
							notice_ref = qualifier.decoded_qualifier.asn1.getComponentByName("noticeRef", instantiate = False)
							if not isinstance(notice_ref, pyasn1.type.base.NoValue):
								standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "Conforming CAs SHOULD NOT use the noticeRef option.")
								judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_UserNoticeRefPresent, "User notice qualifier of policy %s contains a noticeRef in the qualifier body." % (policy.oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

							# Check if encoding of explicitText is UTF8String or IA5String
							explicit_text = qualifier.decoded_qualifier.asn1.getComponentByName("explicitText", instantiate = False)
							if isinstance(explicit_text, pyasn1.type.base.NoValue):
								# No explicit_text set?
								judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextAbsent, "User notice qualifier of policy %s does not contain an explicitText element in the qualifier body." % (policy.oid), compatibility = Compatibility.LIMITED_SUPPORT)
							else:
								explicit_text = explicit_text.getComponent()
								if isinstance(explicit_text, pyasn1.type.char.UTF8String):
									# Recommendation fulfilled, don't do anything
									pass
								elif isinstance(explicit_text, pyasn1.type.char.IA5String):
									standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MAY", text = "Conforming CAs SHOULD use the UTF8String encoding for explicitText, but MAY use IA5String.")
									judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextIA5String, "User notice qualifier of policy %s does not contain an explicitText element of type IA5String, although UTF8String is the preferred one." % (policy.oid), compatibility = Compatibility.LIMITED_SUPPORT, standard = standard)
								else:
									standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "Conforming CAs SHOULD use the UTF8String encoding for explicitText, but MAY use IA5String.")
									judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextInvalidStringType, "User notice qualifier of policy %s does not contain an explicitText element of type %s, but only UTF8String or IA5String are permitted." % (policy.oid, type(explicit_text).__name__), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

								contained_chars = set(ord(char) for char in str(explicit_text))
								for char in sorted(contained_chars):
									if (0 <= char <= 0x1f) or (0x7f <= char <= 0x9f):
										standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "SHOULD", text = "The explicitText string SHOULD NOT include any control characters (e.g., U+0000 to U+001F and U+007F to U+009F).")
										judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextControlCharacters, "User notice qualifier of policy %s does not contains control character 0x%x in its explicitText element." % (policy.oid, char), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)
										break

					elif qualifier.oid == OIDDB.X509ExtensionCertificatePolicyQualifierOIDs.inverse("id-qt-cps"):
						# CPS field is present
						if qualifier.decoded_qualifier is None:
							standard = RFCReference(rfcno = 5280, sect = "4.2.1.4", verb = "MUST", text = "CPSuri ::= IA5String")
							judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_CPSDecodeError, "Could not decode CPS qualifier in X.509 Certificate Policies extension of policy %s." % (policy.oid), compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard, commonness = Commonness.HIGHLY_UNUSUAL)
						else:
							uri = str(qualifier.decoded_qualifier.asn1)
							if (not uri.startswith("http://")) and (not uri.startswith("https://")):
								judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_CertificatePolicies_CPSUnusualSchema, "CPS URI of policy %s does not follow http/https schema: %s" % (policy.oid, uri), compatibility = Compatibility.LIMITED_SUPPORT, commonness = Commonness.UNUSUAL)
		return judgements

	def analyze(self, certificate, root_cert = None):
		individual = [ ]
		for extension in certificate.extensions:
			individual.append(self._analyze_extension(extension))

		judgements = SecurityJudgements()
		judgements += self._judge_may_have_exts(certificate)
		judgements += self._judge_extension_known(certificate)
		judgements += self._judge_undecodable_extensions(certificate)
		judgements += self._judge_unique_id(certificate)
		judgements += self._judge_uniqueness(certificate)
		judgements += self._judge_basic_constraints(certificate)
		judgements += self._judge_subject_key_identifier(certificate)
		judgements += self._judge_authority_key_identifier(certificate, root_cert)
		judgements += self._judge_name_constraints(certificate)
		judgements += self._judge_key_usage(certificate)
		judgements += self._judge_extended_key_usage(certificate)
		judgements += self._judge_subject_alternative_name(certificate)
		judgements += self._judge_issuer_alternative_name(certificate)
		judgements += self._judge_authority_information_access(certificate)
		judgements += self._judge_certificate_policy(certificate)

		return {
			"individual":	individual,
			"security":		judgements,
		}
