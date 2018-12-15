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

from x509sak.OID import OIDDB
from x509sak.AlgorithmDB import HashFunctions
from x509sak.X509Extensions import X509ExtendedKeyUsageExtension
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements
from x509sak.Tools import ValidationTools

@BaseEstimator.register
class CrtExtensionsSecurityEstimator(BaseEstimator):
	_ALG_NAME = "crt_exts"

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
			return SecurityJudgement(JudgementCode.Cert_X509Ext_NotAllowed, "X.509 extension present in v%d certificate. This is a direct violation of RFC5280, Sect. 4.1.2.9." % (certificate.version), compatibility = Compatibility.STANDARDS_VIOLATION)
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
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_Malformed, "X.509 extension %s was not decodable; it appears to be malformed." % (oid_name), compatibility = Compatibility.STANDARDS_VIOLATION, commonness = Commonness.HIGHLY_UNUSUAL)
		return judgements

	def _judge_unique_id(self, certificate):
		judgements = SecurityJudgements()
		if (certificate.version == 1) or ((certificate.version == 3) and (len(certificate.extensions) == 0)):
			if certificate.version == 3:
				additional_note = " without any X.509 extensions"
			else:
				additional_note = ""
			if certificate.issuer_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.Cert_UniqueID_NotAllowed, "Issuer unique IDs is present in v%d certificate%s. This is a direct violation of RFC5280, Sect. 4.1.2.8." % (certificate.version, additional_note), compatibility = Compatibility.STANDARDS_VIOLATION)
			if certificate.subject_unique_id is not None:
				judgements += SecurityJudgement(JudgementCode.Cert_UniqueID_NotAllowed, "Subject unique IDs is present in v%d certificate%s. This is a direct violation of RFC5280, Sect. 4.1.2.8." % (certificate.version, additional_note), compatibility = Compatibility.STANDARDS_VIOLATION)
		return judgements

	def _judge_uniqueness(self, certificate):
		have_oids = set()

		for extension in certificate.extensions:
			if extension.oid in have_oids:
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_Duplicate, "X.509 extension %s (OID %s) is present at least twice. This is a direct violation of RFC5280, Sect. 4.2." % (extension.name, str(extension.oid)), compatibility = Compatibility.STANDARDS_VIOLATION)
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

	def _judge_authority_key_identifier(self, certificate):
		judgements = SecurityJudgements()
		aki = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("AuthorityKeyIdentifier"))
		if aki is None:
			judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_Missing, "AuthorityKeyIdentifier extension is missing.", commonness = Commonness.UNUSUAL)
		else:
			if aki.critical:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityKeyIdentifier_Critical, "AuthorityKeyIdentifier X.509 extension is marked critical. This is a direct violation of RFC5280, Sect. 4.2.1.1.", compatibility = Compatibility.STANDARDS_VIOLATION)
		return judgements

	def _judge_name_constraints(self, certificate):
		judgements = SecurityJudgements()
		nc = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("NameConstraints"))
		if nc is not None:
			if not nc.critical:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_NameConstraints_PresentButNotCritical, "NameConstraints X.509 extension present, but not marked critical. This is a direct violation of RFC5280 Sect. 4.2.1.10.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)
			if not certificate.is_ca_certificate:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_NameConstraints_PresentButNotCA, "NameConstraints X.509 extension present, but certificate is not a CA certificate. This is a direct violation of RFC5280 Sect. 4.2.1.10.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)
		return judgements


	def _judge_key_usage(self, certificate):
		judgements = SecurityJudgements()
		ku_ext = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("KeyUsage"))
		if ku_ext is not None:
			max_bit_cnt = 9
			if len(ku_ext.asn1) == 0:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_Empty, "KeyUsage extension present, but contains empty bitlist. This is a direct violation of RFC5280 Sect. 4.2.1.3.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)
			elif len(ku_ext.asn1) > max_bit_cnt:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_TooLong, "KeyUsage extension present, but contains too many bits (%d found, %d expected at maximum). This is a direct violation of RFC5280 Sect. 4.2.1.3." % (len(ku_ext.asn1), max_bit_cnt), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)

			if not ku_ext.critical:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_NonCritical, "KeyUsage extension present, but not marked as critical. This is a recommendation of RFC5280 Sect. 4.2.1.3.", compatibility = Compatibility.STANDARDS_RECOMMENDATION)

			if "keyCertSign" in ku_ext.flags:
				if not certificate.is_ca_certificate:
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_SignCertNoCA, "KeyUsage extension contains the keyCertSign flag, but certificate is not a CA certificate. This is a recommendation of RFC5280 Sect. 4.2.1.3.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)

				bc = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("BasicConstraints"))
				if bc is None:
					judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_SignCertNoBasicConstraints, "KeyUsage extension contains the keyCertSign flag, but no BasicConstraints extension. This is a recommendation of RFC5280 Sect. 4.2.1.3.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)
		else:
			if certificate.is_ca_certificate:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_KeyUsage_Missing, "CA certificate must contains a KeyUsage X.509 extension, but this is missing. This is a direct violation of RFC5280, Sect. 4.2.1.3.", commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_VIOLATION)
		return judgements

	def _judge_single_general_name(self, entity_name, allow_dnsname_wildcard_matches, extension_str, standard_str, codes):
		if entity_name.str_value == "":
			return SecurityJudgement(codes["empty"], "%s of type %s has empty value. This is a direct violation of %s." % (extension_str, entity_name.name, standard_str), compatibility = Compatibility.STANDARDS_VIOLATION)

		if entity_name.name == "dNSName":
			if allow_dnsname_wildcard_matches:
				(result, label) = ValidationTools.validate_domainname_template(entity_name.str_value)
				if result != ValidationTools.DomainnameTemplateValidationResult.Valid:
					if result == ValidationTools.DomainnameTemplateValidationResult.InvalidCharacter:
						return SecurityJudgement(codes["bad_domain"], "%s of type %s got invalid domain name \"%s\", error at label \"%s\". This is a direct violation of %s." % (extension_str, entity_name.name, entity_name.str_value, label, standard_str), compatibility = Compatibility.STANDARDS_VIOLATION)
					elif result == ValidationTools.DomainnameTemplateValidationResult.FullWildcardNotLeftmost:
						return SecurityJudgement(codes["bad_wc_notleftmost"], "%s of type %s got invalid domain name \"%s\". Full wildcard appears not as leftmost element. This is a direct violation of RFC6125, Sect. 6.4.3." % (extension_str, entity_name.name, entity_name.str_value), compatibility = Compatibility.STANDARDS_VIOLATION)
					elif result == ValidationTools.DomainnameTemplateValidationResult.MoreThanOneWildcard:
						return SecurityJudgement(codes["bad_wc_morethanone"], "%s of type %s got invalid domain name \"%s\". More than one wildcard label present. This is a direct violation of RFC6125, Sect. 6.4.3." % (extension_str, entity_name.name, entity_name.str_value), compatibility = Compatibility.STANDARDS_VIOLATION)
					elif result == ValidationTools.DomainnameTemplateValidationResult.WildcardInInternationalDomain:
						return SecurityJudgement(codes["bad_wc_international"], "%s of type %s got invalid domain name \"%s\". Wildcard in international domain label \"%s\". This is a direct violation of RFC6125, Sect. 6.4.3" % (extension_str, entity_name.name, entity_name.str_value, label), compatibility = Compatibility.STANDARDS_VIOLATION)
					else:
						raise NotImplementedError(result)

				if "*" in entity_name.str_value:
					# Wildcard match
					labels = entity_name.str_value.split(".")
					if len(labels) <= 2:
						return SecurityJudgement(codes["bad_wc_broad"], "%s of type %s and wildcard value \"%s\" has very broad domain match." % (extension_str, entity_name.name, entity_name.str_value), commonness = Commonness.HIGHLY_UNUSUAL)
			else:
				result = ValidationTools.validate_domainname(entity_name.str_value)
				if not reuslt:
					return SecurityJudgement(codes["bad_domain"], "%s of type %s got invalid domain name \"%s\". This is a direct violation of %s." % (extension_str, entity_name.name, entity_name.str_value, standard_str), compatibility = Compatibility.STANDARDS_VIOLATION)

		elif entity_name.name == "iPAddress":
			if len(entity_name.asn1_value) not in [ 4, 16 ]:
				return SecurityJudgement(codes["bad_ip"], "%s of type ipAddress expects either 4 or 16 bytes of data for IPv4/IPv6, but saw %d bytes." % (extension_str, len(entity_name.str_value)), compatibility = Compatibility.STANDARDS_VIOLATION)
		elif entity_name.name == "rfc822Name":
			if not ValidationTools.validate_email_address(entity_name.str_value):
				return SecurityJudgement(codes["bad_email"], "%s of type %s got invalid email address \"%s\". This is a direct violation of %s." % (extension_str, entity_name.name, entity_name.str_value, standard_str), compatibility = Compatibility.STANDARDS_VIOLATION)
		elif entity_name.name == "uniformResourceIdentifier":
			if not ValidationTools.validate_uri(str(entity_name.str_value)):
				return SecurityJudgement(codes["bad_uri"], "%s of type %s got invalid URI \"%s\". This is a direct violation of %s." % (extension_str, entity_name.name, str(entity_name.str_value), standard_str), compatibility = Compatibility.STANDARDS_VIOLATION)

		return None

	def _judge_single_subject_alternative_name(self, entity_name):
		return self._judge_single_general_name(entity_name, allow_dnsname_wildcard_matches = True, extension_str = "Subject Alternative X.509 extension", standard_str = "RFC5280, Sect. 4.2.1.6", codes = {
			"empty":				JudgementCode.Cert_X509Ext_SubjectAltName_EmptyValue,
			"bad_domain":			JudgementCode.Cert_X509Ext_SubjectAltName_BadDomain,
			"bad_wc_notleftmost":	JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_NotLeftmost,
			"bad_wc_morethanone":	JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_MoreThanOneWildcard,
			"bad_wc_international":	JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_InternationalLabel,
			"bad_wc_broad":			JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_BroadMatch,
			"bad_ip":				JudgementCode.Cert_X509Ext_SubjectAltName_BadIP,
			"bad_email":			JudgementCode.Cert_X509Ext_SubjectAltName_BadEmail,
			"bad_uri":				JudgementCode.Cert_X509Ext_SubjectAltName_BadURI,
		})

	def _judge_subject_alternative_name(self, certificate):
		judgements = SecurityJudgements()
		san = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("SubjectAlternativeName"))
		if san is not None:
			if san.name_count == 0:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_Empty, "Subject Alternative Name X.509 extension with no contained names. This is a direct violation of RFC5280, Sect. 4.2.1.6.", compatibility = Compatibility.STANDARDS_VIOLATION)
			for entity_name in san:
				judgements += self._judge_single_subject_alternative_name(entity_name)
			if (not certificate.subject.empty) and san.critical:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_Critical, "Subject Alternative Name X.509 extension should not be critical when a subject is present. This is a direct violation of RFC5280, Sect. 4.2.1.6.", compatibility = Compatibility.STANDARDS_VIOLATION)
			elif certificate.subject.empty and (not san.critical):
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_NotCritical, "Subject Alternative Name X.509 extension should be critical when no subject is present. This is a direct violation of RFC5280, Sect. 4.2.1.6.", compatibility = Compatibility.STANDARDS_VIOLATION)

			if (not certificate.subject.empty) and (set(santuple.name for santuple in san) == set([ "rfc822Name" ])):
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectAltName_EmailOnly, "Subject Alternative Name X.509 extension only contains email addresses even though subject is non-empty. This is a direct violation of RFC5280, Sect. 4.2.1.6.", compatibility = Compatibility.STANDARDS_VIOLATION)

		return judgements

	def _judge_authority_information_access(self, certificate):
		judgements = SecurityJudgements()
		aia = certificate.extensions.get_first(OIDDB.X509Extensions.inverse("id-pe-authorityInfoAccess"))
		if aia is not None:
			if aia.critical:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityInformationAccess_Critical, "Authority Information Access X.509 extension is marked critical. This is a direct violation of RFC5280, Sect. 4.2.2.1.", compatibility = Compatibility.STANDARDS_VIOLATION)
			if aia.method_count == 0:
				judgements += SecurityJudgement(JudgementCode.Cert_X509Ext_AuthorityInformationAccess_Empty, "Authority Information Access X.509 extension contains no access methods. This is a direct violation of RFC5280, Sect. 4.2.2.1.", compatibility = Compatibility.STANDARDS_VIOLATION)

		return judgements

	def analyze(self, certificate):
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
		judgements += self._judge_authority_key_identifier(certificate)
		judgements += self._judge_name_constraints(certificate)
		judgements += self._judge_key_usage(certificate)
		judgements += self._judge_subject_alternative_name(certificate)
		judgements += self._judge_authority_information_access(certificate)

		return {
			"individual":	individual,
			"security":		judgements,
		}
