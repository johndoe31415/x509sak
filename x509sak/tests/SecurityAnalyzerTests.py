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

import json
from x509sak.Exceptions import UnexpectedFileContentException
from x509sak.tests import BaseTest, ResourceFileLoader
from x509sak.Tools import FileLockTools
from x509sak.CertificateAnalyzer import CertificateAnalyzer
from x509sak.X509Certificate import X509Certificate

class SecurityAnalyzerTests(BaseTest):
	def _update_stats_file(self, certname, parent_certname, encountered_codes, checked_codes):
		stats_filename = ".examinecert_stats.json"
		with FileLockTools.lock(stats_filename):
			try:
				with open(stats_filename) as f:
					stats = json.load(f)
			except (FileNotFoundError, json.JSONDecodeError):
				stats = { }

			if "encountered_codes" not in stats:
				stats["encountered_codes"] = { }
			for encountered_code in encountered_codes:
				if encountered_code not in stats["encountered_codes"]:
					stats["encountered_codes"][encountered_code] = [ certname, parent_certname ]

			if "checked_codes" not in stats:
				stats["checked_codes"] = { }
			for checked_code in checked_codes:
				if checked_code not in stats["checked_codes"]:
					stats["checked_codes"][checked_code] = [ certname, parent_certname ]

			with open(stats_filename, "w") as f:
				json.dump(stats, f)

	def _test_examine_x509test_resultcode(self, certname, expect_present = None, expect_absent = None, parent_certname = None, fast_rsa = True, host_check = None, include_raw = False, purpose = None, expect_parse_failure = False):
		if expect_present is None:
			expect_present = tuple()
		if not isinstance(expect_present, (list, tuple)):
			expect_present = (expect_present, )

		if expect_absent is None:
			expect_absent = tuple()
		if not isinstance(expect_absent, (list, tuple)):
			expect_absent = (expect_absent, )

		# Plausibilize we're not chasing non-existing judgement codes (those would always be absent)
		self.assertTrue(JudgementCode.getattr(codename, None) is not None for codename in expect_absent)

		if expect_parse_failure:
			with self.assertRaises(UnexpectedFileContentException):
				X509Certificate.from_pem_data(ResourceFileLoader.load_data(certname))
			return

		certificates = X509Certificate.from_pem_data(ResourceFileLoader.load_data(certname))
		crt_sources = [ CertificateAnalyzer.CertSource(crts = certificates, source = "internal", source_type = "pemcert") ]
		if parent_certname is not None:
			ca_certificate = CertificateAnalyzer.CertSource(crts = X509Certificate.from_pem_data(ResourceFileLoader.load_data(parent_certname)), source = "internal", source_type = "pemcert")
		else:
			ca_certificate = None

		analysis_params = {
			"fast_rsa":				fast_rsa,
			"include_raw_data":		include_raw,
		}
		if host_check is not None:
			analysis_params.update({
				"entity_name":	host_check,
				"purposes":		[ "tls-server" ],
			})
		elif purpose is not None:
			analysis_params["purposes"] = [ purpose ]
		cert_analyzer = CertificateAnalyzer(**analysis_params)
		analyses = cert_analyzer.analyze(crt_sources, ca_certificate)

		encountered_codes = CertificateAnalyzer.extract_codes_from_json(analyses)

		# If we're in debugging mode, update the consolidated JSON stat file
		if self._produce_statistics:
			self._update_stats_file(certname = certname, parent_certname = parent_certname, encountered_codes = encountered_codes, checked_codes = expect_present)
		for code in expect_present:
			self.assertIn(code, encountered_codes)
		for code in expect_absent:
			self.assertNotIn(code, encountered_codes)

	def test_examine_x509test_xf_algo_mismatch1(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-algo-mismatch1.pem", "Cert_Signature_Algorithm_Mismatch")

	def test_examine_x509test_xf_der_invalid_bitstring(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-bitstring.pem", "Cert_Invalid_DER")

	def test_examine_x509test_xf_der_invalid_nonminimal_int(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-nonminimal-int.pem", "Cert_Invalid_DER")

	def test_examine_x509test_xf_der_invalid_uniqueid(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-uniqueid.pem", expect_parse_failure = True)

	def test_examine_x509test_xf_der_pubkey_rsa_nonminimal_int(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-pubkey-rsa-nonminimal-int.pem", "Cert_Pubkey_Invalid_DER")

	def test_examine_x509test_xf_duplicate_extension(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-duplicate-extension.pem", "Cert_X509Ext_Duplicate")

	def test_examine_x509test_xf_duplicate_extension2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-duplicate-extension2.pem", "Cert_X509Ext_Duplicate")

	def test_examine_x509test_xf_ext_altname_blank_domain(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-blank-domain.pem", "Cert_X509Ext_SubjectAltName_BadDNSName_Space")

	def test_examine_x509test_xf_ext_altname_critical_subject(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-critical-subject.pem", "Cert_X509Ext_SubjectAltName_Critical")

	def test_examine_x509test_xf_ext_altname_email_only(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-email-only.pem", "Cert_X509Ext_SubjectAltName_EmailOnly")

	def test_examine_x509test_xf_ext_altname_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-empty.pem", "Cert_X509Ext_SubjectAltName_Empty")

	def test_examine_x509test_xf_ext_altname_empty2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-empty2.pem", "Cert_X509Ext_SubjectAltName_EmptyValue")

	def test_examine_x509test_xf_ext_altname_invalid_domain(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-domain.pem", "Cert_X509Ext_SubjectAltName_BadDNSName")

	def test_examine_x509test_xf_ext_altname_invalid_email(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-email.pem", "Cert_X509Ext_SubjectAltName_BadEmail")

	def test_examine_x509test_xf_ext_altname_invalid_encoding(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-encoding.pem", "Cert_X509Ext_Malformed")

	def test_examine_x509test_xf_ext_altname_ip_wrong(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-ip-wrong.pem", "Cert_X509Ext_SubjectAltName_BadIP")

	def test_examine_x509test_xf_ext_altname_noncrit_nosubj(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-noncrit-nosubj.pem", "Cert_X509Ext_SubjectAltName_NotCritical")

	def test_examine_x509test_xf_ext_altname_relative_uri(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-relative-uri.pem", "Cert_X509Ext_SubjectAltName_BadURI")

	def test_examine_x509test_xf_ext_altname_schemeless_uri(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-schemeless-uri.pem", "Cert_X509Ext_SubjectAltName_BadURI")

	def test_examine_x509test_xf_ext_auth_info_critical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-info-critical.pem", "Cert_X509Ext_AuthorityInformationAccess_Critical")

	def test_examine_x509test_xf_ext_auth_info_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-info-empty.pem", "Cert_X509Ext_AuthorityInformationAccess_Empty")

	def test_examine_x509test_xf_ext_auth_keyid_critical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-critical.pem", "Cert_X509Ext_AuthorityKeyIdentifier_Critical")

	def test_examine_x509test_xf_ext_auth_keyid_invalid_issuer(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-invalid-issuer.pem", "Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadIP")

	def test_examine_x509test_xf_ext_auth_keyid_mismatch(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-mismatch.pem", "Cert_X509Ext_AuthorityKeyIdentifier_CA_KeyIDMismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_examine_x509test_xf_ext_auth_keyid_noid(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-noid.pem", "Cert_X509Ext_AuthorityKeyIdentifier_NoKeyIDPresent")

	def test_examine_x509test_xf_ext_auth_keyid_onlyserial(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-onlyserial.pem", "Cert_X509Ext_AuthorityKeyIdentifier_SerialWithoutName")

	def test_examine_x509test_xf_ext_auth_keyid_serial_mismatch(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-serial-mismatch.pem", "Cert_X509Ext_AuthorityKeyIdentifier_CA_SerialMismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_examine_x509test_xf_ext_cert_policies_any_qual(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-any-qual.pem", "Cert_X509Ext_CertificatePolicies_AnyPolicyUnknownQualifier")

	def test_examine_x509test_xf_ext_cert_policies_bmp_unotice(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-bmp-unotice.pem", "Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextInvalidStringType")

	def test_examine_x509test_xf_ext_cert_policies_dup(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-dup.pem", "Cert_X509Ext_CertificatePolicies_DuplicateOID")

	def test_examine_x509test_xf_ext_cert_policies_unotice_ch(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-unotice-ch.pem", "Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextControlCharacters")

	def test_examine_x509test_xf_ext_constraints_neg_pathlen(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-neg-pathlen.pem", "Cert_X509Ext_Malformed")

	def test_examine_x509test_xf_ext_constraints_noncritical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-noncritical.pem", "Cert_X509Ext_BasicConstraints_PresentButNotCritical")

	def test_examine_x509test_xf_ext_constraints_path_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-path-nonca.pem", "Cert_X509Ext_BasicConstraints_PathLenWithoutCA")

	def test_examine_x509test_xf_ext_constraints_path_nosign(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-path-nosign.pem", "Cert_X509Ext_BasicConstraints_PathLenWithoutKeyCertSign")

	def test_examine_x509test_xf_ext_crl_point_critical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-crl-point-critical.pem", "Cert_X509Ext_CRLDistributionPoints_Critical")

	def test_examine_x509test_xf_ext_crl_point_reasons_only(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-crl-point-reasons-only.pem", "Cert_X509Ext_CRLDistributionPoints_Point_ContainsOnlyReasons")

	def test_examine_x509test_xf_ext_ct_poison(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-poison.pem", "Cert_X509Ext_CertificateTransparencyPoison_IsPrecertificate")

	def test_examine_x509test_xf_ext_ct_sct_trailing_data(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-sct-trailing-data.pem", "Cert_X509Ext_CertificateTransparencySCTs_TrailingData")

	def test_examine_x509test_xf_ext_ct_sct_wrong_type(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-sct-wrong-type.pem", "Cert_X509Ext_CertificateTransparencySCTs_ASN1Malformed")

	def test_examine_x509test_xf_ext_extended_any_key_usage(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-any-key-usage.pem", "Cert_X509Ext_ExtKeyUsage_AnyUsageCritical")

	def test_examine_x509test_xf_ext_extended_key_usage_empty_oid(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-key-usage-empty-oid.pem", "Cert_X509Ext_ExtKeyUsage_Empty")

	def test_examine_x509test_xf_ext_extended_key_usage_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-key-usage-empty.pem", "Cert_X509Ext_ExtKeyUsage_Empty")

#	def test_examine_x509test_xf_ext_freshest_crl_critical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-freshest-crl-critical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-freshest-crl-critical.pem")
#
#	def test_examine_x509test_xf_ext_inhibit_anypolicy_negative(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-inhibit-anypolicy-negative.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-inhibit-anypolicy-negative.pem")
#
#	def test_examine_x509test_xf_ext_inhibit_anypolicy_noncritical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-inhibit-anypolicy-noncritical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-inhibit-anypolicy-noncritical.pem")

	def test_examine_x509test_xf_ext_issuer_altname_critical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-issuer-altname-critical.pem", "Cert_X509Ext_IssuerAltName_Critical")

	def test_examine_x509test_xf_ext_key_usage_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-empty.pem", "Cert_X509Ext_KeyUsage_Empty")

	def test_examine_x509test_xf_ext_key_usage_noncritical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-noncritical.pem", "Cert_X509Ext_KeyUsage_NonCritical")

	def test_examine_x509test_xf_ext_key_usage_sign_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-sign-nonca.pem", "Cert_X509Ext_KeyUsage_SignCertNoBasicConstraints")

	def test_examine_x509test_xf_ext_key_usage_too_long(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-too-long.pem", "Cert_X509Ext_KeyUsage_TooLong")

#	def test_examine_x509test_xf_ext_key_usage_wrong_der(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-wrong-der.pem", "Cert_X509Ext_KeyUsage_InvalidDER")

	def test_examine_x509test_xf_ext_keysign_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-keysign-nonca.pem", "Cert_X509Ext_KeyUsage_SignCertNoCA")

#	def test_examine_x509test_xf_ext_name_constraints_badip(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-badip.pem", "Cert_X509Ext_NameConstraints_BadIP")

#	def test_examine_x509test_xf_ext_name_constraints_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-empty.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-name-constraints-empty.pem")
#
#	def test_examine_x509test_xf_ext_name_constraints_minmax(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-minmax.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-name-constraints-minmax.pem")

	def test_examine_x509test_xf_ext_name_constraints_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-nonca.pem", "Cert_X509Ext_NameConstraints_PresentButNotCA")

	def test_examine_x509test_xf_ext_name_constraints_noncrit(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-noncrit.pem", "Cert_X509Ext_NameConstraints_PresentButNotCritical")

#	def test_examine_x509test_xf_ext_name_constraints_regid(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-regid.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-name-constraints-regid.pem")
#
#	def test_examine_x509test_xf_ext_policy_constraint_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-policy-constraint-empty.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-policy-constraint-empty.pem")
#
#	def test_examine_x509test_xf_ext_policy_constraint_noncrit(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-policy-constraint-noncrit.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-policy-constraint-noncrit.pem")
#
#	def test_examine_x509test_xf_ext_policy_map_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-policy-map-empty.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-policy-map-empty.pem")
#
#	def test_examine_x509test_xf_ext_policy_map_from_any(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-policy-map-from-any.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-policy-map-from-any.pem")
#
#	def test_examine_x509test_xf_ext_policy_map_noncritical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-policy-map-noncritical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-policy-map-noncritical.pem")
#
#	def test_examine_x509test_xf_ext_policy_map_to_any(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-policy-map-to-any.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-policy-map-to-any.pem")
#
#	def test_examine_x509test_xf_ext_policy_map_unref(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-policy-map-unref.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-policy-map-unref.pem")
#
#	def test_examine_x509test_xf_ext_subject_dirattr_critical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-subject-dirattr-critical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-subject-dirattr-critical.pem")
#
#	def test_examine_x509test_xf_ext_subject_dirattr_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-subject-dirattr-empty.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-subject-dirattr-empty.pem")
#
#	def test_examine_x509test_xf_ext_subject_info_critical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-subject-info-critical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-subject-info-critical.pem")
#
#	def test_examine_x509test_xf_ext_subject_info_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-subject-info-empty.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-subject-info-empty.pem")
#
#	def test_examine_x509test_xf_ext_subject_keyid_ca_absent(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-subject-keyid-ca-absent.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-subject-keyid-ca-absent.pem")
#
#	def test_examine_x509test_xf_ext_subject_keyid_critical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-subject-keyid-critical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-subject-keyid-critical.pem")
#
	def test_examine_x509test_xf_gentime_fraction_secs(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-gentime-fraction-secs.pem", "Cert_Validity_Invalid_NotAfter_Encoding")

	def test_examine_x509test_xf_gentime_no_secs(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-gentime-no-secs.pem", "Cert_Validity_Invalid_NotAfter_Encoding")

	def test_examine_x509test_xf_gentime_nonzulu(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-gentime-nonzulu.pem", "Cert_Validity_Invalid_NotAfter_Encoding")

	def test_examine_x509test_xf_issuer_mismatch_v2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-issuer-mismatch-v2.pem", "CA_Relationship_SubjectIssuerMismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_examine_x509test_xf_issuer_mismatch1(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-issuer-mismatch1.pem", "CA_Relationship_SubjectIssuerMismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_examine_x509test_xf_pubkey_ecdsa_not_on_curve(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-not-on-curve.pem", "ECC_Pubkey_Not_On_Curve")

#	def test_examine_x509test_xf_pubkey_ecdsa_secp192r1(self):
#		We omit this x509test check; it refers to RFC5480 Sect. 2.1.1.1 with
#		the comment that the 192 bit finite field is too short. However,
#		RFC5480 does not make any recommendation regarding security of curves
#		and, on the contrary, includes secp192r1 as NIST-recommended curve.
#		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-secp192r1.pem", "")

	def test_examine_x509test_xf_pubkey_ecdsa_unknown_curve(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-unknown-curve.pem", "ECC_UnknownNamedCurve")

	def test_examine_x509test_xf_pubkey_rsa_exponent_negative(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-rsa-exponent-negative.pem", "RSA_Exponent_Is_Zero_Or_Negative")

	def test_examine_x509test_xf_pubkey_rsa_modulus_negative(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-rsa-modulus-negative.pem", "RSA_Modulus_Negative")

	def test_examine_x509test_xf_pubkey_rsa_param_nonnull(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-rsa-param-nonnull.pem", "RSA_Parameter_Field_Not_Null")

	def test_examine_x509test_xf_serial_negative(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-serial-negative.pem", "Cert_Serial_Negative")

	def test_examine_x509test_xf_serial_zero(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-serial-zero.pem", "Cert_Serial_Zero")

	def test_examine_x509test_xf_soon_generalized_time(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-soon-generalized-time.pem", "Cert_Validity_GeneralizedTimeBeforeYear2050")

	def test_examine_x509test_xf_subject_nonprintable(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-subject-nonprintable.pem", "DN_Contains_Illegal_Char")

	def test_examine_x509test_xf_subject_t61(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-subject-t61.pem", "DN_Contains_Deprecated_Type")

	def test_examine_x509test_xf_unknown_critical_ext(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-unknown-critical-ext.pem", "Cert_X509Ext_Unknown_Critical")

	def test_examine_x509test_xf_utctime_no_secs(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-utctime-no-secs.pem", "Cert_Validity_Invalid_NotBefore_Encoding")

	def test_examine_x509test_xf_utctime_nonzulu(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-utctime-nonzulu.pem", "Cert_Validity_Invalid_NotBefore_Encoding")

	def test_examine_x509test_xf_v1_extensions(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v1-extensions.pem", "Cert_X509Ext_NotAllowed")

	def test_examine_x509test_xf_v1_uniqueid(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v1-uniqueid.pem", "Cert_UniqueID_NotAllowed")

	def test_examine_x509test_xf_v2_extensions(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v2-extensions.pem", "Cert_X509Ext_NotAllowed")

	def test_examine_x509test_xf_v3_uniqueid_noexts1(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v3-uniqueid-noexts1.pem", [ "Cert_Version_Not_2", "Cert_UniqueID_NotAllowedForCA" ])

	def test_examine_x509test_xf_v3_uniqueid_noexts2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v3-uniqueid-noexts2.pem", "Cert_Version_Not_2")

################################################################################################################################################################

	def test_constructed_long_serial(self):
		self._test_examine_x509test_resultcode("certs/constructed/long_serial.pem", "Cert_Serial_Large")

	def test_constructed_pubkey_ecc_G(self):
		self._test_examine_x509test_resultcode("certs/constructed/pubkey_ecc_G.pem", "ECC_Pubkey_Is_G")

	def test_constructed_pubkey_ecc_curveorder(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_secp256r1.pem", expect_present = "ECC_Pubkey_CurveOrder")
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283k1.pem", expect_present = "ECC_Pubkey_CurveOrder")
		self._test_examine_x509test_resultcode("certs/ok/rsa_512.pem", expect_absent = "ECC_Pubkey_CurveOrder")

	def test_constructed_pubkey_ecc_fp_non_koblitz(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_secp256r1.pem", expect_absent = "ECC_PrimeFieldKoblitz")

	def test_constructed_pubkey_ecc_fp_koblitz(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_secp256k1.pem", "ECC_PrimeFieldKoblitz")

	def test_constructed_pubkey_ecc_f2m_non_koblitz(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283r1.pem", "ECC_BinaryField", expect_absent = "ECC_BinaryFieldKoblitz")

	def test_constructed_pubkey_ecc_f2m_koblitz(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283k1.pem", [ "ECC_BinaryField", "ECC_BinaryFieldKoblitz" ])

	def test_constructed_ecdsa_sig_r_bitbias(self):
		# Need the CA for this test, since the signature can only be checked
		# when the curve is known, which is encoded in the CA's public key.
		self._test_examine_x509test_resultcode("certs/constructed/ecdsa_sig_r_bitbias.pem", "ECDSA_Signature_R_BitBias", parent_certname = "certs/ok/johannes-bauer.com.pem")

	def test_constructed_ecdsa_sig_s_bitbias(self):
		# Need the CA for this test, since the signature can only be checked
		# when the curve is known, which is encoded in the CA's public key.
		self._test_examine_x509test_resultcode("certs/constructed/ecdsa_sig_s_bitbias.pem", "ECDSA_Signature_S_BitBias", parent_certname = "certs/ok/johannes-bauer.com.pem")

	def test_constructed_ecdsa_sig_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecdsa_sig_malformed.pem", "ECDSA_Signature_Malformed", parent_certname = "certs/constructed/ecdsa_sig_malformed.pem")

	def test_constructed_pubkey_bitbias_x_low_hweight(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_pubkey_x_bitbias1.pem", "ECC_Pubkey_X_BitBias", expect_absent = "ECC_Pubkey_Y_BitBias")

	def test_constructed_pubkey_bitbias_x_high_hweight(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_pubkey_x_bitbias2.pem", "ECC_Pubkey_X_BitBias", expect_absent = "ECC_Pubkey_Y_BitBias")

	def test_constructed_pubkey_bitbias_y(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_pubkey_y_bitbias.pem", "ECC_Pubkey_Y_BitBias", expect_absent = "ECC_Pubkey_X_BitBias")

	def test_hostname_ok(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "Cert_SAN_Match", expect_absent = "Cert_SAN_NoMatch", host_check = "mail.johannes-bauer.com")
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "Cert_SAN_Match", expect_absent = "Cert_SAN_NoMatch", host_check = "www.johannes-bauer.com")
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "Cert_SAN_Match", expect_absent = "Cert_SAN_NoMatch", host_check = "johannes-bauer.com")

	def test_hostname_not_ok(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "Cert_SAN_NoMatch", expect_absent = "Cert_SAN_Match", host_check = "wwwQjohannes-bauer.com")

	def test_constructed_rsa_bitbias(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_bitbias.pem", "RSA_Modulus_BitBias")

	def test_constructed_rsa_modulus_prime(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_modulus_prime.pem", "RSA_Modulus_Prime", fast_rsa = False)

	def test_constructed_rsa_modulus_smallfactor(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_modulus_smallfactor.pem", "RSA_Modulus_Factorable", fast_rsa = False)

	def test_constructed_rsa_modulus_compromised(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_modulus_compromised.pem", "RSA_Modulus_FactorizationKnown")

	def test_constructed_rsa_exponent0(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent0.pem", "RSA_Exponent_Is_Zero_Or_Negative")

	def test_constructed_rsa_exponent1(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent1.pem", "RSA_Exponent_Is_0x1")

	def test_constructed_rsa_exponent3(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent3.pem", "RSA_Exponent_Small")

	def test_constructed_rsa_exponent101(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent101.pem", "RSA_Exponent_SmallUnusual")

	def test_constructed_rsa_exponent65537(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent65537.pem", "RSA_Exponent_Is_0x10001")

	def test_constructed_rsa_exponent_long(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent_long.pem", "RSA_Exponent_Large")

	def test_constructed_rsa_parameter_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_parameter_missing.pem", "RSA_Parameter_Field_Not_Present")

	def test_include_raw_data_rsa(self):
		self._test_examine_x509test_resultcode("certs/ok/rsa_512.pem", expect_present = [ "SignatureFunction_Common", "HashFunction_Derated", "RSA_Modulus_Length", "HashFunction_Length" ], include_raw = True)

	def test_include_raw_data_ecc_fp(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_secp256r1.pem", expect_present = "SignatureFunction_Common", include_raw = True)

	def test_include_raw_data_ecc_f2m(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283r1.pem", include_raw = True)

	def test_include_raw_data_ecc_twedwards(self):
		self._test_examine_x509test_resultcode("certs/ok/pubkey_sig_ed25519.pem", expect_present = "SignatureFunction_UncommonCryptosystem", include_raw = True)

	def test_explicit_prime(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_explicit_param_prime.pem", expect_present = [ "ECC_UnusedCurveName", "ECC_ExplicitCurveEncoding" ], expect_absent = "ECC_UnknownExplicitCurve")

	def test_explicit_twofield_ppbasis(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_explicit_param_twofield_ppbasis.pem", "ECC_ExplicitCurveEncoding", expect_absent = [ "ECC_InvalidPolynomialPower", "ECC_DuplicatePolynomialPower", "ECC_UnknownExplicitCurve" ])

	def test_explicit_twofield_tpbasis(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_explicit_param_twofield_tpbasis.pem", "ECC_ExplicitCurveEncoding", expect_absent = [ "ECC_InvalidPolynomialPower", "ECC_DuplicatePolynomialPower", "ECC_UnknownExplicitCurve" ])

	def test_explicit_twofield_poly_invalid_power1(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_explicit_param_twofield_invalid_power1.pem", "ECC_InvalidPolynomialPower")

	def test_explicit_twofield_poly_invalid_power2(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_explicit_param_twofield_invalid_power2.pem", "ECC_InvalidPolynomialPower")

	def test_explicit_twofield_poly_duplicate_power(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_explicit_param_twofield_duplicate_power.pem", "ECC_DuplicatePolynomialPower")

	def test_explicit_unknown(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_explicit_param_prime_custom_domain.pem", expect_present = [ "ECC_ExplicitCurveEncoding", "ECC_UnknownExplicitCurve" ], expect_absent = "ECC_UnusedCurveName")

	def test_san_broad_match1(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_broad_match1.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadWildcardDomain_BroadMatch")

	def test_san_broad_match2(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_broad_match2.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadWildcardDomain_BroadMatch")

	def test_san_bad_email(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_email.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadEmail")

	def test_san_bad_ip(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_ip.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadIP")

	def test_san_bad_ip_private(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_ip_private.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadIP_Private")

	def test_san_wildcard_not_leftmost(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_wildcard_not_leftmost.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadWildcardDomain_NotLeftmost")

	def test_san_wildcard_more_than_one(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_wildcard_more_than_one.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadWildcardDomain_MoreThanOneWildcard")

	def test_san_international_label_ok(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_international_label_ok.pem", expect_absent = "Cert_X509Ext_SubjectAltName_BadWildcardDomain_InternationalLabel")

	def test_san_international_label_wrong(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_international_label_wrong.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadWildcardDomain_InternationalLabel")

	def test_san_bad_domain(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_domain.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadDNSName")

	def test_san_bad_domain_space(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_domain_space.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadDNSName_Space")

	def test_san_bad_domain_single_label(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_domain_single_label.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadDNSName_SingleLabel")

	def test_san_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_missing.pem", expect_present = "Cert_X509Ext_SubjectAltName_Missing")

	def test_san_missing_nosubject(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_missing_nosubject.pem", expect_present = "Cert_X509Ext_SubjectAltName_Missing")

	def test_san_bad_uri(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_uri.pem", expect_present = "Cert_X509Ext_SubjectAltName_BadURI")

	def test_san_bad_uri_uncommon_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_uri_uncommon_scheme.pem", expect_present = "Cert_X509Ext_SubjectAltName_UncommonURIScheme")

	def test_san_uncommon_identifier(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_good_uri.pem", expect_present = "Cert_X509Ext_SubjectAltName_UncommonIdentifier")

	def test_dn_all_ok(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_all_okay.pem", expect_absent = [ "DN_Contains_Long_RDN" ])

	def test_dn_long_rdn_cn64(self):
		# Still barely okay, 64 characters is limit for CN
		self._test_examine_x509test_resultcode("certs/constructed/dn_long_rdn_cn64.pem", expect_absent = "DN_Contains_Long_RDN")

	def test_dn_long_rdn_cn65(self):
		# Straw that breaks the camel's back
		self._test_examine_x509test_resultcode("certs/constructed/dn_long_rdn_cn65.pem", expect_present = "DN_Contains_Long_RDN")

	def test_dn_long_rdn_c(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_long_rdn_c.pem", expect_present = "DN_Contains_Long_RDN")

	def test_dn_multivalue(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_multivalue.pem", expect_present = "DN_Contains_MultiValues")

	def test_dn_nonprintable(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_nonprintable.pem", expect_present = "DN_Contains_NonPrintable")

	def test_dn_duplicate_rdns(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_multiple_identical_rdns.pem", expect_present = "DN_Contains_DuplicateRDNs")

	def test_dn_many_rdns(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_many_rdns.pem", expect_present = "DN_Contains_Unusually_Many_RDNs")

	def test_dn_no_cn(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_no_cn.pem", expect_present = "DN_Contains_No_CN")

	def test_dn_multiple_cns(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_multiple_cn.pem", expect_present = "DN_Contains_Multiple_CN")

	def test_dn_duplicate_set(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_duplicate_set.pem", expect_present = [ "DN_Contains_Duplicate_Set", "DN_Contains_Duplicate_OID_In_Multivalued_RDN" ])

	def test_dn_duplicate_oid_in_mvrdn(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_duplicate_oid_in_mvrdn.pem", expect_present = "DN_Contains_Duplicate_OID_In_Multivalued_RDN", expect_absent = "DN_Contains_Duplicate_Set")

	def test_cn_match_fqdn_but_multivalue_rdn(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_cn_hostname_multivalue_rdn.pem", expect_present = "Cert_CN_Match_MultiValue_RDN", expect_absent = "DN_Contains_No_CN", host_check = "multivalue.com")

	def test_cn_match_fqdn(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", expect_present = "Cert_CN_Match", expect_absent = "Cert_X509Ext_SubjectAltName_Missing", host_check = "johannes-bauer.com")

	def test_cn_no_match_fqdn(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", expect_present = [ "Cert_CN_NoMatch", "Cert_Name_Verification_Failed" ], host_check = "pupannes-bauer.com")

	def test_check_no_ca_when_expecting_ca(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", expect_present = "Cert_Unexpectedly_No_CA_Cert", purpose = "ca")

	def test_check_ca_when_expecting_no_ca(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer-intermediate.pem", expect_present = "Cert_Unexpectedly_CA_Cert", purpose = "tls-server")

	def test_check_version(self):
		self._test_examine_x509test_resultcode("certs/constructed/version1.pem", expect_present = "Cert_Version_Not_3")

	def test_check_algorithm_alternate_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/algorithm_alternate_oid.pem", expect_present = "SignatureFunction_NonPreferred_OID")

	def test_validity_never_valid(self):
		self._test_examine_x509test_resultcode("certs/constructed/validity_never_valid.pem", expect_present = "Cert_Validity_NeverValid")

	def test_validity_expired(self):
		self._test_examine_x509test_resultcode("certs/constructed/validity_expired.pem", expect_present = "Cert_Validity_Expired")

	def test_validity_valid(self):
		self._test_examine_x509test_resultcode("certs/constructed/validity_valid.pem", expect_present = "Cert_Validity_Valid")

	def test_not_yet_validity_not_yet_valid(self):
		self._test_examine_x509test_resultcode("certs/constructed/validity_not_yet_valid.pem", expect_present = "Cert_Validity_NotYetValid")

	def test_unknown_sigfnc(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_sigfnc.pem", expect_present = "Cert_Unknown_SignatureAlgorithm")

	def test_rsa_pss_ok(self):
		self._test_examine_x509test_resultcode("certs/ok/rsapss_defaults.pem", expect_present = "SignatureFunction_UncommonPaddingScheme")

	def test_rsa_pss_unknown_hashfnc1(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_hashfnc1.pem", expect_present = "Cert_Unknown_HashAlgorithm")

	def test_rsa_pss_unknown_hashfnc2(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_hashfnc2.pem", expect_present = "Cert_Unknown_HashAlgorithm")

	def test_rsa_pss_unknown_maskfnc(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_maskfnc.pem", expect_present = "Cert_Unknown_MaskAlgorithm")

	def test_rsa_pss_malformed1(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_malformed1.pem", expect_present = "RSA_PSS_Invalid_Salt_Length")

	def test_rsa_pss_malformed2(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_malformed2.pem", expect_present = "RSA_PSS_Unknown_Trailer_Field")

	def test_rsa_pss_malformed3(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_malformed3.pem", expect_present = "RSA_PSS_Unknown_Trailer_Field")

	def test_rsa_pss_malformed4(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_malformed4.pem", expect_present = "RSA_PSS_Parameters_Malformed")

	def test_rsa_pss_salt0(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_salt0.pem", expect_present = "RSA_PSS_No_Salt_Used")

	def test_rsa_pss_salt3(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_salt3.pem", expect_present = "RSA_PSS_Short_Salt_Used")

	def test_rsa_pss_salt16(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_salt16.pem", expect_present = "RSA_PSS_Salt_Length")

	def test_rsa_pss_multiple_hashes(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_multiple_hashes.pem", expect_present = "RSA_PSS_Multiple_Hash_Functions")

	def test_rsa_pss_mismatch_algo1(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo1.pem", expect_present = "Cert_Signature_Algorithm_Mismatch")

	def test_rsa_pss_mismatch_algo2(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo2.pem", expect_present = "Cert_Signature_Algorithm_Mismatch")

	def test_rsa_pss_mismatch_algo3(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo3.pem", expect_present = "Cert_Signature_Algorithm_Mismatch")

	def test_rsa_pss_mismatch_algo4(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo4.pem", expect_present = "Cert_Signature_Algorithm_Mismatch")

	def test_rsa_pss_mismatch_algo5(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo5.pem", expect_present = "Cert_Signature_Algorithm_Mismatch")

	def test_mismatch_header_footer_sigparams(self):
		self._test_examine_x509test_resultcode("certs/constructed/mismatch_header_footer_sigparams.pem", expect_present = "Cert_Signature_Algorithm_Mismatch")

	def test_dsa_p_not_prime(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_p_not_prime.pem", expect_present = "DSA_Parameter_P_Not_Prime")

	def test_dsa_q_not_prime(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_q_not_prime.pem", expect_present = "DSA_Parameter_Q_Not_Prime")

	def test_dsa_p_bitbias(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_p_bitbias.pem", expect_present = "DSA_Parameter_P_BitBias", expect_absent = "DSA_Parameter_Q_BitBias")

	def test_dsa_q_bitbias(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_q_bitbias.pem", expect_present = "DSA_Parameter_Q_BitBias", expect_absent = "DSA_Parameter_P_BitBias")

	def test_dsa_r_bitbias(self):
		# Need the CA for this test, since the signature can only be checked
		# when the curve is known, which is encoded in the CA's public key.
		self._test_examine_x509test_resultcode("certs/constructed/dsa_r_bitbias.pem", expect_present = "DSA_Signature_R_BitBias", parent_certname = "certs/constructed/dsa_base.pem")

	def test_dsa_s_bitbias(self):
		# Need the CA for this test, since the signature can only be checked
		# when the curve is known, which is encoded in the CA's public key.
		self._test_examine_x509test_resultcode("certs/constructed/dsa_s_bitbias.pem", expect_present = "DSA_Signature_S_BitBias", parent_certname = "certs/constructed/dsa_base.pem")

	def test_dsa_q_does_not_divide_p1(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_q_does_not_divide_p1.pem", expect_present = "DSA_Parameter_Q_No_Divisor_Of_P1")

	def test_dsa_sig_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_sig_malformed.pem", expect_present = "DSA_Signature_Malformed")

	def test_dsa_typical_parameters(self):
		self._test_examine_x509test_resultcode("certs/ok/dsa_sha1.pem", expect_present = [ "DSA_Parameter_L_N_Common", "DSA_Security_Level" ], expect_absent = "DSA_Parameter_L_N_Uncommon", include_raw = True)

	def test_dsa_atypical_parameters(self):
		self._test_examine_x509test_resultcode("certs/ok/dsa_512_160_sha256.pem", expect_present = "DSA_Parameter_L_N_Uncommon", expect_absent = "DSA_Parameter_L_N_Common")

	def test_dsa_g_invalid_range(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid.pem", expect_present = "DSA_Parameter_G_Invalid")

	def test_dsa_g_invalid_range1(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid_range1.pem", expect_present = "DSA_Parameter_G_Invalid_Range")

	def test_dsa_g_invalid_range2(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid_range2.pem", expect_present = "DSA_Parameter_G_Invalid_Range")

	def test_dsa_g_invalid_range3(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid_range3.pem", expect_present = "DSA_Parameter_G_Invalid_Range")

	def test_dsa_g_invalid_range4(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid_range4.pem", expect_present = "DSA_Parameter_G_Invalid_Range")

	def test_ski_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/ski_missing.pem", expect_present = "Cert_X509Ext_SubjectKeyIdentifier_Missing")

	def test_ski_arbitrary(self):
		self._test_examine_x509test_resultcode("certs/constructed/ski_arbitrary.pem", expect_present = "Cert_X509Ext_SubjectKeyIdentifier_Arbitrary")

	def test_ski_sha1(self):
		self._test_examine_x509test_resultcode("certs/constructed/ski_sha1.pem", expect_present = "Cert_X509Ext_SubjectKeyIdentifier_SHA1")

	def test_ski_sha256(self):
		self._test_examine_x509test_resultcode("certs/constructed/ski_sha256.pem", expect_present = "Cert_X509Ext_SubjectKeyIdentifier_OtherHash")

	def test_aki_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_missing.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_Missing")

	def test_aki_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_malformed.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_Malformed")

	def test_aki_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_empty.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_Empty")

	def test_aki_keyid_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_keyid_empty.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_KeyIDEmpty")

	def test_aki_keyid_long(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_keyid_long.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_KeyIDLong")

	def test_aki_name_without_serial(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_name_without_serial.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_NameWithoutSerial")

	def test_aki_ca_has_no_ski(self):
		self._test_examine_x509test_resultcode("certs/ok/short.pem", parent_certname = "certs/constructed/ski_missing.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CA_NoSKI")

	def test_aki_caname_bad_domain(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_domain.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadDNSName")

	def test_aki_caname_bad_email(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_email.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadEmail")

	def test_aki_caname_bad_uri(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_uri.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadURI")

	def test_aki_caname_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_empty.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_Empty")

	def test_aki_caname_emptyvalue(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_emptyvalue.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_EmptyValue")

	def test_aki_caname_bad_ip_private(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_ip_private.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadIP_Private")

	def test_aki_caname_bad_domain_space(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_domain_space.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadDNSName_Space")

	def test_aki_caname_bad_domain_single_label(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_domain_single_label.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadDNSName_SingleLabel")

	def test_aki_caname_uncommon_identifier(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_good_ip.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_UncommonIdentifier")

	def test_aki_caname_uncommon_uri_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_uncommon_uri_scheme.pem", expect_present = "Cert_X509Ext_AuthorityKeyIdentifier_CAName_UncommonURIScheme")

	def test_ext_unknown_noncritical(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_ext_noncritical.pem", expect_present = "Cert_X509Ext_Unknown_NonCritical")

	def test_basic_constraints_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/bc_missing.pem", expect_present = "Cert_X509Ext_BasicConstraints_Missing")

	def test_basic_constraints_present_critical(self):
		self._test_examine_x509test_resultcode("certs/constructed/bc_present_critical.pem", expect_present = "Cert_X509Ext_BasicConstraints_PresentAndCritical")

	def test_basic_constraints_present_noncritical(self):
		self._test_examine_x509test_resultcode("certs/constructed/bc_present_noncritical.pem", expect_present = "Cert_X509Ext_BasicConstraints_PresentButNotCritical")

	def test_issuer_altname_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_missing.pem", expect_present = "Cert_X509Ext_IssuerAltName_Missing")

	def test_issuer_altname_not_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_not_missing.pem", expect_absent = "Cert_X509Ext_IssuerAltName_Missing")

	def test_issuer_altname_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_empty.pem", expect_present = "Cert_X509Ext_IssuerAltName_Empty")

	def test_issuer_altname_emptyvalue(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_emptyvalue.pem", expect_present = "Cert_X509Ext_IssuerAltName_EmptyValue")

	def test_issuer_altname_bad_domain(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_domain.pem", expect_present = "Cert_X509Ext_IssuerAltName_BadDNSName")

	def test_issuer_altname_bad_domain_space(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_domain_space.pem", expect_present = "Cert_X509Ext_IssuerAltName_BadDNSName_Space")

	def test_issuer_altname_bad_domain_single_label(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_domain_single_label.pem", expect_present = "Cert_X509Ext_IssuerAltName_BadDNSName_SingleLabel")

	def test_issuer_altname_bad_uri(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_uri.pem", expect_present = "Cert_X509Ext_IssuerAltName_BadURI")

	def test_issuer_altname_uncommon_uri_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_uncommon_uri_scheme.pem", expect_present = "Cert_X509Ext_IssuerAltName_UncommonURIScheme")

	def test_issuer_altname_bad_ip(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_ip.pem", expect_present = "Cert_X509Ext_IssuerAltName_BadIP")

	def test_issuer_altname_bad_ip_private(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_ip_private.pem", expect_present = "Cert_X509Ext_IssuerAltName_BadIP_Private")

	def test_issuer_altname_uncommon_identifier(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_good_ip.pem", expect_present = "Cert_X509Ext_IssuerAltName_UncommonIdentifier")

	def test_issuer_altname_bad_email(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_email.pem", expect_present = "Cert_X509Ext_IssuerAltName_BadEmail")

	def test_extension_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ext_malformed.pem", expect_present = "Cert_X509Ext_Malformed")

	def test_certificate_lifetime_noca_conservative(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_noca_conservative.pem", expect_present = "Cert_Validity_Length_Conservative")

	def test_certificate_lifetime_noca_long(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_noca_long.pem", expect_present = "Cert_Validity_Length_Long")

	def test_certificate_lifetime_noca_verylong(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_noca_verylong.pem", expect_present = "Cert_Validity_Length_VeryLong")

	def test_certificate_lifetime_noca_exceptionallylong(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_noca_exceptionallylong.pem", expect_present = "Cert_Validity_Length_ExceptionallyLong")

	def test_certificate_lifetime_ca_conservative(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_ca_conservative.pem", expect_present = "Cert_Validity_Length_Conservative")

	def test_certificate_lifetime_ca_long(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_ca_long.pem", expect_present = "Cert_Validity_Length_Long")

	def test_certificate_lifetime_ca_verylong(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_ca_verylong.pem", expect_present = "Cert_Validity_Length_VeryLong")

	def test_certificate_lifetime_ca_exceptionallylong(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_ca_exceptionallylong.pem", expect_present = "Cert_Validity_Length_ExceptionallyLong")

	def test_key_usage_excessive(self):
		self._test_examine_x509test_resultcode("certs/constructed/ku-xmas.pem", expect_present = [ "Cert_Purpose_KU_ExcessKeyUsage", "Cert_Purpose_KU_UnusualKeyUsage" ], purpose = "tls-server")

	def test_key_usage_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/ku-missing.pem", expect_present = "Cert_Purpose_KU_MissingKeyUsage", purpose = "ca")

	def test_key_usage_trailingzero(self):
		self._test_examine_x509test_resultcode("certs/constructed/ku-trailingzero.pem", expect_present = "Cert_X509Ext_KeyUsage_TrailingZeros")

	def test_key_usage_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ku-malformed.pem", expect_present = "Cert_X509Ext_KeyUsage_Malformed")

	def test_key_usage_extension_missing(self):
		self._test_examine_x509test_resultcode("certs/ok/short.pem", expect_present = "Cert_X509Ext_KeyUsage_Missing")

	def test_key_usage_noncritical_ca(self):
		# Different code path when the certificate is a CA certificate, include
		# test for coverage of both paths.
		self._test_examine_x509test_resultcode("certs/constructed/ku_noncritical_ca.pem", expect_present = "Cert_X509Ext_KeyUsage_NonCritical", purpose = "ca")

	def test_certpol_polcount_1(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_polcount_1.pem", expect_absent = "Cert_X509Ext_CertificatePolicies_MoreThanOnePolicy")

	def test_certpol_polcount_2(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_polcount_2.pem", expect_present = "Cert_X509Ext_CertificatePolicies_MoreThanOnePolicy")

	def test_certpol_deprecated_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_deprecated_oid.pem", expect_present = "Cert_X509Ext_CertificatePolicies_DeprecatedOID")

	def test_certpol_duplicate_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_duplicate_oid.pem", expect_present = "Cert_X509Ext_CertificatePolicies_DuplicateOID")

	def test_certpol_duplicate_qualifier_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_duplicate_qualifier_oid.pem", expect_present = "Cert_X509Ext_CertificatePolicies_DuplicateQualifierOID")

	def test_certpol_cps_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_cps_malformed.pem", expect_present = "Cert_X509Ext_CertificatePolicies_CPSMalformed")

	def test_certpol_cps_constraint_violation(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_cps_constraint_violation.pem", expect_present = "Cert_X509Ext_CertificatePolicies_CPSConstraintViolation")

	def test_certpol_cps_unusual_uri_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_cps_unusual_uri_scheme.pem", expect_present = "Cert_X509Ext_CertificatePolicies_CPSUnusualURIScheme")

	def test_certpol_unotice_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_empty.pem", expect_present = "Cert_X509Ext_CertificatePolicies_UserNoticeEmpty")

	def test_certpol_unotice_withexplicittext(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_withexplicittext.pem", expect_present = "Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextIA5String")

	def test_certpol_unotice_withexplicittextutf8(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_withexplicittext_utf8.pem", expect_absent = "Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextIA5String")

	def test_certpol_unotice_noexplicittext(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_noexplicittext.pem", expect_present = "Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextAbsent")

	def test_certpol_unotice_longexplicittext(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_longexplicittext.pem", expect_present = "Cert_X509Ext_CertificatePolicies_UserNoticeConstraintViolation")

	def test_certpol_unotice_withnoticeref(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_withnoticeref.pem", expect_present = "Cert_X509Ext_CertificatePolicies_UserNoticeRefPresent")

	def test_certpol_unotice_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_malformed.pem", expect_present = "Cert_X509Ext_CertificatePolicies_UserNoticeMalformed")

	def test_certpol_unknown_qualifier_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unknown_qualifier_oid.pem", expect_present = "Cert_X509Ext_CertificatePolicies_UnknownQualifierOID")

	def test_duplicate_extension_present(self):
		self._test_examine_x509test_resultcode("certs/constructed/duplicate_extension.pem", expect_absent = "Cert_X509Ext_All_Unique")

	def test_no_duplicate_extension_present(self):
		self._test_examine_x509test_resultcode("certs/ok/short.pem", expect_present = "Cert_X509Ext_All_Unique")

	def test_eku_no_client(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_server.pem", expect_present = "Cert_Purpose_EKU_NoClientAuth", purpose = "tls-client")

	def test_eku_is_client(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_client.pem", expect_absent = "Cert_Purpose_EKU_NoClientAuth", purpose = "tls-client")

	def test_eku_no_server(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_client.pem", expect_present = "Cert_Purpose_EKU_NoServerAuth", purpose = "tls-server")

	def test_eku_is_server(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_server.pem", expect_absent = "Cert_Purpose_EKU_NoServerAuth", purpose = "tls-server")

	def test_eku_duplicate(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_duplicate.pem", expect_present = "Cert_X509Ext_ExtKeyUsage_Duplicate")

	def test_nsct_no_client(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_server.pem", expect_present = "Cert_Purpose_NSCT_NoSSLClient", purpose = "tls-client")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_ssl_ca.pem", expect_present = "Cert_Purpose_NSCT_NoSSLClient", purpose = "tls-client")

	def test_nsct_is_client(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_client.pem", expect_absent = "Cert_Purpose_NSCT_NoSSLClient", purpose = "tls-client")

	def test_nsct_no_server(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_client.pem", expect_present = "Cert_Purpose_NSCT_NoSSLServer", purpose = "tls-server")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_ssl_ca.pem", expect_present = "Cert_Purpose_NSCT_NoSSLServer", purpose = "tls-server")

	def test_nsct_is_server(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_server.pem", expect_absent = "Cert_Purpose_NSCT_NoSSLServer", purpose = "tls-server")

	def test_nsct_no_ca(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_client.pem", expect_present = "Cert_Purpose_NSCT_NoCA", purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_server.pem", expect_present = "Cert_Purpose_NSCT_NoCA", purpose = "ca")

	def test_nsct_is_ca(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_ssl_ca.pem", expect_absent = "Cert_Purpose_NSCT_NoCA", purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_smime_ca.pem", expect_absent = "Cert_Purpose_NSCT_NoCA", purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_objsign_ca.pem", expect_absent = "Cert_Purpose_NSCT_NoCA", purpose = "ca")

	def test_nsct_ssl_ca(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_ssl_ca.pem", expect_absent = [ "Cert_Purpose_NSCT_NonSSLCA", "Cert_Purpose_NSCT_NoCA"], purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_smime_ca.pem", expect_present = "Cert_Purpose_NSCT_NonSSLCA", expect_absent = "Cert_Purpose_NSCT_NoCA", purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_objsign_ca.pem", expect_present = "Cert_Purpose_NSCT_NonSSLCA", expect_absent = "Cert_Purpose_NSCT_NoCA", purpose = "ca")

	def test_nsct_unused(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_unused.pem", expect_present = "Cert_X509Ext_NetscapeCertType_UnusedBitSet")

	def test_nsct_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_malformed.pem", expect_present = "Cert_X509Ext_NetscapeCertType_Malformed")

	def test_nsct_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_empty.pem", expect_present = "Cert_X509Ext_NetscapeCertType_Empty")

	def test_ext_empty_sequence(self):
		self._test_examine_x509test_resultcode("certs/constructed/ext_empty_sequence.pem", expect_present = "Cert_X509Ext_EmptySequence")

	def test_ext_not_present(self):
		self._test_examine_x509test_resultcode("certs/constructed/ext_not_present.pem", expect_absent = "Cert_X509Ext_EmptySequence")

	def test_ca_relationship_signature_success(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer-intermediate.pem", expect_present = [ "CA_Relationship_SubjectIssuerMatch", "CA_Relationship_SignatureVerificationSuccess" ])

	def test_ca_relationship_signature_failure(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer-root.pem", expect_present = [ "CA_Relationship_SubjectIssuerMismatch", "CA_Relationship_SignatureVerificationFailure" ], expect_absent = "CA_Relationship_CACertificateInvalidAsCA")

	def test_ca_relationship_invalid_as_ca(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer.com.pem", expect_present = [ "CA_Relationship_SubjectIssuerMismatch", "CA_Relationship_SignatureVerificationFailure", "CA_Relationship_CACertificateInvalidAsCA" ])

	def test_ca_relationship_validity_full_overlap(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer-intermediate.pem", expect_present = "CA_Relationship_Validity_FullOverlap")

	def test_ca_relationship_validity_partial_overlap(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_valid_firsthalf.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CA_Relationship_Validity_PartialOverlap")
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_valid_secondhalf.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CA_Relationship_Validity_PartialOverlap")

	def test_ca_relationship_validity_no_overlap(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_valid_before.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CA_Relationship_Validity_NoOverlap")
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_valid_after.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CA_Relationship_Validity_NoOverlap")

	def test_ca_relationship_validity_malformed(self):
		self._test_examine_x509test_resultcode("certs/ok/short.pem", parent_certname = "certs/constructed/timestamp_malformed.pem", expect_present = "CA_Relationship_Validity_TimestampMalformed")
		self._test_examine_x509test_resultcode("certs/constructed/timestamp_malformed.pem", parent_certname = "certs/ok/short.pem", expect_present = "CA_Relationship_Validity_TimestampMalformed")

	def test_ca_relationship_aki_keyid_match(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer-intermediate.pem", expect_present = "CA_Relationship_AKI_KeyIDMatch", expect_absent = "CA_Relationship_AKI_KeyIDMismatch")

	def test_ca_relationship_aki_keyid_mismatch(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer.com.pem", expect_present = "CA_Relationship_AKI_KeyIDMismatch", expect_absent = "CA_Relationship_AKI_KeyIDMatch")

	def test_ca_relationship_aki_keyid_uncheckable(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/custom_key_usage.pem", expect_present = "CA_Relationship_AKI_UncheckableNoCASKI", expect_absent = [ "CA_Relationship_AKI_KeyIDMismatch", "CA_Relationship_AKI_KeyIDMatch" ])

	def test_ca_relationship_aki_caname_match(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_cert_caname_match.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CA_Relationship_AKI_CANameMatch", expect_absent = "CA_Relationship_AKI_CANameMismatch")

	def test_ca_relationship_aki_caname_mismatch(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_cert_caname_mismatch.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CA_Relationship_AKI_CANameMismatch", expect_absent = "CA_Relationship_AKI_CANameMatch")

	def test_ca_relationship_aki_serial_match(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_cert_serial_match.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CA_Relationship_AKI_SerialMatch", expect_absent = "CA_Relationship_AKI_SerialMismatch")

	def test_ca_relationship_aki_serial_mismatch(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_cert_serial_mismatch.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CA_Relationship_AKI_SerialMismatch", expect_absent = "CA_Relationship_AKI_SerialMatch")

	def test_unique_id_issuer(self):
		# Same code point as subject unique ID, but different code path; test
		# both paths for full coverage
		self._test_examine_x509test_resultcode("certs/constructed/unique_id_issuer.pem", "Cert_UniqueID_NotAllowed")

	def test_crldp_point_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_empty.pem", expect_present = [ "Cert_X509Ext_CRLDistributionPoints_Point_Empty" ], expect_absent = [ "Cert_X509Ext_CRLDistributionPoints_Point_ContainsOnlyReasons", "Cert_X509Ext_CRLDistributionPoints_Point_NoLDAPOrHTTPURIPresent" ])

	def test_crldp_point_no_http_ldap(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_no_http_ldap.pem", expect_present = "Cert_X509Ext_CRLDistributionPoints_Point_NoLDAPOrHTTPURIPresent")

	def test_crldp_reason_unused_bit_set(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_unused_bit_set.pem", expect_present = "Cert_X509Ext_CRLDistributionPoints_Reason_UnusedBitAsserted", expect_absent = "Cert_X509Ext_CRLDistributionPoints_Reason_UndefinedBitAsserted")

	def test_crldp_reason_undefined_bits_set(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_undefined_bits_set.pem", expect_present = "Cert_X509Ext_CRLDistributionPoints_Reason_UndefinedBitAsserted", expect_absent = "Cert_X509Ext_CRLDistributionPoints_Reason_UnusedBitAsserted")

	def test_crldp_reason_trailing_bits(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_trailing_bits.pem", expect_present = "Cert_X509Ext_CRLDistributionPoints_Reason_TrailingBits")

	def test_crldp_reason_only_field(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_only_field.pem", expect_present = "Cert_X509Ext_CRLDistributionPoints_Point_ContainsOnlyReasons")

	def test_crldp_reason_not_present(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_not_present.pem", expect_present = "Cert_X509Ext_CRLDistributionPoints_Reason_SegmentationUsed", expect_absent = "Cert_X509Ext_CRLDistributionPoints_NoPointWithAllReasonBits")

	def test_crldp_reason_no_point_with_all(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_no_point_with_all.pem", expect_present = [ "Cert_X509Ext_CRLDistributionPoints_NoPointWithAllReasonBits", "Cert_X509Ext_CRLDistributionPoints_Reason_SegmentationUsed" ])
