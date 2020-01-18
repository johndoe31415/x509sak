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

import json
from x509sak.Exceptions import UnexpectedFileContentException
from x509sak.tests import BaseTest, ResourceFileLoader
from x509sak.Tools import FileLockTools
from x509sak.CertificateAnalyzer import CertificateAnalyzer
from x509sak.X509Certificate import X509Certificate
from x509sak.estimate import JudgementCode

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

		# Plausibilize we're not chasing non-existing judgement codes -- don't
		# check the empty string because we often use that for debugging and
		# it's *obviously* wrong.

		if expect_present != ("", ):
			self.assertTrue(all(getattr(JudgementCode, codename, None) is not None for codename in expect_present))
		if expect_absent != ("", ):
			self.assertTrue(all(getattr(JudgementCode, codename, None) is not None for codename in expect_absent))

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
		self._test_examine_x509test_resultcode("certs/x509test/xf-algo-mismatch1.pem", "X509Cert_Signature_Function_BodyMismatch")

	def test_examine_x509test_xf_der_invalid_bitstring(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-bitstring.pem", "X509Cert_Malformed_NonDEREncoding")

	def test_examine_x509test_xf_der_invalid_nonminimal_int(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-nonminimal-int.pem", "X509Cert_Malformed_NonDEREncoding")

	def test_examine_x509test_xf_der_invalid_uniqueid(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-uniqueid.pem", expect_parse_failure = True)

	def test_examine_x509test_xf_der_pubkey_rsa_nonminimal_int(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-pubkey-rsa-nonminimal-int.pem", "X509Cert_PublicKey_Malformed_NonDEREncoding")

	def test_examine_x509test_xf_duplicate_extension(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-duplicate-extension.pem", "X509Cert_Body_X509Exts_DuplicatesPresent")

	def test_examine_x509test_xf_duplicate_extension2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-duplicate-extension2.pem", "X509Cert_Body_X509Exts_DuplicatesPresent")

	def test_examine_x509test_xf_ext_altname_blank_domain(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-blank-domain.pem", "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_OnlyWhitespace")

	def test_examine_x509test_xf_ext_altname_critical_subject(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-critical-subject.pem", "X509Cert_Body_X509Exts_Ext_SAN_Critical")

	def test_examine_x509test_xf_ext_altname_email_only(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-email-only.pem", "X509Cert_Body_X509Exts_Ext_SAN_EmailOnly")

	def test_examine_x509test_xf_ext_altname_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-empty.pem", "X509Cert_Body_X509Exts_Ext_SAN_Empty")

	def test_examine_x509test_xf_ext_altname_empty2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-empty2.pem", "X509Cert_Body_X509Exts_Ext_SAN_Name_Email_Malformed")

	def test_examine_x509test_xf_ext_altname_invalid_domain(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-domain.pem", "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_Malformed")

	def test_examine_x509test_xf_ext_altname_invalid_email(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-email.pem", "X509Cert_Body_X509Exts_Ext_SAN_Name_Email_Malformed")

	def test_examine_x509test_xf_ext_altname_invalid_encoding(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-encoding.pem", "X509Cert_Body_X509Exts_Unknown_Malformed_Undecodable")

	def test_examine_x509test_xf_ext_altname_ip_wrong(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-ip-wrong.pem", "X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_Malformed")

	def test_examine_x509test_xf_ext_altname_noncrit_nosubj(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-noncrit-nosubj.pem", "X509Cert_Body_X509Exts_Ext_SAN_NotCritical")

	def test_examine_x509test_xf_ext_altname_relative_uri(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-relative-uri.pem", "X509Cert_Body_X509Exts_Ext_SAN_Name_URI_Malformed")

	def test_examine_x509test_xf_ext_altname_schemeless_uri(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-schemeless-uri.pem", "X509Cert_Body_X509Exts_Ext_SAN_Name_URI_Malformed")

	def test_examine_x509test_xf_ext_auth_info_critical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-info-critical.pem", "X509Cert_Body_X509Exts_Ext_AIA_Critical")

	def test_examine_x509test_xf_ext_auth_info_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-info-empty.pem", "X509Cert_Body_X509Exts_Ext_AIA_Empty")

	def test_examine_x509test_xf_ext_auth_keyid_critical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-critical.pem", "X509Cert_Body_X509Exts_Ext_AKI_Critical")

	def test_examine_x509test_xf_ext_auth_keyid_invalid_issuer(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-invalid-issuer.pem", "X509Cert_Body_X509Exts_Ext_AKI_CAName_IPAddress_Malformed")

	def test_examine_x509test_xf_ext_auth_keyid_mismatch(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-mismatch.pem", "CertUsage_CARelationship_AKI_KeyID_Mismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_examine_x509test_xf_ext_auth_keyid_noid(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-noid.pem", "X509Cert_Body_X509Exts_Ext_AKI_NoKeyID")

	def test_examine_x509test_xf_ext_auth_keyid_onlyserial(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-onlyserial.pem", "X509Cert_Body_X509Exts_Ext_AKI_SerialWithoutCAName")

	def test_examine_x509test_xf_ext_auth_keyid_serial_mismatch(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-serial-mismatch.pem", "CertUsage_CARelationship_AKI_Serial_Mismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_examine_x509test_xf_ext_cert_policies_any_qual(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-any-qual.pem", "X509Cert_Body_X509Exts_Ext_CP_Qualifier_AnyPolicyWithUnknownQualifier")

	def test_examine_x509test_xf_ext_cert_policies_bmp_unotice(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-bmp-unotice.pem", "X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_InvalidStringType")

	def test_examine_x509test_xf_ext_cert_policies_dup(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-dup.pem", "X509Cert_Body_X509Exts_Ext_CP_DuplicateOID")

	def test_examine_x509test_xf_ext_cert_policies_unotice_ch(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-unotice-ch.pem", "X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_ControlCharacter")

	def test_examine_x509test_xf_ext_constraints_neg_pathlen(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-neg-pathlen.pem", "X509Cert_Body_X509Exts_Unknown_Malformed_Undecodable")

	def test_examine_x509test_xf_ext_constraints_noncritical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-noncritical.pem", "X509Cert_Body_X509Exts_Ext_BC_NotCritical")

	def test_examine_x509test_xf_ext_constraints_path_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-path-nonca.pem", "X509Cert_Body_X509Exts_Ext_BC_PathLenWithoutCA")

	def test_examine_x509test_xf_ext_constraints_path_nosign(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-path-nosign.pem", "X509Cert_Body_X509Exts_Ext_BC_PathLenWithoutKeyCertSign")

	def test_examine_x509test_xf_ext_crl_point_critical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-crl-point-critical.pem", "X509Cert_Body_X509Exts_Ext_CRLDP_Critical")

	def test_examine_x509test_xf_ext_crl_point_reasons_only(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-crl-point-reasons-only.pem", "X509Cert_Body_X509Exts_Ext_CRLDP_PointWithOnlyReasons")

	def test_examine_x509test_xf_ext_ct_poison(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-poison.pem", "X509Cert_Body_X509Exts_Ext_CTPP_IsPrecertificate")

	def test_examine_x509test_xf_ext_ct_sct_trailing_data(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-sct-trailing-data.pem", "X509Cert_Body_X509Exts_Ext_CTSCT_TrailingData")

	def test_examine_x509test_xf_ext_ct_sct_wrong_type(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-sct-wrong-type.pem", "X509Cert_Body_X509Exts_Ext_CTSCT_Malformed_Undecodable")

	def test_examine_x509test_xf_ext_extended_any_key_usage(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-any-key-usage.pem", "X509Cert_Body_X509Exts_Ext_EKU_AnyUsageCriticial")

	def test_examine_x509test_xf_ext_extended_key_usage_empty_oid(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-key-usage-empty-oid.pem", "X509Cert_Body_X509Exts_Ext_EKU_Empty")

	def test_examine_x509test_xf_ext_extended_key_usage_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-key-usage-empty.pem", "X509Cert_Body_X509Exts_Ext_EKU_Empty")

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
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-issuer-altname-critical.pem", "X509Cert_Body_X509Exts_Ext_IAN_Critical")

	def test_examine_x509test_xf_ext_key_usage_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-empty.pem", "X509Cert_Body_X509Exts_Ext_KU_Empty")

	def test_examine_x509test_xf_ext_key_usage_noncritical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-noncritical.pem", "X509Cert_Body_X509Exts_Ext_KU_NotCritical")

	def test_examine_x509test_xf_ext_key_usage_sign_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-sign-nonca.pem", "X509Cert_Body_X509Exts_Ext_KU_SignCertButNoBasicConstraints")

	def test_examine_x509test_xf_ext_key_usage_too_long(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-too-long.pem", "X509Cert_Body_X509Exts_Ext_KU_TooLong")

#	def test_examine_x509test_xf_ext_key_usage_wrong_der(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-wrong-der.pem", "Cert_X509Ext_KeyUsage_InvalidDER")

	def test_examine_x509test_xf_ext_keysign_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-keysign-nonca.pem", "X509Cert_Body_X509Exts_Ext_KU_SignCertButNoCA")

#	def test_examine_x509test_xf_ext_name_constraints_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-empty.pem", "X509Cert_Body_X509Exts_Ext_NC_Empty")

#	def test_examine_x509test_xf_ext_name_constraints_badip(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-badip.pem", "X509Cert_Body_X509Exts_Ext_NC_Subtree_Name_IPAddress_Malformed")

#	def test_examine_x509test_xf_ext_name_constraints_minmax(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-minmax.pem", expect_present = [ "X509Cert_Body_X509Exts_Ext_NC_Subtree_MinimumNotZero", "X509Cert_Body_X509Exts_Ext_NC_Subtree_MaximumPresent" ])

	def test_examine_x509test_xf_ext_name_constraints_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-nonca.pem", "X509Cert_Body_X509Exts_Ext_NC_NoCA")

	def test_examine_x509test_xf_ext_name_constraints_noncrit(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-noncrit.pem", "X509Cert_Body_X509Exts_Ext_NC_NotCritical")

#	def test_examine_x509test_xf_ext_name_constraints_regid(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-name-constraints-regid.pem", "X509Cert_Body_X509Exts_Ext_NC_Subtree_Name_RestictionOnRegisteredID")

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

	def test_examine_x509test_xf_ext_subject_keyid_ca_absent(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-subject-keyid-ca-absent.pem", "X509Cert_Body_X509Exts_Ext_SKI_Missing")

	def test_examine_x509test_xf_ext_subject_keyid_critical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-subject-keyid-critical.pem", "X509Cert_Body_X509Exts_Ext_SKI_Critical")

	def test_examine_x509test_xf_gentime_fraction_secs(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-gentime-fraction-secs.pem", "X509Cert_Body_Validity_NotAfter_Malformed")

	def test_examine_x509test_xf_gentime_no_secs(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-gentime-no-secs.pem", "X509Cert_Body_Validity_NotAfter_Malformed")

	def test_examine_x509test_xf_gentime_nonzulu(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-gentime-nonzulu.pem", "X509Cert_Body_Validity_NotAfter_Malformed")

	def test_examine_x509test_xf_issuer_mismatch_v2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-issuer-mismatch-v2.pem", "CertUsage_CARelationship_Subject_Issuer_Mismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_examine_x509test_xf_issuer_mismatch1(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-issuer-mismatch1.pem", "CertUsage_CARelationship_Subject_Issuer_Mismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_examine_x509test_xf_pubkey_ecdsa_not_on_curve(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-not-on-curve.pem", "X509Cert_PublicKey_ECC_PublicKeyPoint_NotOnCurve")

#	def test_examine_x509test_xf_pubkey_ecdsa_secp192r1(self):
#		We omit this x509test check; it refers to RFC5480 Sect. 2.1.1.1 with
#		the comment that the 192 bit finite field is too short. However,
#		RFC5480 does not make any recommendation regarding security of curves
#		and, on the contrary, includes secp192r1 as NIST-recommended curve.
#		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-secp192r1.pem", "")

	def test_examine_x509test_xf_pubkey_ecdsa_unknown_curve(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-unknown-curve.pem", "X509Cert_PublicKey_ECC_DomainParameters_Name_UnkownName")

	def test_examine_x509test_xf_pubkey_rsa_exponent_negative(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-rsa-exponent-negative.pem", "X509Cert_PublicKey_RSA_Exponent_Negative")

	def test_examine_x509test_xf_pubkey_rsa_modulus_negative(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-rsa-modulus-negative.pem", "X509Cert_PublicKey_RSA_Modulus_Negative")

	def test_examine_x509test_xf_pubkey_rsa_param_nonnull(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-rsa-param-nonnull.pem", "X509Cert_PublicKey_RSA_ParameterFieldNotPresent")

	def test_examine_x509test_xf_serial_negative(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-serial-negative.pem", "X509Cert_Body_SerialNumber_BasicChecks_Negative")

	def test_examine_x509test_xf_serial_zero(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-serial-zero.pem", "X509Cert_Body_SerialNumber_BasicChecks_Zero")

	def test_examine_x509test_xf_soon_generalized_time(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-soon-generalized-time.pem", "X509Cert_Body_Validity_NotBefore_InvalidType")

	def test_examine_x509test_xf_subject_nonprintable(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-subject-nonprintable.pem", "X509Cert_Body_Subject_IllegalCharacter")

	def test_examine_x509test_xf_subject_t61(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-subject-t61.pem", "X509Cert_Body_Subject_DeprecatedType")

	def test_examine_x509test_xf_unknown_critical_ext(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-unknown-critical-ext.pem", "X509Cert_Body_X509Exts_Unknown_Critical")

	def test_examine_x509test_xf_utctime_no_secs(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-utctime-no-secs.pem", "X509Cert_Body_Validity_NotBefore_Malformed")

	def test_examine_x509test_xf_utctime_nonzulu(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-utctime-nonzulu.pem", "X509Cert_Body_Validity_NotBefore_Malformed")

	def test_examine_x509test_xf_v1_extensions(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v1-extensions.pem", "X509Cert_Body_X509Exts_Disallowed")

	def test_examine_x509test_xf_v1_uniqueid(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v1-uniqueid.pem", "X509Cert_Body_SubjectUniqueID_NotAllowedV1")

	def test_examine_x509test_xf_v2_extensions(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v2-extensions.pem", "X509Cert_Body_X509Exts_Disallowed")

	def test_examine_x509test_xf_v3_uniqueid_noexts1(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v3-uniqueid-noexts1.pem", [ "X509Cert_Body_Version_Not2", "X509Cert_Body_SubjectUniqueID_NotAllowedCA" ])

	def test_examine_x509test_xf_v3_uniqueid_noexts2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v3-uniqueid-noexts2.pem", "X509Cert_Body_Version_Not2")

################################################################################################################################################################

	def test_constructed_long_serial(self):
		self._test_examine_x509test_resultcode("certs/constructed/long_serial.pem", "X509Cert_Body_SerialNumber_BasicChecks_Large")

	def test_constructed_pubkey_ecc_G(self):
		self._test_examine_x509test_resultcode("certs/constructed/pubkey_ecc_G.pem", "X509Cert_PublicKey_ECC_PublicKeyPoint_IsGenerator")

	def test_constructed_pubkey_ecc_curveorder(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_secp256r1.pem", expect_present = "X509Cert_PublicKey_ECC_CurveOrderInBits")
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283k1.pem", expect_present = "X509Cert_PublicKey_ECC_CurveOrderInBits")
		self._test_examine_x509test_resultcode("certs/ok/rsa_512.pem", expect_absent = "X509Cert_PublicKey_ECC_CurveOrderInBits")

	def test_constructed_pubkey_ecc_fp_non_koblitz(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_secp256r1.pem", expect_absent = "X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_KoblitzCurve")

	def test_constructed_pubkey_ecc_fp_koblitz(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_secp256k1.pem", "X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_KoblitzCurve")

	def test_constructed_pubkey_ecc_f2m_non_koblitz(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283r1.pem", "X509Cert_PublicKey_ECC_DomainParameters_BinaryField", expect_absent = "X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_KoblitzCurve")

	def test_constructed_pubkey_ecc_f2m_koblitz(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283k1.pem", [ "X509Cert_PublicKey_ECC_DomainParameters_BinaryField", "X509Cert_PublicKey_ECC_DomainParameters_CurveProperty_KoblitzCurve" ])

	def test_constructed_ecdsa_sig_r_bitbias(self):
		# Need the CA for this test, since the signature can only be checked
		# when the curve is known, which is encoded in the CA's public key.
		self._test_examine_x509test_resultcode("certs/constructed/ecdsa_sig_r_bitbias.pem", "X509Cert_Signature_ECDSA_R_BitBiasPresent", parent_certname = "certs/ok/johannes-bauer.com.pem")

	def test_constructed_ecdsa_sig_s_bitbias(self):
		# Need the CA for this test, since the signature can only be checked
		# when the curve is known, which is encoded in the CA's public key.
		self._test_examine_x509test_resultcode("certs/constructed/ecdsa_sig_s_bitbias.pem", "X509Cert_Signature_ECDSA_S_BitBiasPresent", parent_certname = "certs/ok/johannes-bauer.com.pem")

	def test_constructed_ecdsa_sig_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecdsa_sig_malformed.pem", "X509Cert_Signature_ECDSA_Malformed_Undecodable", parent_certname = "certs/constructed/ecdsa_sig_malformed.pem")

	def test_constructed_pubkey_bitbias_x_low_hweight(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_pubkey_x_bitbias1.pem", "X509Cert_PublicKey_ECC_PublicKeyPoint_X_BitBiasPresent", expect_absent = "X509Cert_PublicKey_ECC_PublicKeyPoint_Y_BitBiasPresent")

	def test_constructed_pubkey_bitbias_x_high_hweight(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_pubkey_x_bitbias2.pem", "X509Cert_PublicKey_ECC_PublicKeyPoint_X_BitBiasPresent", expect_absent = "X509Cert_PublicKey_ECC_PublicKeyPoint_Y_BitBiasPresent")

	def test_constructed_pubkey_bitbias_y(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_pubkey_y_bitbias.pem", "X509Cert_PublicKey_ECC_PublicKeyPoint_Y_BitBiasPresent", expect_absent = "X509Cert_PublicKey_ECC_PublicKeyPoint_X_BitBiasPresent")

	def test_hostname_ok(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "CertUsage_Purpose_ServerCert_SAN_Match", expect_absent = "CertUsage_Purpose_ServerCert_SAN_Mismatch", host_check = "mail.johannes-bauer.com")
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "CertUsage_Purpose_ServerCert_SAN_Match", expect_absent = "CertUsage_Purpose_ServerCert_SAN_Mismatch", host_check = "www.johannes-bauer.com")
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "CertUsage_Purpose_ServerCert_SAN_Match", expect_absent = "CertUsage_Purpose_ServerCert_SAN_Mismatch", host_check = "johannes-bauer.com")

	def test_hostname_not_ok(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "CertUsage_Purpose_ServerCert_SAN_Mismatch", expect_absent = "CertUsage_Purpose_ServerCert_SAN_Match", host_check = "wwwQjohannes-bauer.com")

	def test_constructed_rsa_bitbias(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_bitbias.pem", "X509Cert_PublicKey_RSA_Modulus_BitBiasPresent")

	def test_constructed_rsa_modulus_prime(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_modulus_prime.pem", "X509Cert_PublicKey_RSA_Modulus_Prime", fast_rsa = False)

	def test_constructed_rsa_modulus_smallfactor(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_modulus_smallfactor.pem", "X509Cert_PublicKey_RSA_Modulus_Factorable", fast_rsa = False)

	def test_constructed_rsa_modulus_compromised(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_modulus_compromised.pem", "X509Cert_PublicKey_RSA_Modulus_FactorizationKnown")

	def test_constructed_rsa_exponent0(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent0.pem", "X509Cert_PublicKey_RSA_Exponent_Negative")

	def test_constructed_rsa_exponent1(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent1.pem", "X509Cert_PublicKey_RSA_Exponent_One")

	def test_constructed_rsa_exponent3(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent3.pem", "X509Cert_PublicKey_RSA_Exponent_Small")

	def test_constructed_rsa_exponent101(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent101.pem", "X509Cert_PublicKey_RSA_Exponent_SmallAndUncommon")

	def test_constructed_rsa_exponent65537(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent65537.pem", "X509Cert_PublicKey_RSA_Exponent_MostCommonValue")

	def test_constructed_rsa_exponent_long(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_exponent_long.pem", "X509Cert_PublicKey_RSA_Exponent_Large")

	def test_constructed_rsa_parameter_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_parameter_missing.pem", "X509Cert_PublicKey_RSA_ParameterFieldNotPresent")

	def test_include_raw_data_rsa(self):
		self._test_examine_x509test_resultcode("certs/ok/rsa_512.pem", expect_present = [ "X509Cert_Signature_Function_Common", "X509Cert_Signature_HashFunction_Derated", "X509Cert_PublicKey_RSA_Modulus_LengthInBits", "X509Cert_Signature_HashFunction_DigestLengthInBits" ], include_raw = True)

	def test_include_raw_data_ecc_fp(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_secp256r1.pem", expect_present = "X509Cert_Signature_Function_Common", include_raw = True)

	def test_include_raw_data_ecc_f2m(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283r1.pem", include_raw = True)

	def test_include_raw_data_ecc_twedwards(self):
		self._test_examine_x509test_resultcode("certs/ok/pubkey_sig_ed25519.pem", expect_present = "X509Cert_Signature_Function_UncommonCryptosystem", include_raw = True)

	def test_explicit_prime(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_explicit_param_prime.pem", expect_present = [ "X509Cert_PublicKey_ECC_DomainParameters_Name_UnusedName", "X509Cert_PublicKey_ECC_DomainParameters_Name_ExplicitCurve" ], expect_absent = "X509Cert_PublicKey_ECC_DomainParameters_Name_UnknownExplicit")

	def test_explicit_twofield_ppbasis(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_explicit_param_twofield_ppbasis.pem", "X509Cert_PublicKey_ECC_DomainParameters_Name_ExplicitCurve", expect_absent = [ "X509Cert_PublicKey_ECC_DomainParameters_BinaryField_InvalidPolynomialPower", "X509Cert_PublicKey_ECC_DomainParameters_BinaryField_DuplicatePolynomialPower", "X509Cert_PublicKey_ECC_DomainParameters_Name_UnknownExplicit" ])

	def test_explicit_twofield_tpbasis(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_explicit_param_twofield_tpbasis.pem", "X509Cert_PublicKey_ECC_DomainParameters_Name_ExplicitCurve", expect_absent = [ "X509Cert_PublicKey_ECC_DomainParameters_BinaryField_InvalidPolynomialPower", "X509Cert_PublicKey_ECC_DomainParameters_BinaryField_DuplicatePolynomialPower", "X509Cert_PublicKey_ECC_DomainParameters_Name_UnknownExplicit" ])

	def test_explicit_twofield_poly_invalid_power1(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_explicit_param_twofield_invalid_power1.pem", "X509Cert_PublicKey_ECC_DomainParameters_BinaryField_InvalidPolynomialPower")

	def test_explicit_twofield_poly_invalid_power2(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_explicit_param_twofield_invalid_power2.pem", "X509Cert_PublicKey_ECC_DomainParameters_BinaryField_InvalidPolynomialPower")

	def test_explicit_twofield_poly_duplicate_power(self):
		self._test_examine_x509test_resultcode("certs/constructed/ecc_explicit_param_twofield_duplicate_power.pem", "X509Cert_PublicKey_ECC_DomainParameters_BinaryField_DuplicatePolynomialPower")

	def test_explicit_unknown(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_explicit_param_prime_custom_domain.pem", expect_present = [ "X509Cert_PublicKey_ECC_DomainParameters_Name_ExplicitCurve", "X509Cert_PublicKey_ECC_DomainParameters_Name_UnknownExplicit" ], expect_absent = "X509Cert_PublicKey_ECC_DomainParameters_Name_UnusedName")

	def test_san_broad_match1(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_broad_match1.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_Wildcard_BroadMatch")

	def test_san_broad_match2(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_broad_match2.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_Wildcard_BroadMatch")

	def test_san_bad_email(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_email.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_Email_Malformed")

	def test_san_bad_ip(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_ip.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_Malformed")

	def test_san_bad_ip_private(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_ip_private.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_PrivateAddressSpace")

	def test_san_wildcard_not_leftmost(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_wildcard_not_leftmost.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_Wildcard_NotLeftmost")

	def test_san_wildcard_more_than_one(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_wildcard_more_than_one.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_Wildcard_MulitpleWildcards")

	def test_san_international_label_ok(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_international_label_ok.pem", expect_absent = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_Wildcard_InternationalLabel")

	def test_san_international_label_wrong(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_international_label_wrong.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_Wildcard_InternationalLabel")

	def test_san_bad_domain(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_domain.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_Malformed")

	def test_san_bad_domain_space(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_domain_space.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_OnlyWhitespace")

	def test_san_bad_domain_single_label(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_domain_single_label.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_SingleLabel")

	def test_san_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_missing.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Missing")

	def test_san_missing_nosubject(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_missing_nosubject.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Missing")

	def test_san_bad_uri(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_uri.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_URI_Malformed")

	def test_san_bad_uri_uncommon_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_bad_uri_uncommon_scheme.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_URI_UncommonURIScheme")

	def test_san_uncommon_identifier(self):
		self._test_examine_x509test_resultcode("certs/constructed/san_good_uri.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SAN_Name_URI_Unexpected")

	def test_dn_all_ok(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_all_okay.pem", expect_absent = [ "X509Cert_Body_Subject_RDN_LengthExceeded" ])

	def test_dn_long_rdn_cn64(self):
		# Still barely okay, 64 characters is limit for CN
		self._test_examine_x509test_resultcode("certs/constructed/dn_long_rdn_cn64.pem", expect_absent = "X509Cert_Body_Subject_RDN_LengthExceeded")

	def test_dn_long_rdn_cn65(self):
		# Straw that breaks the camel's back
		self._test_examine_x509test_resultcode("certs/constructed/dn_long_rdn_cn65.pem", expect_present = "X509Cert_Body_Subject_RDN_LengthExceeded")

	def test_dn_long_rdn_c(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_long_rdn_c.pem", expect_present = "X509Cert_Body_Subject_RDN_LengthExceeded")

	def test_dn_multivalue(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_multivalue.pem", expect_present = "X509Cert_Body_Subject_RDN_MultiValuedRDN")

	def test_dn_nonprintable(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_nonprintable.pem", expect_present = "X509Cert_Body_Subject_NonPrintable")

	def test_dn_duplicate_rdns(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_multiple_identical_rdns.pem", expect_present = "X509Cert_Body_Subject_DuplicateRDNs")

	def test_dn_many_rdns(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_many_rdns.pem", expect_present = "X509Cert_Body_Subject_UnusuallyManyRDNs")

	def test_dn_no_cn(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_no_cn.pem", expect_present = "X509Cert_Body_Subject_NoCN")

	def test_dn_multiple_cns(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_multiple_cn.pem", expect_present = "X509Cert_Body_Subject_MultipleCN")

	def test_dn_duplicate_set(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_duplicate_set.pem", expect_present = [ "X509Cert_Body_Subject_RDN_DuplicateSet_Key", "X509Cert_Body_Subject_RDN_DuplicateSet_Key_Value" ])

	def test_dn_duplicate_oid_in_mvrdn(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_duplicate_oid_in_mvrdn.pem", expect_present = "X509Cert_Body_Subject_RDN_DuplicateSet_Key", expect_absent = "X509Cert_Body_Subject_RDN_DuplicateSet_Key_Value")

	def test_cn_match_fqdn_but_multivalue_rdn(self):
		self._test_examine_x509test_resultcode("certs/constructed/dn_cn_hostname_multivalue_rdn.pem", expect_present = "CertUsage_Purpose_ServerCert_CN_MatchMultivalueRDN", expect_absent = "X509Cert_Body_Subject_NoCN", host_check = "multivalue.com")

	def test_cn_match_fqdn(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", expect_present = "CertUsage_Purpose_ServerCert_CN_Match", expect_absent = "X509Cert_Body_X509Exts_Ext_SAN_Missing", host_check = "johannes-bauer.com")

	def test_cn_no_match_fqdn(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", expect_present = [ "CertUsage_Purpose_ServerCert_CN_Mismatch", "CertUsage_Purpose_ServerCert_NameVerificationFailed" ], host_check = "pupannes-bauer.com")

	def test_check_no_ca_when_expecting_ca(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", expect_present = "CertUsage_Purpose_CACert_NoCACert", purpose = "ca")

	def test_check_ca_when_expecting_no_ca(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer-intermediate.pem", expect_present = "CertUsage_Purpose_ClientCert_IsCACert", purpose = "tls-server")

	def test_check_version(self):
		self._test_examine_x509test_resultcode("certs/constructed/version1.pem", expect_present = "X509Cert_Body_Version_Not3")

	def test_check_algorithm_alternate_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/algorithm_alternate_oid.pem", expect_present = "X509Cert_Signature_Function_DeprecatedOID")

	def test_validity_never_valid(self):
		self._test_examine_x509test_resultcode("certs/constructed/validity_never_valid.pem", expect_present = "X509Cert_Body_Validity_Status_NeverValid")

	def test_validity_expired(self):
		self._test_examine_x509test_resultcode("certs/constructed/validity_expired.pem", expect_present = "X509Cert_Body_Validity_Status_Expired")

	def test_validity_valid(self):
		self._test_examine_x509test_resultcode("certs/constructed/validity_valid.pem", expect_present = "X509Cert_Body_Validity_Status_CurrentlyValid")

	def test_not_yet_validity_not_yet_valid(self):
		self._test_examine_x509test_resultcode("certs/constructed/validity_not_yet_valid.pem", expect_present = "X509Cert_Body_Validity_Status_NotYetValid")

	def test_unknown_sigfnc(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_sigfnc.pem", expect_present = "X509Cert_Signature_Function_Unknown")

	def test_rsa_pss_ok(self):
		self._test_examine_x509test_resultcode("certs/ok/rsapss_defaults.pem", expect_present = "X509Cert_Signature_Function_UncommonPadding")

	def test_rsa_pss_unknown_hashfnc1(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_hashfnc1.pem", expect_present = "X509Cert_Signature_HashFunction_Unknown")

	def test_rsa_pss_unknown_hashfnc2(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_hashfnc2.pem", expect_present = "X509Cert_Signature_HashFunction_Unknown")

	def test_rsa_pss_unknown_maskfnc(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_maskfnc.pem", expect_present = "X509Cert_PublicKey_RSA_RSA_PSS_UnknownMaskFunction")

	def test_rsa_pss_malformed1(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_malformed1.pem", expect_present = "X509Cert_PublicKey_RSA_RSAPSS_InvalidSaltLength")

	def test_rsa_pss_malformed2(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_malformed2.pem", expect_present = "X509Cert_PublicKey_RSA_RSA_PSS_UnknownTrailerField")

	def test_rsa_pss_malformed3(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_malformed3.pem", expect_present = "X509Cert_PublicKey_RSA_RSA_PSS_UnknownTrailerField")

	def test_rsa_pss_malformed4(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_malformed4.pem", expect_present = "X509Cert_PublicKey_RSA_RSAPSS_Parameters_Malformed_Undecodable")

	def test_rsa_pss_salt0(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_salt0.pem", expect_present = "X509Cert_PublicKey_RSA_RSA_PSS_NoSaltUsed")

	def test_rsa_pss_salt3(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_salt3.pem", expect_present = "X509Cert_PublicKey_RSA_RSA_PSS_ShortSaltUsed")

	def test_rsa_pss_salt16(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_salt16.pem", expect_present = "X509Cert_PublicKey_RSA_RSA_PSS_SaltLengthInBytes")

	def test_rsa_pss_multiple_hashes(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_multiple_hashes.pem", expect_present = "X509Cert_PublicKey_RSA_RSA_PSS_MultipleHashFunctions")

	def test_rsa_pss_mismatch_algo1(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo1.pem", expect_present = "X509Cert_Signature_Function_BodyMismatch")

	def test_rsa_pss_mismatch_algo2(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo2.pem", expect_present = "X509Cert_Signature_Function_BodyMismatch")

	def test_rsa_pss_mismatch_algo3(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo3.pem", expect_present = "X509Cert_Signature_Function_BodyMismatch")

	def test_rsa_pss_mismatch_algo4(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo4.pem", expect_present = "X509Cert_Signature_Function_BodyMismatch")

	def test_rsa_pss_mismatch_algo5(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsapss_mismatch_algo5.pem", expect_present = "X509Cert_Signature_Function_BodyMismatch")

	def test_mismatch_header_footer_sigparams(self):
		self._test_examine_x509test_resultcode("certs/constructed/mismatch_header_footer_sigparams.pem", expect_present = "X509Cert_Signature_Function_BodyMismatch")

	def test_dsa_p_not_prime(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_p_not_prime.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_P_NotPrime")

	def test_dsa_q_not_prime(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_q_not_prime.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_Q_NotPrime")

	def test_dsa_p_bitbias(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_p_bitbias.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_P_BitBiasPresent", expect_absent = "X509Cert_PublicKey_DSA_Parameters_Q_BitBiasPresent")

	def test_dsa_q_bitbias(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_q_bitbias.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_Q_BitBiasPresent", expect_absent = "X509Cert_PublicKey_DSA_Parameters_P_BitBiasPresent")

	def test_dsa_r_bitbias(self):
		# Need the CA for this test, since the signature can only be checked
		# when the curve is known, which is encoded in the CA's public key.
		self._test_examine_x509test_resultcode("certs/constructed/dsa_r_bitbias.pem", expect_present = "X509Cert_Signature_DSA_R_BitBiasPresent", parent_certname = "certs/constructed/dsa_base.pem")

	def test_dsa_s_bitbias(self):
		# Need the CA for this test, since the signature can only be checked
		# when the curve is known, which is encoded in the CA's public key.
		self._test_examine_x509test_resultcode("certs/constructed/dsa_s_bitbias.pem", expect_present = "X509Cert_Signature_DSA_S_BitBiasPresent", parent_certname = "certs/constructed/dsa_base.pem")

	def test_dsa_q_does_not_divide_p1(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_q_does_not_divide_p1.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_Q_NoDivisorOfP1")

	def test_dsa_sig_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_sig_malformed.pem", expect_present = "X509Cert_Signature_DSA_Malformed_Undecodable")

	def test_dsa_typical_parameters(self):
		self._test_examine_x509test_resultcode("certs/ok/dsa_sha1.pem", expect_present = [ "X509Cert_PublicKey_DSA_L_N_Common", "X509Cert_PublicKey_DSA_L_N" ], expect_absent = "X509Cert_PublicKey_DSA_L_N_Uncommon", include_raw = True)

	def test_dsa_atypical_parameters(self):
		self._test_examine_x509test_resultcode("certs/ok/dsa_512_160_sha256.pem", expect_present = "X509Cert_PublicKey_DSA_L_N_Uncommon", expect_absent = "X509Cert_PublicKey_DSA_L_N_Common")

	def test_dsa_g_invalid_range(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_G_Invalid")

	def test_dsa_g_invalid_range1(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid_range1.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_G_InvalidRange")

	def test_dsa_g_invalid_range2(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid_range2.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_G_InvalidRange")

	def test_dsa_g_invalid_range3(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid_range3.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_G_InvalidRange")

	def test_dsa_g_invalid_range4(self):
		self._test_examine_x509test_resultcode("certs/constructed/dsa_g_invalid_range4.pem", expect_present = "X509Cert_PublicKey_DSA_Parameters_G_InvalidRange")

	def test_ski_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/ski_missing.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SKI_Missing")

	def test_ski_arbitrary(self):
		self._test_examine_x509test_resultcode("certs/constructed/ski_arbitrary.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SKI_Hashfunction_Arbitrary")

	def test_ski_sha1(self):
		self._test_examine_x509test_resultcode("certs/constructed/ski_sha1.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SKI_Hashfunction_SHA1")

	def test_ski_sha256(self):
		self._test_examine_x509test_resultcode("certs/constructed/ski_sha256.pem", expect_present = "X509Cert_Body_X509Exts_Ext_SKI_Hashfunction_Other")

	def test_aki_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_missing.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_Missing")

	def test_aki_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_Malformed_Undecodable")

	def test_aki_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_empty.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_Empty")

	def test_aki_keyid_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_keyid_empty.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_EmptyKeyID")

	def test_aki_keyid_long(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_keyid_long.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_LongKeyID")

	def test_aki_name_without_serial(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_name_without_serial.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAnameWithoutSerial")

	def test_aki_ca_has_no_ski(self):
		self._test_examine_x509test_resultcode("certs/ok/short.pem", parent_certname = "certs/constructed/ski_missing.pem", expect_present = "CertUsage_CARelationship_AKI_KeyID_Uncheckable")

	def test_aki_caname_bad_domain(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_domain.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_DNS_Malformed")

	def test_aki_caname_bad_email(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_email.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_Email_Malformed")

	def test_aki_caname_bad_uri(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_uri.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_URI_Malformed")

	def test_aki_caname_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_empty.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_Empty")

	def test_aki_caname_emptyvalue(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_emptyvalue.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_DNS_Malformed")

	def test_aki_caname_bad_ip_private(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_ip_private.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_IPAddress_PrivateAddressSpace")

	def test_aki_caname_bad_domain_space(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_domain_space.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_DNS_OnlyWhitespace")

	def test_aki_caname_bad_domain_single_label(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_bad_domain_single_label.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_DNS_SingleLabel")

	def test_aki_caname_uncommon_identifier(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_good_ip.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_IPAddress_Unexpected")

	def test_aki_caname_uncommon_uri_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/aki_caname_uncommon_uri_scheme.pem", expect_present = "X509Cert_Body_X509Exts_Ext_AKI_CAName_URI_UncommonURIScheme")

	def test_ext_unknown_noncritical(self):
		self._test_examine_x509test_resultcode("certs/constructed/unknown_ext_noncritical.pem", expect_present = "X509Cert_Body_X509Exts_Unknown_NotCritical")

	def test_basic_constraints_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/bc_missing.pem", expect_present = "X509Cert_Body_X509Exts_Ext_BC_Missing")

	def test_basic_constraints_present_critical(self):
		self._test_examine_x509test_resultcode("certs/constructed/bc_present_critical.pem", expect_present = "X509Cert_Body_X509Exts_Ext_BC_Critical")

	def test_basic_constraints_present_noncritical(self):
		self._test_examine_x509test_resultcode("certs/constructed/bc_present_noncritical.pem", expect_present = "X509Cert_Body_X509Exts_Ext_BC_NotCritical")

	def test_issuer_altname_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_missing.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Missing")

	def test_issuer_altname_not_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_not_missing.pem", expect_absent = "X509Cert_Body_X509Exts_Ext_IAN_Missing")

	def test_issuer_altname_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_empty.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Empty")

	def test_issuer_altname_emptyvalue(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_emptyvalue.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_Email_Malformed")

	def test_issuer_altname_bad_domain(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_domain.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_DNS_Malformed")

	def test_issuer_altname_bad_domain_space(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_domain_space.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_DNS_OnlyWhitespace")

	def test_issuer_altname_bad_domain_single_label(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_domain_single_label.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_DNS_SingleLabel")

	def test_issuer_altname_bad_uri(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_uri.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_URI_Malformed")

	def test_issuer_altname_uncommon_uri_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_uncommon_uri_scheme.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_URI_UncommonURIScheme")

	def test_issuer_altname_bad_ip(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_ip.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_IPAddress_Malformed")

	def test_issuer_altname_bad_ip_private(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_ip_private.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_IPAddress_PrivateAddressSpace")

	def test_issuer_altname_uncommon_identifier(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_good_ip.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_IPAddress_Unexpected")

	def test_issuer_altname_bad_email(self):
		self._test_examine_x509test_resultcode("certs/constructed/issuer_altname_bad_email.pem", expect_present = "X509Cert_Body_X509Exts_Ext_IAN_Name_Email_Malformed")

	def test_extension_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ext_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Unknown_Malformed_Undecodable")

	def test_certificate_lifetime_noca_conservative(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_noca_conservative.pem", expect_present = "X509Cert_Body_Validity_Length_Conservative")

	def test_certificate_lifetime_noca_long(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_noca_long.pem", expect_present = "X509Cert_Body_Validity_Length_Long")

	def test_certificate_lifetime_noca_verylong(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_noca_verylong.pem", expect_present = "X509Cert_Body_Validity_Length_VeryLong")

	def test_certificate_lifetime_noca_exceptionallylong(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_noca_exceptionallylong.pem", expect_present = "X509Cert_Body_Validity_Length_ExceptionallyLong")

	def test_certificate_lifetime_ca_conservative(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_ca_conservative.pem", expect_present = "X509Cert_Body_Validity_Length_Conservative")

	def test_certificate_lifetime_ca_long(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_ca_long.pem", expect_present = "X509Cert_Body_Validity_Length_Long")

	def test_certificate_lifetime_ca_verylong(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_ca_verylong.pem", expect_present = "X509Cert_Body_Validity_Length_VeryLong")

	def test_certificate_lifetime_ca_exceptionallylong(self):
		self._test_examine_x509test_resultcode("certs/constructed/lifetime_ca_exceptionallylong.pem", expect_present = "X509Cert_Body_Validity_Length_ExceptionallyLong")

	def test_key_usage_excessive(self):
		self._test_examine_x509test_resultcode("certs/constructed/ku-xmas.pem", expect_present = [ "CertUsage_Purpose_ClientCert_KU_ExcessBits", "CertUsage_Purpose_ClientCert_KU_UnusualBits" ], purpose = "tls-server")

	def test_key_usage_missing(self):
		self._test_examine_x509test_resultcode("certs/constructed/ku-missing.pem", expect_present = "CertUsage_Purpose_ClientCert_KU_MissingBits", purpose = "ca")

	def test_key_usage_trailingzero(self):
		self._test_examine_x509test_resultcode("certs/constructed/ku-trailingzero.pem", expect_present = "X509Cert_Body_X509Exts_Ext_KU_TrailingZeros")

	def test_key_usage_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ku-malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_KU_Malformed_Undecodable")

	def test_key_usage_extension_missing(self):
		self._test_examine_x509test_resultcode("certs/ok/short.pem", expect_present = "X509Cert_Body_X509Exts_Ext_KU_Missing")

	def test_key_usage_noncritical_ca(self):
		# Different code path when the certificate is a CA certificate, include
		# test for coverage of both paths.
		self._test_examine_x509test_resultcode("certs/constructed/ku_noncritical_ca.pem", expect_present = "X509Cert_Body_X509Exts_Ext_KU_NotCritical", purpose = "ca")

	def test_certpol_polcount_1(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_polcount_1.pem", expect_absent = "X509Cert_Body_X509Exts_Ext_CP_MoreThanOnePolicy")

	def test_certpol_polcount_2(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_polcount_2.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_MoreThanOnePolicy")

	def test_certpol_deprecated_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_deprecated_oid.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_DeprecatedOID")

	def test_certpol_duplicate_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_duplicate_oid.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_DuplicateOID")

	def test_certpol_duplicate_qualifier_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_duplicate_qualifier_oid.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_Qualifier_Duplicate")

	def test_certpol_cps_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_cps_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_CPS_Malformed_Undecodable")

	def test_certpol_cps_constraint_violation(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_cps_constraint_violation.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_CPS_ConstraintViolation")

	def test_certpol_cps_unusual_uri_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_cps_unusual_uri_scheme.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_CPS_URI_UncommonURIScheme")

	def test_certpol_unotice_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_empty.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_UserNotice_Empty")

	def test_certpol_unotice_withexplicittext(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_withexplicittext.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_IA5String")

	def test_certpol_unotice_withexplicittextutf8(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_withexplicittext_utf8.pem", expect_absent = "X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_IA5String")

	def test_certpol_unotice_noexplicittext(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_noexplicittext.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_UserNotice_ExplicitText_Absent")

	def test_certpol_unotice_longexplicittext(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_longexplicittext.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_UserNotice_ConstraintViolation")

	def test_certpol_unotice_withnoticeref(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_withnoticeref.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_UserNotice_NoticeRefPresent")

	def test_certpol_unotice_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unotice_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_UserNotice_Malformed_Undecodable")

	def test_certpol_unknown_qualifier_oid(self):
		self._test_examine_x509test_resultcode("certs/constructed/certpol_unknown_qualifier_oid.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CP_Qualifier_Unknown")

	def test_duplicate_extension_present(self):
		self._test_examine_x509test_resultcode("certs/constructed/duplicate_extension.pem", expect_absent = "X509Cert_Body_X509Exts_AllUnique")

	def test_no_duplicate_extension_present(self):
		self._test_examine_x509test_resultcode("certs/ok/short.pem", expect_present = "X509Cert_Body_X509Exts_AllUnique")

	def test_eku_no_client(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_server.pem", expect_present = "CertUsage_Purpose_ClientCert_EKUMismatch", purpose = "tls-client")

	def test_eku_is_client(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_client.pem", expect_absent = "CertUsage_Purpose_ClientCert_EKUMismatch", purpose = "tls-client")

	def test_eku_no_server(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_client.pem", expect_present = "CertUsage_Purpose_ServerCert_EKUMismatch", purpose = "tls-server")

	def test_eku_is_server(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_server.pem", expect_absent = "CertUsage_Purpose_ServerCert_EKUMismatch", purpose = "tls-server")

	def test_eku_duplicate(self):
		self._test_examine_x509test_resultcode("certs/constructed/eku_duplicate.pem", expect_present = "X509Cert_Body_X509Exts_Ext_EKU_Duplicate")

	def test_nsct_no_client(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_server.pem", expect_present = "CertUsage_Purpose_ClientCert_NSCT_NoSSLClient", purpose = "tls-client")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_ssl_ca.pem", expect_present = "CertUsage_Purpose_ClientCert_NSCT_NoSSLClient", purpose = "tls-client")

	def test_nsct_is_client(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_client.pem", expect_absent = "CertUsage_Purpose_ClientCert_NSCT_NoSSLClient", purpose = "tls-client")

	def test_nsct_no_server(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_client.pem", expect_present = "CertUsage_Purpose_ServerCert_NSCT_NoSSLServer", purpose = "tls-server")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_ssl_ca.pem", expect_present = "CertUsage_Purpose_ServerCert_NSCT_NoSSLServer", purpose = "tls-server")

	def test_nsct_is_server(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_server.pem", expect_absent = "CertUsage_Purpose_ServerCert_NSCT_NoSSLServer", purpose = "tls-server")

	def test_nsct_no_ca(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_client.pem", expect_present = "CertUsage_Purpose_CACert_NSCT_NoCA", purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_server.pem", expect_present = "CertUsage_Purpose_CACert_NSCT_NoCA", purpose = "ca")

	def test_nsct_is_ca(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_ssl_ca.pem", expect_absent = "CertUsage_Purpose_CACert_NSCT_NoCA", purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_smime_ca.pem", expect_absent = "CertUsage_Purpose_CACert_NSCT_NoCA", purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_objsign_ca.pem", expect_absent = "CertUsage_Purpose_CACert_NSCT_NoCA", purpose = "ca")

	def test_nsct_ssl_ca(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_ssl_ca.pem", expect_absent = [ "CertUsage_Purpose_CACert_NSCT_NoSSLCA", "CertUsage_Purpose_CACert_NSCT_NoCA"], purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_smime_ca.pem", expect_present = "CertUsage_Purpose_CACert_NSCT_NoSSLCA", expect_absent = "CertUsage_Purpose_CACert_NSCT_NoCA", purpose = "ca")
		self._test_examine_x509test_resultcode("certs/constructed/nsct_objsign_ca.pem", expect_present = "CertUsage_Purpose_CACert_NSCT_NoSSLCA", expect_absent = "CertUsage_Purpose_CACert_NSCT_NoCA", purpose = "ca")

	def test_nsct_unused(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_unused.pem", expect_present = "X509Cert_Body_X509Exts_Ext_NSCT_UnusedBitSet")

	def test_nsct_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_NSCT_Malformed_Undecodable")

	def test_nsct_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/nsct_empty.pem", expect_present = "X509Cert_Body_X509Exts_Ext_NSCT_Empty")

	def test_ext_empty_sequence(self):
		self._test_examine_x509test_resultcode("certs/constructed/ext_empty_sequence.pem", expect_present = "X509Cert_Body_X509Exts_EmptySequence")

	def test_ext_not_present(self):
		self._test_examine_x509test_resultcode("certs/constructed/ext_not_present.pem", expect_absent = "X509Cert_Body_X509Exts_EmptySequence")

	def test_ca_relationship_signature_success(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer-intermediate.pem", expect_present = [ "CertUsage_CARelationship_Subject_Issuer_Match", "CertUsage_CARelationship_Signature_VerificationSuccess" ])

	def test_ca_relationship_signature_failure(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer-root.pem", expect_present = [ "CertUsage_CARelationship_Subject_Issuer_Mismatch", "CertUsage_CARelationship_Signature_VerificationFailure" ], expect_absent = "CertUsage_CARelationship_CACertificateInvalidAsCA")

	def test_ca_relationship_invalid_as_ca(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer.com.pem", expect_present = [ "CertUsage_CARelationship_Subject_Issuer_Mismatch", "CertUsage_CARelationship_Signature_VerificationFailure", "CertUsage_CARelationship_CACertificateInvalidAsCA" ])

	def test_ca_relationship_validity_full_overlap(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer-intermediate.pem", expect_present = "CertUsage_CARelationship_Validity_FullOverlap")

	def test_ca_relationship_validity_partial_overlap(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_valid_firsthalf.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CertUsage_CARelationship_Validity_PartialOverlap")
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_valid_secondhalf.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CertUsage_CARelationship_Validity_PartialOverlap")

	def test_ca_relationship_validity_no_overlap(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_valid_before.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CertUsage_CARelationship_Validity_NoOverlap")
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_valid_after.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CertUsage_CARelationship_Validity_NoOverlap")

	def test_ca_relationship_validity_malformed(self):
		self._test_examine_x509test_resultcode("certs/ok/short.pem", parent_certname = "certs/constructed/timestamp_malformed.pem", expect_present = "CertUsage_CARelationship_Validity_MalformedTimestamp")
		self._test_examine_x509test_resultcode("certs/constructed/timestamp_malformed.pem", parent_certname = "certs/ok/short.pem", expect_present = "CertUsage_CARelationship_Validity_MalformedTimestamp")

	def test_ca_relationship_aki_keyid_match(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer-intermediate.pem", expect_present = "CertUsage_CARelationship_AKI_KeyID_Match", expect_absent = "CertUsage_CARelationship_AKI_KeyID_Mismatch")

	def test_ca_relationship_aki_keyid_mismatch(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/johannes-bauer.com.pem", expect_present = "CertUsage_CARelationship_AKI_KeyID_Mismatch", expect_absent = "CertUsage_CARelationship_AKI_KeyID_Match")

	def test_ca_relationship_aki_keyid_uncheckable(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", parent_certname = "certs/ok/custom_key_usage.pem", expect_present = "CertUsage_CARelationship_AKI_KeyID_Uncheckable", expect_absent = [ "CertUsage_CARelationship_AKI_KeyID_Mismatch", "CertUsage_CARelationship_AKI_KeyID_Match" ])

	def test_ca_relationship_aki_caname_match(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_cert_caname_match.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CertUsage_CARelationship_AKI_CAName_Match", expect_absent = "CertUsage_CARelationship_AKI_CAName_Mismatch")

	def test_ca_relationship_aki_caname_mismatch(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_cert_caname_mismatch.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CertUsage_CARelationship_AKI_CAName_Mismatch", expect_absent = "CertUsage_CARelationship_AKI_CAName_Match")

	def test_ca_relationship_aki_serial_match(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_cert_serial_match.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CertUsage_CARelationship_AKI_Serial_Match", expect_absent = "CertUsage_CARelationship_AKI_Serial_Mismatch")

	def test_ca_relationship_aki_serial_mismatch(self):
		self._test_examine_x509test_resultcode("certs/constructed/ca_rel_cert_serial_mismatch.pem", parent_certname = "certs/constructed/ca_rel_CA_y2k.pem", expect_present = "CertUsage_CARelationship_AKI_Serial_Mismatch", expect_absent = "CertUsage_CARelationship_AKI_Serial_Match")

	def test_unique_id_issuer(self):
		self._test_examine_x509test_resultcode("certs/constructed/unique_id_issuer.pem", [ "X509Cert_Body_IssuerUniqueID_NotAllowedCA", "X509Cert_Body_IssuerUniqueID_NotAllowedV1" ])

	def test_crldp_point_empty(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_empty.pem", expect_present = [ "X509Cert_Body_X509Exts_Ext_CRLDP_Empty" ], expect_absent = [ "X509Cert_Body_X509Exts_Ext_CRLDP_PointWithOnlyReasons", "X509Cert_Body_X509Exts_Ext_CRLDP_NoLDAPorHTTPURI" ])

	def test_crldp_point_no_http_ldap(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_no_http_ldap.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_NoLDAPorHTTPURI")

	def test_crldp_reason_unused_bit_set(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_unused_bit_set.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_Reasons_UnusedBitsAsserted", expect_absent = "X509Cert_Body_X509Exts_Ext_CRLDP_Reasons_UndefinedBitsAsserted")

	def test_crldp_reason_undefined_bits_set(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_undefined_bits_set.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_Reasons_UndefinedBitsAsserted", expect_absent = "X509Cert_Body_X509Exts_Ext_CRLDP_Reasons_UnusedBitsAsserted")

	def test_crldp_reason_trailing_bits(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_trailing_bits.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_Reasons_TrailingZeros")

	def test_crldp_reason_only_field(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_only_field.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointWithOnlyReasons")

	def test_crldp_reason_not_present(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_not_present.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_SegmentationUsed", expect_absent = "X509Cert_Body_X509Exts_Ext_CRLDP_NoPointWithAllReasonBits")

	def test_crldp_reason_no_point_with_all(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_reason_no_point_with_all.pem", expect_present = [ "X509Cert_Body_X509Exts_Ext_CRLDP_NoPointWithAllReasonBits", "X509Cert_Body_X509Exts_Ext_CRLDP_SegmentationUsed" ])

	def test_crldp_point_name_bad_dns(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_dns.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_DNS_Malformed")

	def test_crldp_point_name_bad_dns_single_label(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_dns_single_label.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_DNS_SingleLabel")

	def test_crldp_point_name_bad_dns_space(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_dns_space.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_DNS_OnlyWhitespace")

	def test_crldp_point_name_bad_email(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_email.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_Email_Malformed")

	def test_crldp_point_name_bad_ip(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_ip.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_IPAddress_Malformed")

	def test_crldp_point_name_bad_ip_private(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_ip_private.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_IPAddress_PrivateAddressSpace")

	def test_crldp_point_name_bad_uri(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_uri.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_Malformed")

	def test_crldp_point_name_bad_uri_ldap_no_attrspec(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_uri_ldap_no_attrspec.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_NoAttrdesc")

	def test_crldp_point_name_bad_uri_ldap_no_dn1(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_uri_ldap_no_dn1.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_NoDN")

	def test_crldp_point_name_bad_uri_ldap_no_dn2(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_uri_ldap_no_dn2.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_NoDN")

	def test_crldp_point_name_bad_uri_ldap_no_host(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_bad_uri_ldap_no_host.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_NoHostname")

	def test_crldp_point_invalid_ldap_dn1(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_invalid_ldap_dn1.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_MalformedDN")

	def test_crldp_point_invalid_ldap_dn2(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_invalid_ldap_dn2.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_MalformedDN")

	def test_crldp_point_invalid_ldap_dn3(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_invalid_ldap_dn3.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_MalformedDN")

	def test_crldp_point_valid_ldap_dn(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_valid_ldap_dn.pem", expect_absent = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_LDAP_MalformedDN")

	def test_crldp_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_Malformed_Undecodable")

	def test_crldp_point_rdn_used(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_rdn_used.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_RDN_Present")

	def test_crldp_point_rdn_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_rdn_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_RDN_Malformed")

	def test_crldp_point_rdn_ambiguous(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_rdn_ambiguous.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_RDN_Ambiguous")

	def test_crldp_point_name_empty_value(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_empty_value.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_Email_Malformed")

	def test_crldp_point_name_possibly_no_der_crl1(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_possibly_no_der_crl1.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_PossiblyNoDERCRLServed")

	def test_crldp_point_name_possibly_no_der_crl2(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_possibly_no_der_crl2.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_PossiblyNoDERCRLServed")

	def test_crldp_point_name_uncommon_identifier(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_uncommon_identifier.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_RegisteredID_Unexpected")

	def test_crldp_point_name_uncommon_uri_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_point_name_uncommon_uri_scheme.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_PointName_URI_UncommonURIScheme")

	def test_crldp_issuer_name_bad_email(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_issuer_name_bad_email.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_CRLIssuer_Email_Malformed")

	def test_crldp_issuer_name_bad_uri(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_issuer_name_bad_uri.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_CRLIssuer_URI_Malformed")

	def test_crldp_issuer_name_empty_value(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_issuer_name_empty_value.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_CRLIssuer_Email_Malformed")

	def test_crldp_issuer_name_uncommon_identifier(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_issuer_name_uncommon_identifier.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_CRLIssuer_RegisteredID_Unexpected")

	def test_crldp_issuer_name_uncommon_uri_scheme(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_issuer_name_uncommon_uri_scheme.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_CRLIssuer_URI_UncommonURIScheme")

	def test_crldp_issuer_redundantly_present(self):
		self._test_examine_x509test_resultcode("certs/constructed/crldp_issuer_redundantly_present.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CRLDP_CRLIssuer_Redundant")

	def test_ct_poison_invalid_payload(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_poison_invalid_payload.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTPP_InvalidPayload")

	def test_ct_poison_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_poison_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTPP_Malformed_Undecodable")

	def test_ct_poison_ok(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_poison_ok.pem", expect_absent = [ "X509Cert_Body_X509Exts_Ext_CTPP_Malformed_Undecodable", "X509Cert_Body_X509Exts_Ext_CTPP_InvalidPayload" ])

	def test_ct_poison_not_critical(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_poison_not_critical.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTPP_NotCritical")

	def test_ct_scts_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTSCT_Malformed_Undecodable")

	def test_ct_scts_ok(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_ok.pem", expect_absent = [ "X509Cert_Body_X509Exts_Ext_CTSCT_SCT_InvalidSignatureFunction", "X509Cert_Body_X509Exts_Ext_CTSCT_SCT_InvalidHashFunction", "X509Cert_Body_X509Exts_Ext_CTSCT_Malformed_Undecodable", "X509Cert_Body_X509Exts_Ext_CTSCT_Malformed_Content" ])

	def test_ct_scts_content_malformed(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_content_malformed.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTSCT_Malformed_Content")

	def test_ct_scts_hash_sha384(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_hash_sha384.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTSCT_SCT_InvalidHashFunction")

	def test_ct_scts_sig_ed25519(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_sig_ed25519.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTSCT_SCT_InvalidSignatureFunction")

	def test_ct_scts_sig_rsa(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_sig_rsa.pem", expect_absent = "X509Cert_Body_X509Exts_Ext_CTSCT_SCT_InvalidSignatureFunction")

	def test_ct_scts_timestamp_early(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_timestamp_early.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTSCT_SCT_ImplausibleTimestamp")

	def test_ct_scts_timestamp_late(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_timestamp_late.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTSCT_SCT_ImplausibleTimestamp")

	def test_ct_scts_version2(self):
		self._test_examine_x509test_resultcode("certs/constructed/ct_scts_version2.pem", expect_present = "X509Cert_Body_X509Exts_Ext_CTSCT_SCT_UnknownVersion")

	def test_bc_pathlen_but_no_ku(self):
		self._test_examine_x509test_resultcode("certs/constructed/bc_pathlen_but_no_ku.pem", expect_present = "X509Cert_Body_X509Exts_Ext_BC_PathLenWithoutKeyCertSign")
