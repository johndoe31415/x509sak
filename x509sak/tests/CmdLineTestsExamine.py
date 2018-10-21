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

import tempfile
import json
from x509sak.tests import BaseTest, ResourceFileLoader
from x509sak.SubprocessExecutor import SubprocessExecutor

class CmdLineTestsExamine(BaseTest):
	def test_crt_with_custom_key_usage(self):
		with ResourceFileLoader("certs/ok/custom_key_usage.pem") as certfile:
			output = SubprocessExecutor(self._x509sak + [ "examine", certfile ]).run().stdout
			self.assertIn(b"CN = 0b239049", output)
			self.assertIn(b"CN = \"Root CA\"", output)
			self.assertIn(b"ECC on prime256v1", output)

	def test_examine_write_json(self):
		with ResourceFileLoader("certs/ok/custom_key_usage.pem") as crtfile, tempfile.NamedTemporaryFile(prefix = "crt_", suffix = ".json") as jsonfile:
			SubprocessExecutor(self._x509sak + [ "examine", "-f", "json", "-o", jsonfile.name, crtfile ]).run()
			with open(jsonfile.name) as jsonfile:
				json_data = json.load(jsonfile)
			self.assertEqual(json_data["data"][0]["issuer"]["rfc2253"], "CN=Root CA")
			self.assertEqual(json_data["data"][0]["subject"]["rfc2253"], "CN=0b239049-3d65-46c2-8fdd-90f13cadc70b")
			self.assertEqual(json_data["data"][0]["validity"]["not_before"]["iso"], "2018-07-14T16:00:53Z")
			self.assertEqual(json_data["data"][0]["validity"]["not_after"]["iso"], "2019-07-14T16:00:53Z")

	def _get_codes(self, data, result = None):
		if result is None:
			result = set()
		if isinstance(data, list):
			for item in data:
				self._get_codes(item, result)
		elif isinstance(data, dict):
			if "code" in data:
				result.add(data["code"])
			for (key, value) in data.items():
				self._get_codes(value, result)
		return result

	def _test_examine_x509test_noparse(self, certname):
		with ResourceFileLoader(certname) as certfile:
			SubprocessExecutor(self._x509sak + [ "examine", "--fast-rsa", "-f", "json", "-o", "-", certfile ], success_return_codes = [ 1 ]).run()

	def _test_examine_x509test_resultcode(self, certname, expect_code):
		with ResourceFileLoader(certname) as certfile:
			result = SubprocessExecutor(self._x509sak + [ "examine", "--fast-rsa", "-f", "json", "-o", "-", certfile ]).run()
			stdout = result.stdout_text
			data = json.loads(stdout)
			codes = self._get_codes(data)
			self.assertIn(expect_code, codes)

	def test_examine_x509test_xf_algo_mismatch1(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-algo-mismatch1.pem", "Cert_Signature_Algorithm_Mismatch")

	def test_examine_x509test_xf_der_invalid_bitstring(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-bitstring.pem", "Cert_Invalid_DER")

	def test_examine_x509test_xf_der_invalid_nonminimal_int(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-nonminimal-int.pem", "Cert_Invalid_DER")

#	def test_examine_x509test_xf_der_invalid_uniqueid(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-der-invalid-uniqueid.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-der-invalid-uniqueid.pem")

	def test_examine_x509test_xf_der_pubkey_rsa_nonminimal_int(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-der-pubkey-rsa-nonminimal-int.pem", "Cert_Pubkey_Invalid_DER")

#	def test_examine_x509test_xf_duplicate_extension(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-duplicate-extension.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-duplicate-extension.pem")
#
#	def test_examine_x509test_xf_duplicate_extension2(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-duplicate-extension2.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-duplicate-extension2.pem")
#
#	def test_examine_x509test_xf_ext_altname_blank_domain(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-blank-domain.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-blank-domain.pem")
#
#	def test_examine_x509test_xf_ext_altname_critical_subject(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-critical-subject.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-critical-subject.pem")
#
#	def test_examine_x509test_xf_ext_altname_email_only(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-email-only.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-email-only.pem")
#
#	def test_examine_x509test_xf_ext_altname_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-empty.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-empty.pem")
#
#	def test_examine_x509test_xf_ext_altname_empty2(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-empty2.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-empty2.pem")
#
#	def test_examine_x509test_xf_ext_altname_invalid_domain(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-domain.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-invalid-domain.pem")
#
#	def test_examine_x509test_xf_ext_altname_invalid_email(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-email.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-invalid-email.pem")
#
#	def test_examine_x509test_xf_ext_altname_invalid_encoding(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-invalid-encoding.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-invalid-encoding.pem")

#	def test_examine_x509test_xf_ext_altname_ip_wrong(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-ip-wrong.pem", "Cert_X509Ext_SubjectAltName_BadIP")

#	def test_examine_x509test_xf_ext_altname_noncrit_nosubj(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-noncrit-nosubj.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-noncrit-nosubj.pem")
#
#	def test_examine_x509test_xf_ext_altname_relative_uri(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-relative-uri.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-relative-uri.pem")
#
#	def test_examine_x509test_xf_ext_altname_schemeless_uri(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-altname-schemeless-uri.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-altname-schemeless-uri.pem")
#
#	def test_examine_x509test_xf_ext_auth_info_critical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-info-critical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-auth-info-critical.pem")
#
#	def test_examine_x509test_xf_ext_auth_info_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-info-empty.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-auth-info-empty.pem")
#
#	def test_examine_x509test_xf_ext_auth_keyid_critical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-critical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-auth-keyid-critical.pem")
#
#	def test_examine_x509test_xf_ext_auth_keyid_invalid_issuer(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-invalid-issuer.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-auth-keyid-invalid-issuer.pem")
#
#	def test_examine_x509test_xf_ext_auth_keyid_mismatch(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-mismatch.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-auth-keyid-mismatch.pem")
#
#	def test_examine_x509test_xf_ext_auth_keyid_noid(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-noid.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-auth-keyid-noid.pem")
#
#	def test_examine_x509test_xf_ext_auth_keyid_onlyserial(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-onlyserial.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-auth-keyid-onlyserial.pem")
#
#	def test_examine_x509test_xf_ext_auth_keyid_serial_mismatch(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-serial-mismatch.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-auth-keyid-serial-mismatch.pem")
#
#	def test_examine_x509test_xf_ext_cert_policies_any_qual(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-any-qual.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-cert-policies-any-qual.pem")
#
#	def test_examine_x509test_xf_ext_cert_policies_bmp_unotice(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-bmp-unotice.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-cert-policies-bmp-unotice.pem")
#
#	def test_examine_x509test_xf_ext_cert_policies_dup(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-dup.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-cert-policies-dup.pem")
#
#	def test_examine_x509test_xf_ext_cert_policies_unotice_ch(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-cert-policies-unotice-ch.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-cert-policies-unotice-ch.pem")
#
#	def test_examine_x509test_xf_ext_constraints_neg_pathlen(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-neg-pathlen.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-constraints-neg-pathlen.pem")
#
#	def test_examine_x509test_xf_ext_constraints_noncritical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-noncritical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-constraints-noncritical.pem")
#
#	def test_examine_x509test_xf_ext_constraints_path_nonca(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-path-nonca.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-constraints-path-nonca.pem")
#
#	def test_examine_x509test_xf_ext_constraints_path_nosign(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-constraints-path-nosign.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-constraints-path-nosign.pem")
#
#	def test_examine_x509test_xf_ext_crl_point_critical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-crl-point-critical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-crl-point-critical.pem")
#
#	def test_examine_x509test_xf_ext_crl_point_reasons_only(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-crl-point-reasons-only.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-crl-point-reasons-only.pem")
#
#	def test_examine_x509test_xf_ext_ct_poison(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-poison.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-ct-poison.pem")
#
#	def test_examine_x509test_xf_ext_ct_sct_trailing_data(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-sct-trailing-data.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-ct-sct-trailing-data.pem")
#
#	def test_examine_x509test_xf_ext_ct_sct_wrong_type(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-ct-sct-wrong-type.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-ct-sct-wrong-type.pem")
#
#	def test_examine_x509test_xf_ext_extended_any_key_usage(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-any-key-usage.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-extended-any-key-usage.pem")
#
#	def test_examine_x509test_xf_ext_extended_key_usage_empty_oid(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-key-usage-empty-oid.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-extended-key-usage-empty-oid.pem")
#
#	def test_examine_x509test_xf_ext_extended_key_usage_empty(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-extended-key-usage-empty.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-extended-key-usage-empty.pem")
#
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
#
#	def test_examine_x509test_xf_ext_issuer_altname_critical(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-issuer-altname-critical.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-issuer-altname-critical.pem")

	def test_examine_x509test_xf_ext_key_usage_empty(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-empty.pem", "Cert_X509Ext_KeyUsage_Empty")

	def test_examine_x509test_xf_ext_key_usage_noncritical(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-noncritical.pem", "Cert_X509Ext_KeyUsage_NonCritical")

	def test_examine_x509test_xf_ext_key_usage_sign_nonca(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-sign-nonca.pem", "Cert_X509Ext_KeyUsage_SignCertNoCA")

	def test_examine_x509test_xf_ext_key_usage_too_long(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-too-long.pem", "Cert_X509Ext_KeyUsage_TooLong")

#	def test_examine_x509test_xf_ext_key_usage_wrong_der(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-key-usage-wrong-der.pem", "Cert_X509Ext_KeyUsage_InvalidDER")
#
#	def test_examine_x509test_xf_ext_keysign_nonca(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-keysign-nonca.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-ext-keysign-nonca.pem")

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
#
#	def test_examine_x509test_xf_issuer_mismatch_v2(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-issuer-mismatch-v2.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-issuer-mismatch-v2.pem")
#
#	def test_examine_x509test_xf_issuer_mismatch1(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-issuer-mismatch1.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-issuer-mismatch1.pem")
#
	def test_examine_x509test_xf_pubkey_ecdsa_not_on_curve(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-not-on-curve.pem", "ECC_Pubkey_Not_On_Curve")

#	def test_examine_x509test_xf_pubkey_ecdsa_secp192r1(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-secp192r1.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-pubkey-ecdsa-secp192r1.pem")
#
#	def test_examine_x509test_xf_pubkey_ecdsa_unknown_curve(self):
#		self._test_examine_x509test_resultcode("certs/x509test/xf-pubkey-ecdsa-unknown-curve.pem", "")
#		self._test_examine_x509test_noparse("certs/x509test/xf-pubkey-ecdsa-unknown-curve.pem")
#
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
		self._test_examine_x509test_resultcode("certs/x509test/xf-v3-uniqueid-noexts1.pem", "Cert_UniqueID_NotAllowed")

	def test_examine_x509test_xf_v3_uniqueid_noexts2(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-v3-uniqueid-noexts2.pem", "Cert_UniqueID_NotAllowed")
