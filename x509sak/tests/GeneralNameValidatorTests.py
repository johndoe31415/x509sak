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

from pyasn1_modules import rfc5280
from pyasn1.type.univ import OctetString
from x509sak.tests.BaseTest import BaseTest
from x509sak.estimate.GeneralNameValidator import GeneralNameValidator
from x509sak.estimate.Judgement import JudgementCode

class GeneralNameValidatorTests(BaseTest):
	def _create_general_name(self, name, inner):
		gn = rfc5280.GeneralName()
		gn[name] = gn.getComponentByName(name).clone(inner)
		return gn

	def _validate(self, name, inner, permissible_types = None, permissible_uri_schemes = None, assert_length = None, assert_present = None):
		gn = self._create_general_name(name, inner)
		errors = {
			"empty_value":					GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_EmptyValue),
			"email":						GeneralNameValidator.Error(code = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_Email_Malformed),
			"ip":							GeneralNameValidator.Error(code = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_Malformed),
			"ip_private":					GeneralNameValidator.Error(code = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_PrivateAddressSpace),
			"uri":							GeneralNameValidator.Error(code = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_URI_Malformed),
			"uri_invalid_scheme":			GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_UncommonURIScheme),
			"dnsname":						GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName),
			"dnsname_space":				GeneralNameValidator.Error(code = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_OnlyWhitespace),
			"dnsname_single_label":			GeneralNameValidator.Error(code = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_SingleLabel),
			"dnsname_wc_notleftmost":		GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_NotLeftmost),
			"dnsname_wc_morethanone":		GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_MoreThanOneWildcard),
			"dnsname_wc_international":		GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_InternationalLabel),
			"dnsname_wc_broad":				GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_BroadMatch),
			"invalid_type":					GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_UncommonIdentifier),
		}
		result = GeneralNameValidator(errors = errors, permissible_types = permissible_types, permissible_uri_schemes = permissible_uri_schemes).validate_asn1(gn)
		if assert_length is not None:
			self.assertEqual(len(result), assert_length)
		if assert_present is not None:
			code_set = set(judgement.code for judgement in result)
			self.assertIn(assert_present, code_set)
		return result

	def test_email_ok(self):
		self._validate("rfc822Name", "foo@bar.com", assert_length = 0)

	def test_email_bad(self):
		self._validate("rfc822Name", "foo @bar.com", assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_Email_Malformed)

	def test_ipv4_ok(self):
		self._validate("iPAddress", OctetString(bytes.fromhex("aa bb cc dd")), assert_length = 0)

	def test_ipv6_ok(self):
		self._validate("iPAddress", OctetString(bytes(16)), assert_length = 0)

	def test_ip_bad(self):
		self._validate("iPAddress", OctetString(bytes(2)), assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_Malformed)

	def test_ip_private_class_a(self):
		self._validate("iPAddress", OctetString(bytes([ 10, 42, 117, 83 ])), assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_PrivateAddressSpace)

	def test_ip_private_class_b(self):
		self._validate("iPAddress", OctetString(bytes([ 172, 31, 12, 4 ])), assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_PrivateAddressSpace)

	def test_ip_private_class_c(self):
		self._validate("iPAddress", OctetString(bytes([ 192, 168, 17, 44 ])), assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_PrivateAddressSpace)

	def test_ip_multicast(self):
		self._validate("iPAddress", OctetString(bytes([ 239, 255, 255, 255 ])), assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_PrivateAddressSpace)

	def test_ip_broadcast(self):
		self._validate("iPAddress", OctetString(bytes([ 255, 255, 255, 255 ])), assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_PrivateAddressSpace)

	def test_ip_loopback(self):
		self._validate("iPAddress", OctetString(bytes([ 127, 255, 255, 255 ])), assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_IPAddress_PrivateAddressSpace)

	def test_dnsname_ok(self):
		self._validate("dNSName", "foobar.com", assert_length = 0)

	def test_dnsname_single_label(self):
		self._validate("dNSName", "com", assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_SingleLabel)

	def test_dnsname_space(self):
		self._validate("dNSName", " ", assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_DNS_OnlyWhitespace)

	def test_dnsname_bad1(self):
		self._validate("dNSName", "muh kuh.com", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName)

	def test_dnsname_bad2(self):
		self._validate("dNSName", "muh\xffkuh.com", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName)

	def test_dnsname_bad3(self):
		self._validate("dNSName", "muh\x00kuh.com", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName)

	def test_dnsname_bad4(self):
		self._validate("dNSName", "", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName)

	def test_uri_ok(self):
		self._validate("uniformResourceIdentifier", "http://google.com", assert_length = 0)
		self._validate("uniformResourceIdentifier", "http://google.com/", assert_length = 0)
		self._validate("uniformResourceIdentifier", "http://google.com/foo.crt", assert_length = 0)

	def test_uri_bad1(self):
		self._validate("uniformResourceIdentifier", "http:/google.com/foo.crt", assert_present = ExperimentalJudgementCodes.X509Cert_Body_X509Exts_Ext_SAN_Name_URI_Malformed)

	def test_uri_bad2(self):
		self._validate("uniformResourceIdentifier", "ldap://google.com/foo.crt", permissible_uri_schemes = [ "http", "https", "ldap" ], assert_length = 0)
		self._validate("uniformResourceIdentifier", "ldap://google.com/foo.crt", permissible_uri_schemes = [ "http", "https" ], assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_UncommonURIScheme)

	def test_uncommon_identifier(self):
		self._validate("dNSName", "google.com", permissible_types = [ "rfc822Name" ], assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_UncommonIdentifier)
