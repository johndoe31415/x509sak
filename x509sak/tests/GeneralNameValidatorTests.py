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

	def _validate(self, name, inner, assert_length = None, assert_present = None):
		gn = self._create_general_name(name, inner)
		errors = {
			"email":						GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadEmail),
			"ip":							GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP),
			"ip_private":					GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP_Private),
			"uri":							GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadURI),
			"uri_invalid_scheme":			GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_UncommonURIScheme),
			"dnsname":						GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName),
			"dnsname_space":				GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName_Space),
			"dnsname_single_label":			GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName_SingleLabel),
			"dnsname_wc_notleftmost":		GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_NotLeftmost),
			"dnsname_wc_morethanone":		GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_MoreThanOneWildcard),
			"dnsname_wc_international":		GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_InternationalLabel),
			"dnsname_wc_broad":				GeneralNameValidator.Error(code = JudgementCode.Cert_X509Ext_SubjectAltName_BadWildcardDomain_BroadMatch),
		}
		result = GeneralNameValidator(gn, errors = errors).validate()
		if assert_length is not None:
			self.assertEqual(len(result), assert_length)
		if assert_present is not None:
			code_set = set(judgement.code for judgement in result)
			self.assertIn(assert_present, code_set)
		return result

	def test_email_ok(self):
		 self._validate("rfc822Name", "foo@bar.com", assert_length = 0)

	def test_email_bad(self):
		self._validate("rfc822Name", "foo @bar.com", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadEmail)

	def test_ipv4_ok(self):
		 self._validate("iPAddress", OctetString(bytes.fromhex("aa bb cc dd")), assert_length = 0)

	def test_ipv6_ok(self):
		 self._validate("iPAddress", OctetString(bytes(16)), assert_length = 0)

	def test_ip_bad(self):
		 self._validate("iPAddress", OctetString(bytes(2)), assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP)

	def test_ip_private_class_a(self):
		 self._validate("iPAddress", OctetString(bytes([ 10, 42, 117, 83 ])), assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP_Private)

	def test_ip_private_class_b(self):
		 self._validate("iPAddress", OctetString(bytes([ 172, 31, 12, 4 ])), assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP_Private)

	def test_ip_private_class_c(self):
		 self._validate("iPAddress", OctetString(bytes([ 192, 168, 17, 44 ])), assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP_Private)

	def test_ip_multicast(self):
		 self._validate("iPAddress", OctetString(bytes([ 239, 255, 255, 255 ])), assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP_Private)

	def test_ip_broadcast(self):
		 self._validate("iPAddress", OctetString(bytes([ 255, 255, 255, 255 ])), assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP_Private)

	def test_ip_loopback(self):
		 self._validate("iPAddress", OctetString(bytes([ 127, 255, 255, 255 ])), assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadIP_Private)

	def test_dnsname_ok(self):
		 self._validate("dNSName", "foobar.com", assert_length = 0)

	def test_dnsname_bad_single_label(self):
		 self._validate("dNSName", "com", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName_SingleLabel)

	def test_dnsname_bad_space(self):
		 self._validate("dNSName", " ", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName_Space)

	def test_dnsname_bad1(self):
		 self._validate("dNSName", "muh kuh.com", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName)

	def test_dnsname_bad2(self):
		 self._validate("dNSName", "muh\xffkuh.com", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName)

	def test_dnsname_bad3(self):
		 self._validate("dNSName", "muh\x00kuh.com", assert_present = JudgementCode.Cert_X509Ext_SubjectAltName_BadDNSName)
