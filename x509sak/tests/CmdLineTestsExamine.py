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

import tempfile
import json
from x509sak.tests import BaseTest, ResourceFileLoader
from x509sak.CertificateAnalyzer import CertificateAnalyzer

class CmdLineTestsExamine(BaseTest):
	def test_crt_with_custom_key_usage(self):
		with ResourceFileLoader("certs/ok/custom_key_usage.pem") as certfile:
			output = self._run_x509sak([ "examine", certfile ]).stdout
			self.assertIn(b"CN = 0b239049", output)
			self.assertIn(b"CN = \"Root CA\"", output)
			self.assertIn(b"ECC on prime256v1", output)

	def test_examine_write_json(self):
		with ResourceFileLoader("certs/ok/custom_key_usage.pem") as crtfile, tempfile.NamedTemporaryFile(prefix = "crt_", suffix = ".json") as jsonfile:
			self._run_x509sak([ "examine", "-f", "json", "-o", jsonfile.name, crtfile ])
			with open(jsonfile.name) as jsonfile:
				json_data = json.load(jsonfile)
			self.assertEqual(json_data["data"][0]["issuer"]["rfc2253"], "CN=Root CA")
			self.assertEqual(json_data["data"][0]["subject"]["rfc2253"], "CN=0b239049-3d65-46c2-8fdd-90f13cadc70b")
			self.assertEqual(json_data["data"][0]["validity"]["not_before"]["iso"], "2018-07-14T16:00:53Z")
			self.assertEqual(json_data["data"][0]["validity"]["not_after"]["iso"], "2019-07-14T16:00:53Z")

	def test_purpose_ca(self):
		with ResourceFileLoader("certs/ok/johannes-bauer-root.pem") as crtfile:
			self._run_x509sak([ "examine", "-p", "ca", "--fast-rsa", crtfile ])

	def test_purpose_tls_server(self):
		with ResourceFileLoader("certs/ok/johannes-bauer.com.pem") as crtfile:
			output = self._run_x509sak([ "examine", "-p", "tls-server", "-n", "johannes-bauer.com", crtfile ]).stdout_text
			self.assertIn("Subject Alternative Name matches 'johannes-bauer.com'", output)

	def test_encodings(self):
		with ResourceFileLoader("certs/ok/johannes-bauer-intermediate.pem") as crtfile:
			self._run_x509sak([ "examine", "-p", "ca", "--fast-rsa", "-f", "ansitext", crtfile ])
			self._run_x509sak([ "examine", "-p", "ca", "--fast-rsa", "-f", "text", crtfile ])
			self._run_x509sak([ "examine", "-p", "ca", "--fast-rsa", "-f", "json", crtfile ])

	def test_rsa_pss_default(self):
		with ResourceFileLoader("certs/ok/rsapss_defaults.pem") as crtfile:
			self._run_x509sak([ "examine", "-p", "tls-client", "--fast-rsa", "-f", "json", crtfile ]).stdout_json

	def test_rsa_pss_custom(self):
		with ResourceFileLoader("certs/ok/rsapss_sha256_salt_32.pem") as crtfile:
			self._run_x509sak([ "examine", "-p", "tls-client", "--fast-rsa", "-f", "json", crtfile ]).stdout_json

	def _test_examine_x509test_resultcode(self, certname, expect_present = None, expect_absent = None, parent_certname = None, fast_rsa = True, host_check = None, include_raw = False, purpose = None):
		if expect_present is None:
			expect_present = tuple()
		if not isinstance(expect_present, (list, tuple)):
			expect_present = (expect_present, )

		if expect_absent is None:
			expect_absent = tuple()
		if not isinstance(expect_absent, (list, tuple)):
			expect_absent = (expect_absent, )

		def gen_cmdline(fast_rsa, host_check, include_raw, certfile_name, cacertfile_name, outfile_name, outformat = "json"):
			cmdline = [ "examine" ]
			if fast_rsa:
				cmdline += [ "--fast-rsa" ]
			cmdline += [ "-f", outformat ]
			cmdline += [ "-o", outfile_name ]
			if cacertfile_name is not None:
				cmdline += [ "--parent-certificate", cacertfile_name ]
			if host_check is not None:
				cmdline += [ "-p", "tls-server", "--server-name", host_check ]
			elif purpose is not None:
				cmdline += [ "-p", purpose ]

			if include_raw:
				cmdline += [ "--include-raw-data" ]
			cmdline += [ certfile_name ]
			return cmdline

		with ResourceFileLoader(certname) as certfile, tempfile.NamedTemporaryFile(suffix = ".json") as outfile:
			if parent_certname is None:
				cmdline = gen_cmdline(fast_rsa, host_check, include_raw, certfile_name = certfile, cacertfile_name = None, outfile_name = outfile.name, outformat = "ansitext")
				self._run_x509sak(cmdline)
				cmdline = gen_cmdline(fast_rsa, host_check, include_raw, certfile_name = certfile, cacertfile_name = None, outfile_name = outfile.name, outformat = "json")
				self._run_x509sak(cmdline)
			else:
				with ResourceFileLoader(parent_certname) as parent_crt:
					cmdline = gen_cmdline(fast_rsa, host_check, include_raw, certfile_name = certfile, cacertfile_name = parent_crt, outfile_name = outfile.name, outformat = "ansitext")
					self._run_x509sak(cmdline)
					cmdline = gen_cmdline(fast_rsa, host_check, include_raw, certfile_name = certfile, cacertfile_name = parent_crt, outfile_name = outfile.name, outformat = "json")
					self._run_x509sak(cmdline)

			# Read all codes from the generated JSON
			with open(outfile.name) as f:
				data = json.load(f)
			encountered_codes = CertificateAnalyzer.extract_codes_from_json(data)

			for code in expect_present:
				self.assertIn(code, encountered_codes)
			for code in expect_absent:
				self.assertNotIn(code, encountered_codes)

	def test_examine_x509test_xf_algo_mismatch1(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-algo-mismatch1.pem", "Cert_Signature_Algorithm_Mismatch")

	def test_examine_x509test_xf_ext_auth_keyid_mismatch(self):
		self._test_examine_x509test_resultcode("certs/x509test/xf-ext-auth-keyid-mismatch.pem", "Cert_X509Ext_AuthorityKeyIdentifier_CA_KeyIDMismatch", parent_certname = "certs/x509test/ok-ca.pem")

	def test_hostname_ok(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", "Cert_SAN_Match", expect_absent = "Cert_SAN_NoMatch", host_check = "mail.johannes-bauer.com")

	def test_constructed_rsa_modulus_prime(self):
		self._test_examine_x509test_resultcode("certs/constructed/rsa_modulus_prime.pem", "Crypto_AsymCryptoSys_RSA_Modulus_Prime", fast_rsa = False)

	def test_include_raw_data_ecc_f2m(self):
		self._test_examine_x509test_resultcode("certs/ok/ecc_sect283r1.pem", include_raw = True)

	def test_check_no_ca_when_expecting_ca(self):
		self._test_examine_x509test_resultcode("certs/ok/johannes-bauer.com.pem", expect_present = "Cert_Unexpectedly_No_CA_Cert", purpose = "ca")
