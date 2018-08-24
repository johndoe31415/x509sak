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

import os
import pkgutil
import datetime
from x509sak.tests import BaseTest
from x509sak import X509Certificate
from x509sak.X509Certificate import X509CertificateClass
from x509sak.OID import OIDDB

class X509CertificateTests(BaseTest):
	def test_pem_load(self):
		x509_text = pkgutil.get_data("x509sak.tests.data", "certs/ok/johannes-bauer.com.pem").decode("ascii")
		cert = X509Certificate.from_pem_data(x509_text)
		self.assertEqual(len(cert), 1)
		cert = cert[0]
		self.assertEqual(cert.to_pem_data() + "\n", x509_text)

	def test_crt_equality(self):
		cert1 = self._load_crt("ok/johannes-bauer.com")
		cert2 = self._load_crt("ok/johannes-bauer.com")
		self.assertEqual(cert1, cert2)

	def test_distinguished_names(self):
		cert = self._load_crt("ok/johannes-bauer-intermediate")
		self.assertEqual(cert.issuer.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")
		self.assertEqual(cert.subject.rfc2253_str, "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")

		cert = self._load_crt("ok/johannes-bauer-root")
		self.assertEqual(cert.subject, cert.issuer)
		self.assertFalse(cert.subject != cert.issuer)

	def test_load_system_certs(self):
		dirname = "/etc/ssl/certs/"
		for filename in os.listdir(dirname):
			if filename.endswith(".pem"):
				fullfilename = dirname + filename
				cert = X509Certificate.read_pemfile(fullfilename)[0]
				_ = cert.issuer.rfc2253_str + cert.subject.rfc2253_str

	def test_crt_dates(self):
		cert = self._load_crt("ok/johannes-bauer-intermediate")
		self.assertEqual(cert.valid_not_before, datetime.datetime(2016, 3, 17, 16, 40, 46))
		self.assertEqual(cert.valid_not_after, datetime.datetime(2021, 3, 17, 16, 40, 46))

	def test_extension_get(self):
		cert = self._load_crt("ok/johannes-bauer.com")
		exts = cert.get_extensions()
		self.assertEqual(len(exts), 9)

	def test_extension_has(self):
		cert = self._load_crt("ok/johannes-bauer.com")
		exts = cert.get_extensions()
		self.assertTrue(exts.has(OIDDB.X509Extensions.inverse("ExtendedKeyUsage")))
		self.assertTrue(exts.has(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier")))
		self.assertFalse(exts.has(OIDDB.X509Extensions.inverse("CertSRVCAVersion")))
		self.assertEqual(len(exts), 9)
		exts.remove_all(OIDDB.X509Extensions.inverse("ExtendedKeyUsage"))
		self.assertEqual(len(exts), 8)
		exts.remove_all(OIDDB.X509Extensions.inverse("CertSRVCAVersion"))
		self.assertEqual(len(exts), 8)

	def test_extension_ski(self):
		cert = self._load_crt("ok/johannes-bauer.com")
		exts = cert.get_extensions()
		ext = exts.get_first(OIDDB.X509Extensions.inverse("CertSRVCAVersion"))
		self.assertIsNone(ext)
		ext = exts.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
		self.assertIsNotNone(ext)
		self.assertEqual(ext.keyid, bytes.fromhex("1A4AB011B05CFA57FB49028765169337F78D8EE6"))

	def test_extension_aki(self):
		cert = self._load_crt("ok/johannes-bauer.com")
		exts = cert.get_extensions()
		ext = exts.get_first(OIDDB.X509Extensions.inverse("AuthorityKeyIdentifier"))
		self.assertIsNotNone(ext)
		self.assertEqual(ext.keyid, bytes.fromhex("A84A6A63047DDDBAE6D139B7A64565EFF3A8ECA1"))

	def test_cert_sign_chain(self):
		cert = self._load_crt("ok/johannes-bauer.com")
		ca_cert = self._load_crt("ok/johannes-bauer-intermediate")
		self.assertTrue(cert.signed_by(ca_cert, verbose_failure = True))

	def test_certtype(self):
		self.assertTrue(self._load_crt("ok/johannes-bauer-root").is_ca_certificate)
		self.assertTrue(self._load_crt("ok/johannes-bauer-intermediate").is_ca_certificate)
		self.assertFalse(self._load_crt("ok/johannes-bauer.com").is_ca_certificate)
		self.assertTrue(self._load_crt("ok/custom_key_usage").is_ca_certificate)
		self.assertTrue(self._load_crt("broken/keycomp_debian").is_ca_certificate)
		self.assertTrue(self._load_crt("ok/no_extensions").is_ca_certificate)

	def test_selfsigned(self):
		self.assertTrue(self._load_crt("ok/johannes-bauer-root").is_selfsigned)
		self.assertFalse(self._load_crt("ok/johannes-bauer-intermediate").is_selfsigned)
		self.assertFalse(self._load_crt("ok/johannes-bauer.com").is_selfsigned)

	def test_classification(self):
		self.assertEqual(self._load_crt("ok/johannes-bauer-root").classify(), X509CertificateClass.CARoot)
		self.assertEqual(self._load_crt("ok/johannes-bauer-intermediate").classify(), X509CertificateClass.CAIntermediate)
		self.assertEqual(self._load_crt("ok/johannes-bauer.com").classify(), X509CertificateClass.ClientServerAuth)

	def test_crt_get_pubkey(self):
		x509 = self._load_crt("ok/johannes-bauer.com")
		self.assertEqual(str(x509.pubkey), "PublicKey<ECC-secp384r1>")
