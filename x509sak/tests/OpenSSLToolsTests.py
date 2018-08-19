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
from x509sak.tests import BaseTest
from x509sak.OpenSSLTools import OpenSSLTools
from x509sak.KeySpecification import KeySpecification, Cryptosystem
from x509sak.PrivateKeyStorage import PrivateKeyStorage, PrivateKeyStorageForm
from x509sak.SubprocessExecutor import SubprocessExecutor

class OpenSSLToolsTests(BaseTest):
	@staticmethod
	def _read_file(filename):
		with open(filename, "rb") as f:
			return f.read()

	def test_gen_privkey_rsa(self):
		input_output_data = [
			(
				{ "bitlen": 512 },
				b"512 bit",
			),
			(
				{ "bitlen": 600 },
				b"600 bit",
			),
		]

		for (input_data, output_data) in input_output_data:
			with tempfile.NamedTemporaryFile(prefix = "privkey_", suffix = ".pem") as f:
				OpenSSLTools.create_private_key(PrivateKeyStorage(storage_form = PrivateKeyStorageForm.PEM_FILE, filename = f.name), keyspec = KeySpecification(cryptosystem = Cryptosystem.RSA, parameters = input_data))
				content = self._read_file(f.name)
				self.assertIn(b"BEGIN RSA PRIVATE KEY", content)
				self.assertIn(b"END RSA PRIVATE KEY", content)
				output = SubprocessExecutor([ "openssl", "rsa", "-text" ], stdin = content).run().stdout
				self.assertIn(output_data, output)

	def test_gen_privkey_ecc(self):
		input_output_data = [
			(
				{ "curve": "secp384r1" },
				(b"384 bit", b"secp384r1"),
			),
			(
				{ "curve": "secp256r1" },
				(b"256 bit", b"prime256v1"),
			),
		]

		for (input_data, output_data) in input_output_data:
			with tempfile.NamedTemporaryFile(prefix = "privkey_", suffix = ".pem") as f:
				OpenSSLTools.create_private_key(PrivateKeyStorage(storage_form = PrivateKeyStorageForm.PEM_FILE, filename = f.name), keyspec = KeySpecification(cryptosystem = Cryptosystem.ECC, parameters = input_data))
				content = self._read_file(f.name)
				self.assertNotIn(b"BEGIN EC PARAMETERS", content)
				self.assertNotIn(b"END EC PARAMETERS", content)
				self.assertIn(b"BEGIN EC PRIVATE KEY", content)
				self.assertIn(b"END EC PRIVATE KEY", content)
				output = SubprocessExecutor([ "openssl", "ec", "-text" ], stdin = content).run().stdout
				self.assertIn(output_data[0], output)
				self.assertIn(output_data[1], output)

	def test_gen_csr(self):
		with tempfile.NamedTemporaryFile(prefix = "privkey_", suffix = ".pem") as privkey_file, tempfile.NamedTemporaryFile(prefix = "csr_", suffix = ".pem") as csr_file:
			OpenSSLTools.create_private_key(PrivateKeyStorage(storage_form = PrivateKeyStorageForm.PEM_FILE, filename = privkey_file.name), keyspec = KeySpecification(cryptosystem = Cryptosystem.ECC, parameters = { "curve": "secp256r1" }))
			private_key_storage = PrivateKeyStorage(storage_form = PrivateKeyStorageForm.PEM_FILE, filename = privkey_file.name)

			OpenSSLTools.create_csr(private_key_storage = private_key_storage, csr_filename = csr_file.name, subject_dn = "/CN=Foobar")
			output = SubprocessExecutor([ "openssl", "req", "-text" ], stdin = self._read_file(csr_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE REQUEST", output)
			self.assertIn(b"END CERTIFICATE REQUEST", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertNotIn(b"Requested Extensions:", output)

			OpenSSLTools.create_csr(private_key_storage = private_key_storage, csr_filename = csr_file.name, subject_dn = "/CN=Foobar", subject_alternative_dns_names = [ "muhkuh" ])
			output = SubprocessExecutor([ "openssl", "req", "-text" ], stdin = self._read_file(csr_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE REQUEST", output)
			self.assertIn(b"END CERTIFICATE REQUEST", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertIn(b"Requested Extensions:", output)
			self.assertIn(b"X509v3 Subject Alternative Name:", output)
			self.assertIn(b"DNS:muhkuh", output)

			OpenSSLTools.create_csr(private_key_storage = private_key_storage, csr_filename = csr_file.name, subject_dn = "/CN=Foobar", subject_alternative_dns_names = [ "muhkuh", "kruckelmuckel" ])
			output = SubprocessExecutor([ "openssl", "req", "-text" ], stdin = self._read_file(csr_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE REQUEST", output)
			self.assertIn(b"END CERTIFICATE REQUEST", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertIn(b"Requested Extensions:", output)
			self.assertIn(b"X509v3 Subject Alternative Name:", output)
			self.assertIn(b"DNS:muhkuh", output)
			self.assertIn(b"DNS:kruckelmuckel", output)

			OpenSSLTools.create_csr(private_key_storage = private_key_storage, csr_filename = csr_file.name, subject_dn = "/CN=Foobar", subject_alternative_dns_names = [ "muhkuh", "kruckelmuckel" ], subject_alternative_ip_addresses = [ "11.22.33.44", "99.88.77.66", "abcd::9876" ])
			output = SubprocessExecutor([ "openssl", "req", "-text" ], stdin = self._read_file(csr_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE REQUEST", output)
			self.assertIn(b"END CERTIFICATE REQUEST", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertIn(b"Requested Extensions:", output)
			self.assertIn(b"X509v3 Subject Alternative Name:", output)
			self.assertIn(b"DNS:muhkuh", output)
			self.assertIn(b"DNS:kruckelmuckel", output)
			self.assertIn(b"IP Address:11.22.33.44", output)
			self.assertIn(b"IP Address:99.88.77.66", output)
			self.assertIn(b"IP Address:ABCD:0:0:0:0:0:0:9876", output)

			OpenSSLTools.create_csr(private_key_storage = private_key_storage, csr_filename = csr_file.name, subject_dn = "/CN=Foobar", subject_alternative_dns_names = [ "muhkuh", "kruckelmuckel" ], subject_alternative_ip_addresses = [ "11.22.33.44", "99.88.77.66", "abcd::9876" ], x509_extensions = { "2.3.4.5.6.7": "ASN1:UTF8String:Never gonna give you up" })
			output = SubprocessExecutor([ "openssl", "req", "-text" ], stdin = self._read_file(csr_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE REQUEST", output)
			self.assertIn(b"END CERTIFICATE REQUEST", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertIn(b"Requested Extensions:", output)
			self.assertIn(b"X509v3 Subject Alternative Name:", output)
			self.assertIn(b"DNS:muhkuh", output)
			self.assertIn(b"DNS:kruckelmuckel", output)
			self.assertIn(b"IP Address:11.22.33.44", output)
			self.assertIn(b"IP Address:99.88.77.66", output)
			self.assertIn(b"IP Address:ABCD:0:0:0:0:0:0:9876", output)
			self.assertIn(b"Never gonna give you up", output)

	def test_gen_selfsigned_cert(self):
		with tempfile.NamedTemporaryFile(prefix = "privkey_", suffix = ".pem") as privkey_file, tempfile.NamedTemporaryFile(prefix = "crt_", suffix = ".pem") as certificate_file:
			OpenSSLTools.create_private_key(PrivateKeyStorage(storage_form = PrivateKeyStorageForm.PEM_FILE, filename = privkey_file.name), keyspec = KeySpecification(cryptosystem = Cryptosystem.ECC, parameters = { "curve": "secp256r1" }))
			private_key_storage = PrivateKeyStorage(storage_form = PrivateKeyStorageForm.PEM_FILE, filename = privkey_file.name)

			OpenSSLTools.create_selfsigned_certificate(private_key_storage = private_key_storage, certificate_filename = certificate_file.name, subject_dn = "/CN=Foobar", validity_days = 365)
			output = SubprocessExecutor([ "openssl", "x509", "-text" ], stdin = self._read_file(certificate_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE--", output)
			self.assertIn(b"END CERTIFICATE--", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertNotIn(b"X509v3 extensions:", output)

			OpenSSLTools.create_selfsigned_certificate(private_key_storage = private_key_storage, certificate_filename = certificate_file.name, subject_dn = "/CN=Foobar", subject_alternative_dns_names = [ "muhkuh" ], validity_days = 365)
			output = SubprocessExecutor([ "openssl", "x509", "-text" ], stdin = self._read_file(certificate_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE--", output)
			self.assertIn(b"END CERTIFICATE--", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertIn(b"X509v3 extensions:", output)
			self.assertIn(b"X509v3 Subject Alternative Name:", output)
			self.assertIn(b"DNS:muhkuh", output)

			OpenSSLTools.create_selfsigned_certificate(private_key_storage = private_key_storage, certificate_filename = certificate_file.name, subject_dn = "/CN=Foobar", subject_alternative_dns_names = [ "muhkuh", "kruckelmuckel" ], validity_days = 365)
			output = SubprocessExecutor([ "openssl", "x509", "-text" ], stdin = self._read_file(certificate_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE--", output)
			self.assertIn(b"END CERTIFICATE--", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertIn(b"X509v3 extensions:", output)
			self.assertIn(b"X509v3 Subject Alternative Name:", output)
			self.assertIn(b"DNS:muhkuh", output)
			self.assertIn(b"DNS:kruckelmuckel", output)

			OpenSSLTools.create_selfsigned_certificate(private_key_storage = private_key_storage, certificate_filename = certificate_file.name, subject_dn = "/CN=Foobar", subject_alternative_dns_names = [ "muhkuh", "kruckelmuckel" ], subject_alternative_ip_addresses = [ "11.22.33.44", "99.88.77.66", "abcd::9876" ], validity_days = 365)
			output = SubprocessExecutor([ "openssl", "x509", "-text" ], stdin = self._read_file(certificate_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE--", output)
			self.assertIn(b"END CERTIFICATE--", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertIn(b"X509v3 extensions:", output)
			self.assertIn(b"X509v3 Subject Alternative Name:", output)
			self.assertIn(b"DNS:muhkuh", output)
			self.assertIn(b"DNS:kruckelmuckel", output)
			self.assertIn(b"IP Address:11.22.33.44", output)
			self.assertIn(b"IP Address:99.88.77.66", output)
			self.assertIn(b"IP Address:ABCD:0:0:0:0:0:0:9876", output)

			OpenSSLTools.create_selfsigned_certificate(private_key_storage = private_key_storage, certificate_filename = certificate_file.name, subject_dn = "/CN=Foobar", subject_alternative_dns_names = [ "muhkuh", "kruckelmuckel" ], subject_alternative_ip_addresses = [ "11.22.33.44", "99.88.77.66", "abcd::9876" ], x509_extensions = { "2.3.4.5.6.7": "ASN1:UTF8String:Never gonna give you up" }, validity_days = 365)
			output = SubprocessExecutor([ "openssl", "x509", "-text" ], stdin = self._read_file(certificate_file.name)).run().stdout
			self.assertIn(b"BEGIN CERTIFICATE--", output)
			self.assertIn(b"END CERTIFICATE--", output)
			self.assertTrue((b"Subject: CN = Foobar" in output) or (b"Subject: CN=Foobar" in output))
			self.assertIn(b"X509v3 extensions:", output)
			self.assertIn(b"X509v3 Subject Alternative Name:", output)
			self.assertIn(b"DNS:muhkuh", output)
			self.assertIn(b"DNS:kruckelmuckel", output)
			self.assertIn(b"IP Address:11.22.33.44", output)
			self.assertIn(b"IP Address:99.88.77.66", output)
			self.assertIn(b"IP Address:ABCD:0:0:0:0:0:0:9876", output)
			self.assertIn(b"Never gonna give you up", output)
