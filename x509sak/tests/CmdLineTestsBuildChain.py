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
from x509sak.WorkDir import WorkDir
from x509sak.tests import BaseTest, ResourceFileLoader
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.X509Certificate import X509Certificate

class CmdLineTestsBuildChain(BaseTest):
	def test_root_only_out_default(self):
		with ResourceFileLoader("certs/ok/johannes-bauer-root.pem") as certfile:
			output = SubprocessExecutor(self._x509sak + [ "buildchain", certfile ]).run().stdout
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output)
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_root_notrust(self):
		with ResourceFileLoader("certs/ok/johannes-bauer-root.pem") as certfile:
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "--dont-trust-crtfile", certfile ]).run().stdout
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output)
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_interm_root_notrust(self):
		with ResourceFileLoader("certs/ok/johannes-bauer-intermediate.pem") as certfile:
			SubprocessExecutor(self._x509sak + [ "buildchain", certfile ], success_return_codes = [ 1 ]).run()
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "--allow-partial-chain", certfile ]).run().stdout
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output)
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")

		with ResourceFileLoader([ "certs/ok/johannes-bauer-root.pem" ], "certs/ok/johannes-bauer-intermediate.pem") as (searchdir, certfile):
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, certfile ]).run().stdout
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 2)
		crts = X509Certificate.from_pem_data(output.decode("ascii"))
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")
		self.assertEqual(crts[1].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")

	def test_der_input(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			crt = self._load_crt("ok/johannes-bauer-root")
			crt.write_derfile("root.der")
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "--inform", "der", "root.der" ]).run().stdout
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
			crts = X509Certificate.from_pem_data(output.decode("ascii"))
			self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_root_only_out_rootonly(self):
		with ResourceFileLoader([ "certs/ok/johannes-bauer-root.pem", "certs/ok/johannes-bauer-intermediate.pem" ], "certs/ok/johannes-bauer.com.pem") as (searchdir, certfile):
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, "--outform", "rootonly", certfile ]).run().stdout
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output.decode("ascii"))
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_intermediate(self):
		with ResourceFileLoader([ "certs/ok/johannes-bauer-root.pem", "certs/ok/johannes-bauer-intermediate.pem" ], "certs/ok/johannes-bauer.com.pem") as (searchdir, certfile):
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, "--outform", "intermediates", certfile ]).run().stdout
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output.decode("ascii"))
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")

	def test_all_except_root(self):
		with ResourceFileLoader([ "certs/ok/johannes-bauer-root.pem", "certs/ok/johannes-bauer-intermediate.pem" ], "certs/ok/johannes-bauer.com.pem") as (searchdir, certfile):
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, "--outform", "all-except-root", certfile ]).run().stdout
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 2)
		crts = X509Certificate.from_pem_data(output.decode("ascii"))
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")
		self.assertEqual(crts[1].subject.rfc2253_str, "CN=johannes-bauer.com")

	def test_all_except_root_stdout(self):
		with tempfile.NamedTemporaryFile(prefix = "chain_", suffix = ".pem") as outfile, ResourceFileLoader([ "certs/ok/johannes-bauer-root.pem", "certs/ok/johannes-bauer-intermediate.pem" ], "certs/ok/johannes-bauer.com.pem") as (searchdir, certfile):
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, "--outform", "all-except-root", "--outfile", outfile.name, certfile ]).run().stdout
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 0)
			crts = X509Certificate.read_pemfile(outfile.name)
			self.assertEqual(crts[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")
			self.assertEqual(crts[1].subject.rfc2253_str, "CN=johannes-bauer.com")

	def test_multifile_all_except_root(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir), ResourceFileLoader([ "certs/ok/johannes-bauer-root.pem", "certs/ok/johannes-bauer-intermediate.pem" ], "certs/ok/johannes-bauer.com.pem") as (searchdir, certfile):
			SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, "--outform", "multifile", "--outfile", "outcrt%02d.pem", certfile ]).run()
			self.assertEqual(X509Certificate.read_pemfile("outcrt00.pem")[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")
			self.assertEqual(X509Certificate.read_pemfile("outcrt01.pem")[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")
			self.assertEqual(X509Certificate.read_pemfile("outcrt02.pem")[0].subject.rfc2253_str, "CN=johannes-bauer.com")

			SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, "--outform", "multifile", "--order-leaf-to-root", "--outfile", "rev_outcrt%02d.pem", certfile ]).run()
			self.assertEqual(X509Certificate.read_pemfile("rev_outcrt00.pem")[0].subject.rfc2253_str, "CN=johannes-bauer.com")
			self.assertEqual(X509Certificate.read_pemfile("rev_outcrt01.pem")[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")
			self.assertEqual(X509Certificate.read_pemfile("rev_outcrt02.pem")[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_pkcs12(self):
		with tempfile.NamedTemporaryFile(suffix = ".p12") as p12file, ResourceFileLoader([ "certs/ok/johannes-bauer-root.pem", "certs/ok/johannes-bauer-intermediate.pem" ], "certs/ok/johannes-bauer.com.pem") as (searchdir, certfile):
			SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, "--outform", "pkcs12", "--outfile", p12file.name, certfile ]).run()
			output = SubprocessExecutor([ "openssl", "pkcs12", "-in", p12file.name, "-passin", "pass:" ]).run().stdout
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 3)

	def test_cmd_errors(self):
		SubprocessExecutor(self._x509sak + [ "buildchain", "--private-key", "foo.key", "x509sak/tests/data/johannes-bauer-root.crt" ], success_return_codes = [ 1 ]).run()
		SubprocessExecutor(self._x509sak + [ "buildchain", "--pkcs12-legacy-crypto", "x509sak/tests/data/johannes-bauer-root.crt" ], success_return_codes = [ 1 ]).run()
		SubprocessExecutor(self._x509sak + [ "buildchain", "--pkcs12-no-passphrase", "x509sak/tests/data/johannes-bauer-root.crt" ], success_return_codes = [ 1 ]).run()
		SubprocessExecutor(self._x509sak + [ "buildchain", "--pkcs12-passphrase-file", "pass.txt", "x509sak/tests/data/johannes-bauer-root.crt" ], success_return_codes = [ 1 ]).run()
		SubprocessExecutor(self._x509sak + [ "buildchain", "--outform", "pkcs12", "--pkcs12-passphrase-file", "pass.txt", "x509sak/tests/data/johannes-bauer-root.crt" ], success_return_codes = [ 1 ]).run()
		SubprocessExecutor(self._x509sak + [ "buildchain", "--outform", "pkcs12", "--pkcs12-legacy-crypto", "pass.txt", "x509sak/tests/data/johannes-bauer-root.crt" ], success_return_codes = [ 1 ]).run()

	def test_cmd_no_root_found(self):
		SubprocessExecutor(self._x509sak + [ "buildchain", "--allow-partial-chain", "--outform", "rootonly", "x509sak/tests/data/johannes-bauer-intermediate.crt" ], success_return_codes = [ 1 ]).run()

	def test_pkcs12_stdout(self):
		with ResourceFileLoader([ "certs/ok/johannes-bauer-root.pem", "certs/ok/johannes-bauer-intermediate.pem" ], "certs/ok/johannes-bauer.com.pem") as (searchdir, certfile):
			pkcs12 =  SubprocessExecutor(self._x509sak + [ "buildchain", "-s", searchdir, "--outform", "pkcs12", certfile ]).run().stdout
			output = SubprocessExecutor([ "openssl", "pkcs12", "-passin", "pass:" ], stdin = pkcs12).run().stdout
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 3)

	def test_pkcs12_passphrase_specify(self):
		with tempfile.NamedTemporaryFile(mode = "w", suffix = ".txt") as passfile, ResourceFileLoader("certs/ok/ecc_secp256r1.pem", "privkey/ok/ecc_secp256r1.pem") as (certfile, keyfile):
			print("foobar", file = passfile)
			passfile.flush()
			pkcs12 =  SubprocessExecutor(self._x509sak + [ "buildchain", "--outform", "pkcs12", "--private-key", keyfile, "--pkcs12-passphrase-file", passfile.name, certfile ]).run().stdout

			# Fails with wrong passphrase
			SubprocessExecutor([ "openssl", "pkcs12", "-passin", "-nodes", "pass:" ], stdin = pkcs12, success_return_codes = [ 1 ]).run()
			SubprocessExecutor([ "openssl", "pkcs12", "-passin", "-nodes", "pass:abcdef" ], stdin = pkcs12, success_return_codes = [ 1 ]).run()

			# Works with right passphrase
			output = SubprocessExecutor([ "openssl", "pkcs12", "-nodes", "-passin", "pass:foobar" ], stdin = pkcs12).run().stdout
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
			self.assertOcurrences(output, b"-----BEGIN PRIVATE KEY-----", 1)

	def test_pkcs12_passphrase_autogen(self):
		with ResourceFileLoader("certs/ok/ecc_secp256r1.pem", "privkey/ok/ecc_secp256r1.pem") as (certfile, keyfile):
			result = SubprocessExecutor(self._x509sak + [ "buildchain", "--outform", "pkcs12", "--private-key", keyfile, certfile ]).run()

			pkcs12 = result.stdout
			stderr = result.stderr_text.rstrip("\r\n")
			self.assertTrue(stderr.startswith("Passphrase: "))
			passphrase = stderr[12:]

			# Fails with wrong passphrase
			SubprocessExecutor([ "openssl", "pkcs12", "-passin", "-nodes", "pass:" ], stdin = pkcs12, success_return_codes = [ 1 ]).run()
			SubprocessExecutor([ "openssl", "pkcs12", "-passin", "-nodes", "pass:abcdef" ], stdin = pkcs12, success_return_codes = [ 1 ]).run()

			# Works with right passphrase
			output = SubprocessExecutor([ "openssl", "pkcs12", "-nodes", "-passin", "pass:" + passphrase ], stdin = pkcs12).run().stdout
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
			self.assertOcurrences(output, b"-----BEGIN PRIVATE KEY-----", 1)

	def test_multi_intermediate(self):
		with ResourceFileLoader("certs/ok/multi_intermediate/root.crt", "certs/ok/multi_intermediate/interm1.crt", "certs/ok/multi_intermediate/interm2.crt", "certs/ok/multi_intermediate/client.crt") as (root_file, interm1_file, interm2_file, client_file):
			# Assert that without any intermediate certificate, building a chain fails
			SubprocessExecutor(self._x509sak + [ "buildchain", "-s", root_file, client_file ], success_return_codes = [ 1 ]).run()

			interm1_crt = X509Certificate.read_pemfile(interm1_file)[0]
			interm2_crt = X509Certificate.read_pemfile(interm2_file)[0]

			# With intermediate 1, it works.
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "-s", root_file, "-s", interm1_file, client_file ]).run().stdout
			certs = X509Certificate.from_pem_data(output)
			self.assertEqual(len(certs), 3)
			self.assertEqual(certs[1], interm1_crt)

			# Similarly, with intermedaite 2, it works.
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "-s", root_file, "-s", interm2_file, client_file ]).run().stdout
			certs = X509Certificate.from_pem_data(output)
			self.assertEqual(len(certs), 3)
			self.assertEqual(certs[1], interm2_crt)

			# But if both are accepted, intemediate 2 wins (it's newer)
			output = SubprocessExecutor(self._x509sak + [ "buildchain", "-s", root_file, "-s", interm1_file, "-s", interm2_file, client_file ]).run().stdout
			certs = X509Certificate.from_pem_data(output)
			self.assertEqual(len(certs), 3)
			self.assertEqual(certs[1], interm2_crt)
