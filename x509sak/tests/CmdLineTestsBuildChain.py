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
import tempfile
from x509sak.WorkDir import WorkDir
from x509sak.tests import BaseTest
from x509sak.SubprocessExecutor import SubprocessExecutor
from x509sak.X509Certificate import X509Certificate

class CmdLineTestsBuildChain(BaseTest):
	def assertOcurrences(self, haystack, needle, expected_count):
		count = haystack.count(needle)
		self.assertEqual(count, expected_count)

	def test_root_only(self):
		output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "x509sak/tests/data/johannes-bauer-root.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output)
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_root_notrust(self):
		output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "--dont-trust-crtfile", "x509sak/tests/data/johannes-bauer-root.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output)
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_interm_root_notrust(self):
		SubprocessExecutor.run(self._x509sak + [ "buildchain", "x509sak/tests/data/johannes-bauer-intermediate.crt" ], discard_stderr = True, success_retcodes = [ 1 ])
		output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "--allow-partial-chain", "x509sak/tests/data/johannes-bauer-intermediate.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output)
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,C=US,O=Let's Encrypt")

		output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", "x509sak/tests/data", "x509sak/tests/data/johannes-bauer-intermediate.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 2)
		crts = X509Certificate.from_pem_data(output.decode("ascii"))
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")
		self.assertEqual(crts[1].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,C=US,O=Let's Encrypt")

	def test_der_input(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			crt = self._load_crt("johannes-bauer-root.crt")
			crt.write_derfile("root.der")
			output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "--inform", "der", "root.der" ])
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
			crts = X509Certificate.from_pem_data(output.decode("ascii"))
			self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_root_only(self):
		output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", "x509sak/tests/data", "--outform", "rootonly", "x509sak/tests/data/johannes-bauer.com.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output.decode("ascii"))
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_intermediate(self):
		output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", "x509sak/tests/data", "--outform", "intermediates", "x509sak/tests/data/johannes-bauer.com.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 1)
		crts = X509Certificate.from_pem_data(output.decode("ascii"))
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,C=US,O=Let's Encrypt")

	def test_all_except_root(self):
		output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", "x509sak/tests/data", "--outform", "all-except-root", "x509sak/tests/data/johannes-bauer.com.crt" ])
		self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 2)
		crts = X509Certificate.from_pem_data(output.decode("ascii"))
		self.assertEqual(crts[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,C=US,O=Let's Encrypt")
		self.assertEqual(crts[1].subject.rfc2253_str, "CN=johannes-bauer.com")

	def test_all_except_root_stdout(self):
		with tempfile.NamedTemporaryFile("w", prefix = "config_", suffix = ".cnf") as out_file:
			output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", "x509sak/tests/data", "--outform", "all-except-root", "--outfile", out_file.name, "x509sak/tests/data/johannes-bauer.com.crt" ])
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 0)
			crts = X509Certificate.read_pemfile(out_file.name)
			self.assertEqual(crts[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,C=US,O=Let's Encrypt")
			self.assertEqual(crts[1].subject.rfc2253_str, "CN=johannes-bauer.com")

	def test_multifile_all_except_root(self):
		search_dir = os.path.realpath("x509sak/tests/data")
		crt_file = os.path.realpath("x509sak/tests/data/johannes-bauer.com.crt")
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", search_dir, "--outform", "multifile", "--outfile", "outcrt%02d.pem", crt_file ])
			self.assertEqual(X509Certificate.read_pemfile("outcrt00.pem")[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")
			self.assertEqual(X509Certificate.read_pemfile("outcrt01.pem")[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,C=US,O=Let's Encrypt")
			self.assertEqual(X509Certificate.read_pemfile("outcrt02.pem")[0].subject.rfc2253_str, "CN=johannes-bauer.com")

			output = SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", search_dir, "--outform", "multifile", "--order-leaf-to-root", "--outfile", "rev_outcrt%02d.pem", crt_file ])
			self.assertEqual(X509Certificate.read_pemfile("rev_outcrt00.pem")[0].subject.rfc2253_str, "CN=johannes-bauer.com")
			self.assertEqual(X509Certificate.read_pemfile("rev_outcrt01.pem")[0].subject.rfc2253_str, "CN=Let's Encrypt Authority X3,C=US,O=Let's Encrypt")
			self.assertEqual(X509Certificate.read_pemfile("rev_outcrt02.pem")[0].subject.rfc2253_str, "CN=DST Root CA X3,O=Digital Signature Trust Co.")

	def test_pkcs12(self):
		search_dir = os.path.realpath("x509sak/tests/data")
		crt_file = os.path.realpath("x509sak/tests/data/johannes-bauer.com.crt")
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", search_dir, "--outform", "pkcs12", "--outfile", "output.p12", crt_file ])
			output = SubprocessExecutor.run([ "openssl", "pkcs12", "-in", "output.p12", "-passin", "pass:" ])
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 3)

	def test_cmd_errors(self):
		SubprocessExecutor.run(self._x509sak + [ "buildchain", "--private-key", "foo.key", "x509sak/tests/data/johannes-bauer-root.crt" ], discard_stderr = True, success_retcodes = [ 1 ])
		SubprocessExecutor.run(self._x509sak + [ "buildchain", "--pkcs12-legacy-crypto", "x509sak/tests/data/johannes-bauer-root.crt" ], discard_stderr = True, success_retcodes = [ 1 ])
		SubprocessExecutor.run(self._x509sak + [ "buildchain", "--pkcs12-no-passphrase", "x509sak/tests/data/johannes-bauer-root.crt" ], discard_stderr = True, success_retcodes = [ 1 ])
		SubprocessExecutor.run(self._x509sak + [ "buildchain", "--pkcs12-passphrase-file", "pass.txt", "x509sak/tests/data/johannes-bauer-root.crt" ], discard_stderr = True, success_retcodes = [ 1 ])
		SubprocessExecutor.run(self._x509sak + [ "buildchain", "--outform", "pkcs12", "--pkcs12-passphrase-file", "pass.txt", "x509sak/tests/data/johannes-bauer-root.crt" ], discard_stderr = True, success_retcodes = [ 1 ])
		SubprocessExecutor.run(self._x509sak + [ "buildchain", "--outform", "pkcs12", "--pkcs12-legacy-crypto", "pass.txt", "x509sak/tests/data/johannes-bauer-root.crt" ], discard_stderr = True, success_retcodes = [ 1 ])

	def test_cmd_no_root_found(self):
		SubprocessExecutor.run(self._x509sak + [ "buildchain", "--allow-partial-chain", "--outform", "rootonly", "x509sak/tests/data/johannes-bauer-intermediate.crt" ], discard_stderr = True, success_retcodes = [ 1 ])

	def test_pkcs12_stdout(self):
		search_dir = os.path.realpath("x509sak/tests/data")
		crt_file = os.path.realpath("x509sak/tests/data/johannes-bauer.com.crt")
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			pkcs12 =  SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", search_dir, "--outform", "pkcs12", crt_file ])
			output = SubprocessExecutor.run([ "openssl", "pkcs12", "-passin", "pass:" ], stdin = pkcs12)
			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 3)

#	def test_pkcs12_passphrase(self):
#		search_dir = os.path.realpath("x509sak/tests/data")
#		crt_file = os.path.realpath("x509sak/tests/data/johannes-bauer.com.crt")
#		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
#			pkcs12 =  SubprocessExecutor.run(self._x509sak + [ "buildchain", "-s", search_dir, "--outform", "pkcs12", "--private-key", search_dir + "/privkey_rsa_768.pem", "--pkcs12-no-passphrase", crt_file ])
#			output = SubprocessExecutor.run([ "openssl", "pkcs12", "-passin", "pass:" ], stdin = pkcs12)
#			self.assertOcurrences(output, b"-----BEGIN CERTIFICATE-----", 3)
