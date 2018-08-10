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
import unittest
import tempfile
from x509sak.WorkDir import WorkDir
from x509sak.SubprocessExecutor import SubprocessExecutor

class CmdLineTestsSignCSR(unittest.TestCase):
	def setUp(self):
		self._x509sak = os.path.realpath("x509sak.py")

	def test_sign_pubkey(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			# Creata a CA
			SubprocessExecutor.run([ self._x509sak, "createca", "myCA" ])

			# Create a default CSR
			SubprocessExecutor.run([ self._x509sak, "createcsr", "client.key", "client.csr" ])

			# Sign the CSR
			SubprocessExecutor.run([ self._x509sak, "signcsr", "myCA", "client.csr", "client.crt" ])

			# Extract public key from private key
			(success, pubkey_in) = SubprocessExecutor.run([ "openssl", "ec", "-pubout", "-in", "client.key" ], return_stdout = True, discard_stderr = True)

			# Extract public key from certificate
			(success, pubkey_out) = SubprocessExecutor.run([ "openssl", "x509", "-noout", "-pubkey", "-in", "client.crt" ], return_stdout = True)

			self.assertEqual(pubkey_in, pubkey_out)

	def test_take_override_subject(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			# Creata a CA
			SubprocessExecutor.run([ self._x509sak, "createca", "myCA" ])

			# Create a CSR with a specific CN/OU
			SubprocessExecutor.run([ self._x509sak, "createcsr", "-s", "/CN=CSR_CN_Subject/OU=CSR_OU_Subject", "client.key", "client.csr" ])

			# Sign the CSR and take original subject
			SubprocessExecutor.run([ self._x509sak, "signcsr", "myCA", "client.csr", "client_original.crt" ])

			# Sign the CSR and override subject
			SubprocessExecutor.run([ self._x509sak, "signcsr", "-s", "/CN=Foobar", "myCA", "client.csr", "client_override.crt" ])

			# Get text representation of CSR and CRT
			(success, csr_text) = SubprocessExecutor.run([ "openssl", "req", "-noout", "-text", "-in", "client.csr" ], return_stdout = True)
			(success, crt_orig_text) = SubprocessExecutor.run([ "openssl", "x509", "-noout", "-text", "-in", "client_original.crt" ], return_stdout = True)
			(success, crt_override_text) = SubprocessExecutor.run([ "openssl", "x509", "-noout", "-text", "-in", "client_override.crt" ], return_stdout = True)

			# The subject is in the CSR and the CRT without any specification,
			# but not in the CRT where it was overriden
			self.assertIn(b"CSR_CN_Subject", csr_text)
			self.assertIn(b"CSR_OU_Subject", csr_text)
			self.assertIn(b"CSR_CN_Subject", crt_orig_text)
			self.assertIn(b"CSR_OU_Subject", crt_orig_text)
			self.assertNotIn(b"CSR_CN_Subject", crt_override_text)
			self.assertNotIn(b"CSR_OU_Subject", crt_override_text)

	def test_san_included(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			# Creata a CA
			SubprocessExecutor.run([ self._x509sak, "createca", "myCA" ])

			# Create a CSR
			SubprocessExecutor.run([ self._x509sak, "createcsr", "client.key", "client.csr" ])

			# Sign the CSR with a SAN
			SubprocessExecutor.run([ self._x509sak, "signcsr", "--san-dns", "foobar.com", "--san-dns", "barfoo.com", "--san-ip", "11.22.33.44", "myCA", "client.csr", "client.crt" ])

			# Check that SAN ended up in the CRT
			(success, crt_text) = SubprocessExecutor.run([ "openssl", "x509", "-noout", "-text", "-in", "client.crt" ], return_stdout = True)
			self.assertIn(b"X509v3 extensions", crt_text)
			self.assertIn(b"foobar.com", crt_text)
			self.assertIn(b"barfoo.com", crt_text)

	def test_override_extensions(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			# Creata a CA
			SubprocessExecutor.run([ self._x509sak, "createca", "myCA" ])

			# Create a CSR and pack it full of extensions
			SubprocessExecutor.run([ self._x509sak, "createcsr", "-t", "tls-client", "--san-dns", "fooname.com", "--san-ip", "11.22.33.44", "client.key", "client.csr" ])

			# Sign the CSR but don't put any extensions in the CRT
			SubprocessExecutor.run([ self._x509sak, "signcsr", "myCA", "client.csr", "client_none.crt" ])

			# Sign the CSR a second time and override extensions
			SubprocessExecutor.run([ self._x509sak, "signcsr", "-s", "/CN=Server", "-t", "tls-server", "myCA", "client.csr", "client_server.crt" ])

			# Sign the CSR a third time and override extensions and add a SAN
			SubprocessExecutor.run([ self._x509sak, "signcsr", "-s", "/CN=Server with SAN DNS", "-t", "tls-server", "--san-dns", "newdns.com", "myCA", "client.csr", "client_server_dns.crt" ])

			# Get text representation of CSR and CRT
			(success, csr_text) = SubprocessExecutor.run([ "openssl", "req", "-noout", "-text", "-in", "client.csr" ], return_stdout = True)
			(success, crt_none_text) = SubprocessExecutor.run([ "openssl", "x509", "-noout", "-text", "-in", "client_none.crt" ], return_stdout = True)
			(success, crt_server_text) = SubprocessExecutor.run([ "openssl", "x509", "-noout", "-text", "-in", "client_server.crt" ], return_stdout = True)
			(success, crt_server_dns_text) = SubprocessExecutor.run([ "openssl", "x509", "-noout", "-text", "-in", "client_server_dns.crt" ], return_stdout = True)

			# CSR contains a bunch of extensions
			self.assertIn(b"Requested Extensions", csr_text)
			self.assertIn(b"fooname.com", csr_text)
			self.assertIn(b"11.22.33.44", csr_text)
			self.assertIn(b"Netscape Cert Type", csr_text)
			self.assertIn(b"Basic Constraints", csr_text)
			self.assertIn(b"SSL Client", csr_text)

			# But the CRT does not contain any
			self.assertNotIn(b"X509v3 extensions", crt_none_text)
			self.assertNotIn(b"fooname.com", crt_none_text)
			self.assertNotIn(b"11.22.33.44", crt_none_text)
			self.assertNotIn(b"Netscape Cert Type", crt_none_text)
			self.assertNotIn(b"Basic Constraints", crt_none_text)

			# The cert with template contains some, though.
			self.assertIn(b"X509v3 extensions", crt_server_text)
			self.assertNotIn(b"fooname.com", crt_server_text)
			self.assertNotIn(b"11.22.33.44", crt_server_text)
			self.assertIn(b"Netscape Cert Type", crt_server_text)
			self.assertIn(b"Basic Constraints", crt_server_text)
			self.assertIn(b"SSL Server", crt_server_text)

			# And one more, the last one also contains the specified SAN
			self.assertIn(b"X509v3 extensions", crt_server_dns_text)
			self.assertNotIn(b"fooname.com", crt_server_dns_text)
			self.assertNotIn(b"11.22.33.44", crt_server_dns_text)
			self.assertIn(b"Netscape Cert Type", crt_server_dns_text)
			self.assertIn(b"Basic Constraints", crt_server_dns_text)
			self.assertIn(b"SSL Server", crt_server_dns_text)
			self.assertIn(b"newdns.com", crt_server_dns_text)
