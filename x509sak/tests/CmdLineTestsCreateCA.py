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
import pkgutil
import tempfile
from x509sak.WorkDir import WorkDir
from x509sak.SubprocessExecutor import SubprocessExecutor

class CmdLineTestsCreateCA(unittest.TestCase):
	@staticmethod
	def _load_crt(crtname):
		x509_text = pkgutil.get_data("x509sak.tests.data", crtname).decode("ascii")
		cert = X509Certificate.from_pem_data(x509_text)[0]
		return cert

	def setUp(self):
		self._x509sak = os.path.realpath("x509sak.py")

	def assertOcurrences(self, haystack, needle, expected_count):
		count = haystack.count(needle)
		self.assertEqual(count, expected_count)

	def test_create_simple_ca(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run([ self._x509sak, "createca", "root_ca" ])
			(success, output) = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "root_ca/CA.crt" ], return_stdout = True)
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertIn(b"id-ecPublicKey", output)

	def test_create_simple_ca_2(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run([ self._x509sak, "createca", "-g", "ecc:secp256r1", "-s", "/CN=YepThatsTheCN", "-h", "sha512", "root_ca" ])
			(success, output) = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "root_ca/CA.crt" ], return_stdout = True)
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertIn(b"id-ecPublicKey", output)
			self.assertIn(b"ecdsa-with-SHA512", output)
			self.assertIn(b"prime256v1", output)
			self.assertTrue((b"CN=YepThatsTheCN" in output) or (b"CN = YepThatsTheCN" in output))
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:TRUE", output)
			self.assertIn(b"X509v3 Subject Key Identifier", output)

	def test_create_simple_ca_3(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run([ self._x509sak, "createca", "-g", "rsa:1024", "-s", "/CN=YepThats!TheCN", "-h", "sha1", "root_ca" ])
			(success, output) = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "root_ca/CA.crt" ], return_stdout = True)
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertIn(b"rsaEncryption", output)
			self.assertIn(b"sha1WithRSAEncryption", output)
			self.assertIn(b"RSA Public-Key: (1024 bit)", output)
			self.assertTrue((b"CN=YepThats!TheCN" in output) or (b"CN = YepThats!TheCN" in output))
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:TRUE", output)
			self.assertIn(b"X509v3 Subject Key Identifier", output)
