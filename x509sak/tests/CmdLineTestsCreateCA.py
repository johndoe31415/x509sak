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
from x509sak.WorkDir import WorkDir
from x509sak.SubprocessExecutor import SubprocessExecutor

class CmdLineTestsCreateCA(BaseTest):
	def test_create_simple_ca(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run(self._x509sak + [ "createca", "root_ca" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "root_ca/CA.crt" ])
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertIn(b"id-ecPublicKey", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "root_ca/CA.key" ])

	def test_create_simple_ca_2(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run(self._x509sak + [ "createca", "-g", "ecc:secp256r1", "-s", "/CN=YepThatsTheCN", "-h", "sha512", "root_ca" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "root_ca/CA.crt" ])
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertIn(b"id-ecPublicKey", output)
			self.assertIn(b"ecdsa-with-SHA512", output)
			self.assertIn(b"prime256v1", output)
			self.assertTrue((b"CN=YepThatsTheCN" in output) or (b"CN = YepThatsTheCN" in output))
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:TRUE", output)
			self.assertIn(b"X509v3 Subject Key Identifier", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "root_ca/CA.key" ])

	def test_create_simple_ca_3(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run(self._x509sak + [ "createca", "-g", "rsa:1024", "-s", "/CN=YepThats!TheCN", "-h", "sha1", "root_ca" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "root_ca/CA.crt" ])
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertIn(b"rsaEncryption", output)
			self.assertIn(b"sha1WithRSAEncryption", output)
			self.assertTrue(b"Public-Key: (1024 bit)" in output)
			self.assertTrue((b"CN=YepThats!TheCN" in output) or (b"CN = YepThats!TheCN" in output))
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:TRUE", output)
			self.assertIn(b"X509v3 Subject Key Identifier", output)
			SubprocessExecutor.run([ "openssl", "rsa", "-in", "root_ca/CA.key" ])

	def test_create_nested_ca(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run(self._x509sak + [ "createca", "this/is/a/root_ca" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "this/is/a/root_ca/CA.crt" ])
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertIn(b"id-ecPublicKey", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "this/is/a/root_ca/CA.key" ])

	def test_create_intermediate_ca(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run(self._x509sak + [ "createca", "-s", "/CN=PARENT", "root_ca" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "root_ca/CA.crt" ])
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertTrue((b"Issuer: CN=PARENT" in output) or (b"Issuer: CN = PARENT" in output))
			self.assertTrue((b"Subject: CN=PARENT" in output) or (b"Subject: CN = PARENT" in output))
			self.assertIn(b"id-ecPublicKey", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "root_ca/CA.key" ])

			SubprocessExecutor.run(self._x509sak + [ "createca", "-p", "root_ca", "-s", "/CN=INTERMEDIATE", "intermediate_ca" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "intermediate_ca/CA.crt" ])
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertTrue((b"Issuer: CN=PARENT" in output) or (b"Issuer: CN = PARENT" in output))
			self.assertTrue((b"Subject: CN=INTERMEDIATE" in output) or (b"Subject: CN = INTERMEDIATE" in output))
			self.assertIn(b"id-ecPublicKey", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "intermediate_ca/CA.key" ])

	def test_subject_info(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run(self._x509sak + [ "createca", "-s", "/CN=Elem00/OU=Elem01/C=DE/SN=Elem02/GN=Elem03/emailAddress=Elem04/title=Elem05/L=Elem06/stateOrProvinceName=Elem07/pseudonym=Elem08", "root_ca" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-subject", "-noout", "-in", "root_ca/CA.crt" ])
			self.assertIn(b"DE", output)
			for eid in range(9):
				element = ("Elem%02d" % (eid)).encode("ascii")
				self.assertIn(element, output)

	def test_x509_extension(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run(self._x509sak + [ "createca", "--extension", "nameConstraints=critical,permitted;DNS:foo.bar.com", "root_ca" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-text", "-noout", "-in", "root_ca/CA.crt" ])
			self.assertIn(b"DNS:foo.bar.com", output)
			self.assertNotIn(b"pathlen", output)

			SubprocessExecutor.run(self._x509sak + [ "createca", "--extension", "nameConstraints=critical,permitted;DNS:foo.bar.com", "--extension", "basicConstraints=critical,CA:TRUE,pathlen:123", "root_ca2" ])
			output = SubprocessExecutor.run([ "openssl", "x509", "-text", "-noout", "-in", "root_ca2/CA.crt" ])
			self.assertIn(b"DNS:foo.bar.com", output)
			self.assertIn(b"pathlen:123", output)
