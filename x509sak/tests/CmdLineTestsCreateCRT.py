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
from x509sak.Exceptions import CmdExecutionFailedException

class CmdLineTestsCreateCRT(unittest.TestCase):
	def setUp(self):
		self._x509sak = os.path.realpath("x509sak.py")

	def _gencert(self, certno, options = None):
		if options is None:
			options = [ ]
		SubprocessExecutor.run([ self._x509sak, "createcsr", "-s", "/CN=CHILD%d" % (certno), "-c", "root_ca" ] + options + [ "client%d.key" % (certno), "client%d.crt" % (certno) ])
		(success, output) = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "client%d.crt" % (certno) ], return_stdout = True)
		self.assertIn(b"--BEGIN CERTIFICATE--", output)
		self.assertIn(b"--END CERTIFICATE--", output)
		self.assertTrue((b"Issuer: CN=PARENT" in output) or (b"Issuer: CN = PARENT" in output))
		self.assertTrue((b"Subject: CN=CHILD%d" % (certno) in output) or (b"Subject: CN = CHILD%d" % (certno) in output))
		return output

	def test_create_simple_crt(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run([ self._x509sak, "createca", "-s", "/CN=PARENT", "root_ca" ])
			(success, output) = SubprocessExecutor.run([ "openssl", "x509", "-text", "-in", "root_ca/CA.crt" ], return_stdout = True)
			self.assertIn(b"--BEGIN CERTIFICATE--", output)
			self.assertIn(b"--END CERTIFICATE--", output)
			self.assertTrue((b"Issuer: CN=PARENT" in output) or (b"Issuer: CN = PARENT" in output))
			self.assertTrue((b"Subject: CN=PARENT" in output) or (b"Subject: CN = PARENT" in output))
			self.assertIn(b"id-ecPublicKey", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "root_ca/CA.key" ])

			output = self._gencert(1)
			self.assertIn(b"id-ecPublicKey", output)
			self.assertNotIn(b"X509v3 extensions", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "client1.key" ])

			output = self._gencert(2, [ "-t", "tls-client" ])
			self.assertIn(b"id-ecPublicKey", output)
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:FALSE", output)
			self.assertIn(b"SSL Client", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "client2.key" ])

			output = self._gencert(3, [ "-t", "tls-server", "-g", "rsa:1024" ])
			self.assertIn(b"Public-Key: (1024 bit)", output)
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:FALSE", output)
			self.assertIn(b"SSL Server", output)
			SubprocessExecutor.run([ "openssl", "rsa", "-in", "client3.key" ])

			output = self._gencert(4, [ "-t", "tls-server", "-g", "ecc:secp256r1" ])
			self.assertIn(b"id-ecPublicKey", output)
			self.assertIn(b"prime256v1", output)
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:FALSE", output)
			self.assertIn(b"SSL Server", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "client4.key" ])

			output = self._gencert(5, [ "-t", "tls-server", "-h", "sha1" ])
			self.assertIn(b"ecdsa-with-SHA1", output)
			self.assertIn(b"id-ecPublicKey", output)
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:FALSE", output)
			self.assertIn(b"SSL Server", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "client5.key" ])

			output = self._gencert(6, [ "-t", "tls-server", "-h", "sha512" ])
			self.assertIn(b"ecdsa-with-SHA512", output)
			self.assertIn(b"id-ecPublicKey", output)
			self.assertIn(b"X509v3 extensions", output)
			self.assertIn(b"CA:FALSE", output)
			self.assertIn(b"SSL Server", output)
			SubprocessExecutor.run([ "openssl", "ec", "-in", "client6.key" ])

	def test_duplicate_cn(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run([ self._x509sak, "createca", "-s", "/CN=PARENT", "root_ca" ])
			output = self._gencert(1)

			# Try to reuse same CN for other certificate -- must fail!
			with self.assertRaises(CmdExecutionFailedException):
				SubprocessExecutor.run([ self._x509sak, "createcsr", "-s" "/CN=CHILD1", "-t", "tls-client", "-c", "root_ca", "client2.key", "client2.crt" ])

	def test_create_simple_csr(self):
		with tempfile.TemporaryDirectory() as tempdir, WorkDir(tempdir):
			SubprocessExecutor.run([ self._x509sak, "createcsr", "-s", "/CN=Request1", "request1.key", "request1.csr" ])
			(success, output) = SubprocessExecutor.run([ "openssl", "req", "-text", "-in", "request1.csr" ], return_stdout = True)
			self.assertIn(b"--BEGIN CERTIFICATE REQUEST--", output)
			self.assertIn(b"--END CERTIFICATE REQUEST--", output)
			self.assertTrue((b"Subject: CN=Request1" in output) or (b"Subject: CN = Request1" in output))
			self.assertNotIn(b"Requested Extensions:", output)

			SubprocessExecutor.run([ self._x509sak, "createcsr", "-s", "/CN=Request2", "--san-dns", "foodns", "request2.key", "request2.csr" ])
			(success, output) = SubprocessExecutor.run([ "openssl", "req", "-text", "-in", "request2.csr" ], return_stdout = True)
			self.assertIn(b"--BEGIN CERTIFICATE REQUEST--", output)
			self.assertIn(b"--END CERTIFICATE REQUEST--", output)
			self.assertTrue((b"Subject: CN=Request2" in output) or (b"Subject: CN = Request2" in output))
			self.assertIn(b"Requested Extensions:", output)
			self.assertIn(b"DNS:foodns", output)

			SubprocessExecutor.run([ self._x509sak, "createcsr", "-s", "/CN=Request3", "--san-dns", "foodns", "--san-dns", "bardns", "request3.key", "request3.csr" ])
			(success, output) = SubprocessExecutor.run([ "openssl", "req", "-text", "-in", "request3.csr" ], return_stdout = True)
			self.assertIn(b"--BEGIN CERTIFICATE REQUEST--", output)
			self.assertIn(b"--END CERTIFICATE REQUEST--", output)
			self.assertTrue((b"Subject: CN=Request3" in output) or (b"Subject: CN = Request3" in output))
			self.assertIn(b"Requested Extensions:", output)
			self.assertIn(b"DNS:foodns", output)
			self.assertIn(b"DNS:bardns", output)

			SubprocessExecutor.run([ self._x509sak, "createcsr", "-s", "/CN=Request4", "--san-dns", "foodns", "--san-dns", "bardns", "--san-ip", "111.222.33.44", "request4.key", "request4.csr" ])
			(success, output) = SubprocessExecutor.run([ "openssl", "req", "-text", "-in", "request4.csr" ], return_stdout = True)
			self.assertIn(b"--BEGIN CERTIFICATE REQUEST--", output)
			self.assertIn(b"--END CERTIFICATE REQUEST--", output)
			self.assertTrue((b"Subject: CN=Request4" in output) or (b"Subject: CN = Request4" in output))
			self.assertIn(b"Requested Extensions:", output)
			self.assertIn(b"DNS:foodns", output)
			self.assertIn(b"DNS:bardns", output)
			self.assertIn(b"IP Address:111.222.33.44", output)
