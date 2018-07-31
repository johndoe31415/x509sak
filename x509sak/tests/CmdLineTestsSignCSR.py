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

			# Sign the CSR and take all original subject data
			SubprocessExecutor.run([ self._x509sak, "signcsr", "myCA", "client.csr", "client_original.crt" ])

			# Sign the CSR and override all subject parameters
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
