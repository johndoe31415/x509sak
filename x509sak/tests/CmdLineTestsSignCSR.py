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
			# Create a default CSR
			SubprocessExecutor.run([ self._x509sak, "createcsr", "request1.key", "request1.csr" ])

			# Creata a CA
			SubprocessExecutor.run([ self._x509sak, "createca", "myCA" ])

			# Sign the CSR
			SubprocessExecutor.run([ self._x509sak, "signcsr", "myCA", "request1.csr", "request1.crt" ])

			# Extract public key from private key
			(success, pubkey_in) = SubprocessExecutor.run([ "openssl", "ec", "-pubout", "-in", "request1.key" ], return_stdout = True, discard_stderr = True)

			# Extract public key from certificate
			(success, pubkey_out) = SubprocessExecutor.run([ "openssl", "x509", "-noout", "-pubkey", "-in", "request1.crt" ], return_stdout = True)

			self.assertEqual(pubkey_in, pubkey_out)
